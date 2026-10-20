use axum::{
    extract::{
        ws::Message, ConnectInfo, DefaultBodyLimit, MatchedPath, Path, Query, Request, State,
        WebSocketUpgrade,
    },
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use miliastra_core::{control::*, coordination, decisions::ProjectState, hash, Invitation};
use serde::Deserialize;
use sqlx::{PgPool, Row};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::broadcast;
#[derive(Clone)]
struct App {
    pool: PgPool,
    events: Arc<broadcast::Sender<(String, serde_json::Value)>>,
    endpoint: String,
    limits: Arc<Limiter>,
    shutdown: tokio::sync::watch::Receiver<bool>,
    /// When each member last asked for each slice, to limit repeat requests.
    finish_requests: Arc<Mutex<HashMap<(String, String, String), Instant>>>,
    presence: Arc<miliastra_core::presence_board::PresenceBoard>,
}
const FINISH_REQUEST_INTERVAL: Duration = Duration::from_secs(60);
/// Per-IP limits for requests without sign-in (create, join, invitation lookup).
struct Limiter {
    trust_forwarded: bool,
    /// Test runs only (DISABLE_RATE_LIMITS=1): many projects and joins from one address.
    disabled: bool,
    windows: Mutex<HashMap<(&'static str, IpAddr), (Instant, u32)>>,
}
const LIMIT_WINDOW: Duration = Duration::from_secs(600);
impl Limiter {
    fn client(&self, headers: &HeaderMap, peer: SocketAddr) -> IpAddr {
        // Only trust X-Forwarded-For when the proxy is the only way in.
        self.trust_forwarded
            .then(|| {
                headers
                    .get("x-forwarded-for")?
                    .to_str()
                    .ok()?
                    .split(',')
                    .next()?
                    .trim()
                    .parse()
                    .ok()
            })
            .flatten()
            .unwrap_or(peer.ip())
    }
    fn check(&self, route: &'static str, ip: IpAddr, max: u32) -> Result<()> {
        if self.disabled {
            return Ok(());
        }
        let now = Instant::now();
        let mut windows = self.windows.lock().unwrap();
        if windows.len() > 10_000 {
            windows.retain(|_, (start, _)| now.duration_since(*start) < LIMIT_WINDOW);
        }
        let (start, count) = windows.entry((route, ip)).or_insert((now, 0));
        if now.duration_since(*start) >= LIMIT_WINDOW {
            *start = now;
            *count = 0;
        }
        *count += 1;
        if *count > max {
            return Err(Error(anyhow::Error::new(Throttled)));
        }
        Ok(())
    }
}
#[derive(Debug)]
struct Throttled;
impl std::fmt::Display for Throttled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Too many requests. Wait a few minutes, then try again.")
    }
}
impl std::error::Error for Throttled {}
struct Error(anyhow::Error);
impl<E: Into<anyhow::Error>> From<E> for Error {
    fn from(e: E) -> Self {
        Self(e.into())
    }
}
impl IntoResponse for Error {
    fn into_response(self) -> Response {
        if let Some(error) = self
            .0
            .downcast_ref::<miliastra_core::errors::ServiceError>()
        {
            let status =
                StatusCode::from_u16(error.code.http_status()).expect("valid error status");
            return (status, Json(error)).into_response();
        }

        let (code, s) = if self.0.downcast_ref::<Throttled>().is_some() {
            (StatusCode::TOO_MANY_REQUESTS, self.0.to_string())
        } else if let Some(e) = self.0.downcast_ref::<sqlx::Error>() {
            if matches!(e, sqlx::Error::RowNotFound) {
                (StatusCode::NOT_FOUND, "Project not found".into())
            } else {
                tracing::error!("database request failed");
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "The collaboration service is temporarily unavailable".into(),
                )
            }
        } else if self.0.downcast_ref::<serde_json::Error>().is_some() {
            tracing::error!("stored project state is unreadable");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "The collaboration service could not read this project".into(),
            )
        } else if self.0.downcast_ref::<uuid::Error>().is_some() {
            (StatusCode::BAD_REQUEST, "Invalid identifier".into())
        } else {
            (StatusCode::CONFLICT, self.0.to_string())
        };
        let kind = match code.as_u16() {
            400 => miliastra_core::errors::ErrorCode::Validation,
            404 => miliastra_core::errors::ErrorCode::NotFound,
            429 => miliastra_core::errors::ErrorCode::RateLimited,
            500 => miliastra_core::errors::ErrorCode::Internal,
            503 => miliastra_core::errors::ErrorCode::Unavailable,
            _ => miliastra_core::errors::ErrorCode::Conflict,
        };
        (
            code,
            Json(miliastra_core::errors::ServiceError::new(kind, s)),
        )
            .into_response()
    }
}
type Result<T> = std::result::Result<T, Error>;
fn now() -> i64 {
    chrono::Utc::now().timestamp()
}
fn token(h: &HeaderMap) -> Result<&str> {
    h.get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| {
            miliastra_core::errors::ServiceError::new(
                miliastra_core::errors::ErrorCode::Unauthorized,
                "Sign in again to continue",
            )
            .into()
        })
}
async fn load<'a>(
    app: &'a App,
    id: &str,
) -> Result<(sqlx::Transaction<'a, sqlx::Postgres>, ProjectState)> {
    let mut tx = app.pool.begin().await?;
    let row = sqlx::query("SELECT state FROM projects WHERE id=$1 FOR UPDATE")
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;
    let p = serde_json::from_value(row.get("state"))?;
    Ok((tx, p))
}
/// Reads skip the row lock so they don't wait behind renewals and publications.
async fn load_read(app: &App, id: &str) -> Result<ProjectState> {
    let row = sqlx::query("SELECT state FROM projects WHERE id=$1")
        .bind(id)
        .fetch_one(&app.pool)
        .await?;
    Ok(serde_json::from_value(row.get("state"))?)
}
async fn save(tx: &mut sqlx::Transaction<'_, sqlx::Postgres>, p: &ProjectState) -> Result<()> {
    sqlx::query("UPDATE projects SET state=$2 WHERE id=$1")
        .bind(&p.id)
        .bind(serde_json::to_value({
            let mut compact = p.clone();
            compact.history.clear();
            compact
        })?)
        .execute(&mut **tx)
        .await?;
    Ok(())
}
fn emit(app: &App, id: &str, kind: &str) {
    let _ = app
        .events
        .send((id.into(), serde_json::json!({"kind":kind})));
}
async fn store_update(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    id: &str,
    u: &Update,
) -> Result<()> {
    sqlx::query("INSERT INTO updates(project,sequence,id,author_id,at,document) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(project,id) DO NOTHING")
        .bind(id).bind(u.sequence as i64).bind(&u.id).bind(&u.author_id).bind(u.at)
        .bind(serde_json::to_value(u)?).execute(&mut **tx).await?;
    Ok(())
}
async fn create(
    State(app): State<App>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<CreateProject>,
) -> Result<Json<Joined>> {
    app.limits
        .check("create", app.limits.client(&headers, peer), 10)?;
    let (p, joined) = ProjectState::create(req, now(), app.endpoint.clone())?;
    let id = p.id.clone();
    let mut tx = app.pool.begin().await?;
    sqlx::query("INSERT INTO projects(id,state) VALUES($1,$2)")
        .bind(&id)
        .bind(serde_json::to_value({
            let mut compact = p.clone();
            compact.history.clear();
            compact
        })?)
        .execute(&mut *tx)
        .await?;
    for u in &p.history {
        store_update(&mut tx, &id, u).await?;
    }
    tx.commit().await?;
    Ok(Json(joined))
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Join {
    invite: String,
    profile_hash: String,
    member_id: String,
}
async fn join(
    State(app): State<App>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<Join>,
) -> Result<Json<Joined>> {
    app.limits
        .check("join", app.limits.client(&headers, peer), 30)?;
    let (mut tx, mut p) = load(&app, &id).await?;
    if !p
        .invites
        .get(&hash(req.invite.as_bytes()))
        .is_some_and(|t| *t > now())
    {
        return Err(
            anyhow::anyhow!("Invitation expired; ask the owner for a new invitation").into(),
        );
    }
    uuid::Uuid::parse_str(&req.member_id)?;
    miliastra_core::control::fingerprint(&req.profile_hash)?;
    if p.members.contains_key(&req.member_id) {
        return Err(anyhow::anyhow!("Creator identity already joined").into());
    }
    let member = req.member_id;
    let secret = format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    );
    p.members.insert(
        member.clone(),
        Member {
            id: member.clone(),
            profile_hash: req.profile_hash,
            owner: false,
            joined: now(),
        },
    );
    p.tokens.insert(hash(secret.as_bytes()), member.clone());
    save(&mut tx, &p).await?;
    tx.commit().await?;
    emit(&app, &id, "members");
    Ok(Json(Joined {
        project: p.view(now()),
        member,
        token: secret,
        invitation: None,
    }))
}
async fn view(
    State(app): State<App>,
    Path(id): Path<String>,
    h: HeaderMap,
) -> Result<Json<ProjectView>> {
    let p = load_read(&app, &id).await?;
    p.authenticate(token(&h)?)?;
    let mut view = p.view(now());
    view.presence = app.presence.list(&id);
    Ok(Json(view))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Lock {
    section: String,
    #[serde(default)]
    fence: u64,
    #[serde(default)]
    takeover: bool,
}
async fn acquire(
    State(app): State<App>,
    Path(id): Path<String>,
    h: HeaderMap,
    Json(req): Json<Lock>,
) -> Result<Json<Lease>> {
    let (mut tx, mut p) = load(&app, &id).await?;
    let member = p.authenticate(token(&h)?)?;
    let previous = p.other_holder(&member, &req.section, now());
    let l = p.acquire(&member, &req.section, now(), req.takeover)?;
    save(&mut tx, &p).await?;
    tx.commit().await?;
    emit(&app, &id, "locks");
    if let Some(previous) = previous {
        // The name is still encrypted; we only pass it on.
        let _ = app.events.send((
            id,
            serde_json::json!({"kind":"takeover","section":req.section,"to":previous.member,"from":l.member}),
        ));
    }
    Ok(Json(l))
}
async fn renew(
    State(app): State<App>,
    Path(id): Path<String>,
    h: HeaderMap,
    Json(req): Json<Lock>,
) -> Result<Json<Lease>> {
    let (mut tx, mut p) = load(&app, &id).await?;
    let member = p.authenticate(token(&h)?)?;
    let l = p.renew(&member, &req.section, req.fence, now())?;
    save(&mut tx, &p).await?;
    tx.commit().await?;
    Ok(Json(l))
}
async fn release(
    State(app): State<App>,
    Path(id): Path<String>,
    h: HeaderMap,
    Json(req): Json<Lock>,
) -> Result<Json<serde_json::Value>> {
    let (mut tx, mut p) = load(&app, &id).await?;
    let member = p.authenticate(token(&h)?)?;
    p.release(&member, &req.section, req.fence)?;
    save(&mut tx, &p).await?;
    tx.commit().await?;
    emit(&app, &id, "locks");
    Ok(Json(serde_json::json!({"ok":true})))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FinishRequest {
    section: String,
}
/// Asks whoever holds a slice to share it. Sent as a live event only.
async fn request_finish(
    State(app): State<App>,
    Path(id): Path<String>,
    h: HeaderMap,
    Json(req): Json<FinishRequest>,
) -> Result<Json<serde_json::Value>> {
    let p = load_read(&app, &id).await?;
    let member = p.authenticate(token(&h)?)?;
    let (lease, from) = p.finish_request(&member, &req.section, now())?;
    {
        let mut recent = app.finish_requests.lock().unwrap();
        let key = (id.clone(), req.section.clone(), member.clone());
        if recent
            .get(&key)
            .is_some_and(|at| at.elapsed() < FINISH_REQUEST_INTERVAL)
        {
            return Err(anyhow::anyhow!("You already asked recently; give them a moment").into());
        }
        if recent.len() > 10_000 {
            recent.retain(|_, at| at.elapsed() < FINISH_REQUEST_INTERVAL);
        }
        recent.insert(key, Instant::now());
    }
    let _ = app.events.send((
        id,
        serde_json::json!({"kind":"finish-request","section":req.section,"to":lease.member,"from":from}),
    ));
    Ok(Json(serde_json::json!({"ok":true,"holder":lease.member})))
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AccessRequestBody {
    invite: String,
    id: String,
    sealed: miliastra_core::coordination::SealedAccess,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AccessStatusBody {
    invite: String,
    id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AccessResultBody {
    id: String,
    result: String,
}
/// A joiner (with a valid invitation) asks the owner's app to share the team folder.
async fn request_access(
    State(app): State<App>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<AccessRequestBody>,
) -> Result<Json<serde_json::Value>> {
    app.limits
        .check("access", app.limits.client(&headers, peer), 30)?;
    let (mut tx, mut p) = load(&app, &id).await?;
    let request = p.request_access(&req.invite, &req.id, req.sealed, now())?;
    save(&mut tx, &p).await?;
    tx.commit().await?;
    emit(&app, &id, "access-request");
    Ok(Json(serde_json::json!({ "id": request })))
}
async fn access_status(
    State(app): State<App>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<AccessStatusBody>,
) -> Result<Json<serde_json::Value>> {
    app.limits
        .check("access-status", app.limits.client(&headers, peer), 600)?;
    let p = load_read(&app, &id).await?;
    let (status, message) = p.access_status(&req.invite, &req.id, now())?;
    // Tells a waiting joiner whether the owner's app is online to share the folder.
    let owner_online = p
        .owner_id()
        .is_some_and(|o| app.presence.is_connected(&id, o));
    Ok(Json(
        serde_json::json!({ "status": status, "message": message, "ownerOnline": owner_online }),
    ))
}
async fn pending_access(
    State(app): State<App>,
    Path(id): Path<String>,
    h: HeaderMap,
) -> Result<Json<Vec<coordination::AccessRequest>>> {
    let p = load_read(&app, &id).await?;
    let member = p.authenticate(token(&h)?)?;
    Ok(Json(p.pending_access(&member, now())?))
}
async fn record_access(
    State(app): State<App>,
    Path(id): Path<String>,
    h: HeaderMap,
    Json(req): Json<AccessResultBody>,
) -> Result<Json<serde_json::Value>> {
    let (mut tx, mut p) = load(&app, &id).await?;
    let member = p.authenticate(token(&h)?)?;
    p.record_access(&member, &req.id, &req.result)?;
    save(&mut tx, &p).await?;
    tx.commit().await?;
    emit(&app, &id, "access-result");
    Ok(Json(serde_json::json!({ "ok": true })))
}
async fn publish_names(
    State(app): State<App>,
    Path(id): Path<String>,
    h: HeaderMap,
    Json(req): Json<PublishNames>,
) -> Result<Json<Update>> {
    let (mut tx, mut p) = load(&app, &id).await?;
    let member = p.authenticate(token(&h)?)?;
    if let Some(row) = sqlx::query("SELECT document FROM updates WHERE project=$1 AND id=$2")
        .bind(&id)
        .bind(&req.id)
        .fetch_optional(&mut *tx)
        .await?
    {
        p.history.push(serde_json::from_value(row.get("document"))?);
    }
    let u = p.publish_names(&member, req, now())?;
    save(&mut tx, &p).await?;
    store_update(&mut tx, &id, &u).await?;
    tx.commit().await?;
    emit(&app, &id, "published");
    Ok(Json(u))
}
async fn publish(
    State(app): State<App>,
    Path(id): Path<String>,
    h: HeaderMap,
    Json(req): Json<PublishRequest>,
) -> Result<Json<Update>> {
    let (mut tx, mut p) = load(&app, &id).await?;
    let member = p.authenticate(token(&h)?)?;
    for update_id in std::iter::once(Some(req.id.clone()))
        .chain(std::iter::once(req.restores.clone()))
        .flatten()
    {
        if let Some(row) = sqlx::query("SELECT document FROM updates WHERE project=$1 AND id=$2")
            .bind(&id)
            .bind(update_id)
            .fetch_optional(&mut *tx)
            .await?
        {
            p.history.push(serde_json::from_value(row.get("document"))?);
        }
    }
    let revisions: Vec<String> = req.revisions.iter().map(|r| r.revision.clone()).collect();
    let reused:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM updates, jsonb_array_elements(document->'revisions') AS revision WHERE project=$1 AND revision->>'revision'=ANY($2) AND id<>$3)")
        .bind(&id).bind(&revisions).bind(&req.id).fetch_one(&mut *tx).await?;
    if reused {
        return Err(anyhow::anyhow!("Revision ID already used").into());
    }
    let u = p.publish(&member, req, now())?;
    save(&mut tx, &p).await?;
    store_update(&mut tx, &id, &u).await?;
    tx.commit().await?;
    emit(&app, &id, "published");
    Ok(Json(u))
}
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct Filter {
    before: Option<u64>,
}
async fn history(
    State(app): State<App>,
    Path(id): Path<String>,
    Query(q): Query<Filter>,
    h: HeaderMap,
) -> Result<Json<HistoryPage>> {
    let p = load_read(&app, &id).await?;
    p.authenticate(token(&h)?)?;
    let rows=sqlx::query("SELECT sequence,document FROM updates WHERE project=$1 AND ($2::bigint IS NULL OR sequence<$2) ORDER BY sequence DESC LIMIT 51")
        .bind(&id).bind(q.before.map(|v|v as i64)).fetch_all(&app.pool).await?;
    let more = rows.len() > 50;
    let entries: Vec<Update> = rows
        .iter()
        .take(50)
        .map(|r| serde_json::from_value(r.get("document")))
        .collect::<std::result::Result<_, _>>()?;
    let next = if more {
        entries.last().map(|u| u.sequence)
    } else {
        None
    };
    Ok(Json(HistoryPage { entries, next }))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bootstrap {
    bootstrap: String,
}
async fn invitation(
    State(app): State<App>,
    Path(id): Path<String>,
    h: HeaderMap,
    Json(locator): Json<Bootstrap>,
) -> Result<Json<Invitation>> {
    let (mut tx, mut p) = load(&app, &id).await?;
    let member = p.authenticate(token(&h)?)?;
    let code = p.create_invite(&member, now(), locator.bootstrap)?;
    save(&mut tx, &p).await?;
    tx.commit().await?;
    emit(&app, &id, "members");
    Ok(Json(Invitation {
        version: 1,
        endpoint: app.endpoint,
        project: id,
        invite: code,
    }))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MemberBody {
    member: String,
}
async fn remove_member(
    State(app): State<App>,
    Path(id): Path<String>,
    h: HeaderMap,
    Json(req): Json<MemberBody>,
) -> Result<Json<serde_json::Value>> {
    let (mut tx, mut p) = load(&app, &id).await?;
    let member = p.authenticate(token(&h)?)?;
    p.remove_member(&member, &req.member)?;
    save(&mut tx, &p).await?;
    tx.commit().await?;
    // The removed member's connection gets this event, then closes.
    let _ = app.events.send((
        id.clone(),
        serde_json::json!({"kind":"removed","member":req.member}),
    ));
    emit(&app, &id, "members");
    Ok(Json(serde_json::json!({"ok":true})))
}
async fn transfer_ownership(
    State(app): State<App>,
    Path(id): Path<String>,
    h: HeaderMap,
    Json(req): Json<MemberBody>,
) -> Result<Json<serde_json::Value>> {
    let (mut tx, mut p) = load(&app, &id).await?;
    let member = p.authenticate(token(&h)?)?;
    p.transfer_ownership(&member, &req.member)?;
    save(&mut tx, &p).await?;
    tx.commit().await?;
    emit(&app, &id, "members");
    Ok(Json(serde_json::json!({"ok":true})))
}
async fn events(
    State(app): State<App>,
    Path(id): Path<String>,
    h: HeaderMap,
    ws: WebSocketUpgrade,
) -> Result<Response> {
    let p = load_read(&app, &id).await?;
    let member = p.authenticate(token(&h)?)?;
    let mut rx = app.events.subscribe();
    let mut shutdown = app.shutdown.clone();
    Ok(ws.on_upgrade(move |mut socket| async move {
        // An open connection is what "online" means. The status it sends is encrypted.
        app.presence.connect(&id, &member);
        emit(&app, &id, "presence");
        loop {
            tokio::select! {
                event = rx.recv() => match event {
                    Ok((project, v)) if project == id => {
                        if socket.send(Message::Text(v.to_string().into())).await.is_err() {
                            break;
                        }
                        if v["kind"] == "removed" && v["member"] == member.as_str() {
                            let _ = socket.send(Message::Close(None)).await;
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        let _ = socket
                            .send(Message::Text("{\"kind\":\"reconcile\"}".into()))
                            .await;
                    }
                    Err(_) => break,
                    _ => {}
                },
                incoming = socket.recv() => match incoming {
                    Some(Ok(Message::Ping(v))) => {
                        let _ = socket.send(Message::Pong(v)).await;
                    }
                    Some(Ok(Message::Text(text))) => {
                        let status = serde_json::from_str::<serde_json::Value>(&text)
                            .ok()
                            .filter(|v| v["kind"] == "status")
                            .and_then(|v| v["status"].as_str().map(str::to_owned));
                        if let Some(status) = status {
                            if app.presence.set_status(&id, &member, &status).is_ok() {
                                emit(&app, &id, "presence");
                            }
                        }
                    }
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                    _ => {}
                },
                // Close live connections on shutdown; clients reconnect and resync.
                _ = shutdown.changed() => {
                    let _ = socket.send(Message::Close(None)).await;
                    break;
                }
            }
        }
        app.presence.disconnect(&id, &member);
        emit(&app, &id, "presence");
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolveInvitation {
    project: String,
    invite: String,
}
async fn resolve_invitation(
    State(app): State<App>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<ResolveInvitation>,
) -> Result<Json<serde_json::Value>> {
    app.limits
        .check("resolve", app.limits.client(&headers, peer), 60)?;
    uuid::Uuid::parse_str(&req.project)?;
    uuid::Uuid::parse_str(&req.invite)?;
    let p = load_read(&app, &req.project).await?;
    if !p
        .invites
        .get(&hash(req.invite.as_bytes()))
        .is_some_and(|expires| *expires > now())
    {
        return Err(anyhow::anyhow!("This invitation is invalid or expired").into());
    }
    Ok(Json(
        serde_json::json!({"version":1,"endpoint":app.endpoint,"project":req.project,"invite":req.invite,"bootstrap":p.invite_bootstraps.get(&hash(req.invite.as_bytes())),"owner":p.owner_for_invitation()}),
    ))
}
async fn log_requests(request: Request, next: Next) -> Response {
    let method = request.method().clone();
    // Log the route template only: no raw paths, queries, headers, IPs or bodies.
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map(|p| p.as_str().to_owned())
        .unwrap_or_else(|| "unmatched".into());
    let started = Instant::now();
    let response = next.run(request).await;
    tracing::info!(
        %method,
        %route,
        status = response.status().as_u16(),
        elapsed_ms = started.elapsed().as_millis() as u64,
        "request"
    );
    response
}
async fn cleanup(app: &App) -> anyhow::Result<()> {
    app.limits
        .windows
        .lock()
        .unwrap()
        .retain(|_, (at, _)| at.elapsed() < LIMIT_WINDOW);
    app.finish_requests
        .lock()
        .unwrap()
        .retain(|_, at| at.elapsed() < FINISH_REQUEST_INTERVAL);
    let mut after = String::new();
    loop {
        let ids: Vec<String> =
            sqlx::query_scalar("SELECT id FROM projects WHERE id > $1 ORDER BY id LIMIT 100")
                .bind(&after)
                .fetch_all(&app.pool)
                .await?;
        if ids.is_empty() {
            break;
        }
        for id in &ids {
            let mut tx = app.pool.begin().await?;
            let row = sqlx::query("SELECT state FROM projects WHERE id=$1 FOR UPDATE SKIP LOCKED")
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?;
            if let Some(row) = row {
                let mut project: ProjectState = serde_json::from_value(row.get("state"))?;
                if project.cleanup(now()) {
                    save(&mut tx, &project).await.map_err(|e| e.0)?;
                    tx.commit().await?;
                    emit(app, id, "changed");
                }
            }
        }
        after = ids.last().unwrap().clone();
    }
    Ok(())
}
async fn maintenance(app: App) {
    let mut shutdown = app.shutdown.clone();
    let mut ticks = tokio::time::interval(Duration::from_secs(60));
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            _ = ticks.tick() => {
                if cleanup(&app).await.is_err() { tracing::error!("temporary metadata cleanup failed"); }
            }
        }
    }
}
async fn invitation_page() -> Response {
    use axum::{http::header, response::Html};
    ([(header::CACHE_CONTROL,"no-store"),(header::REFERRER_POLICY,"no-referrer"),(header::CONTENT_SECURITY_POLICY,"default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'")],Html(miliastra_core::invitation_page::HTML)).into_response()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let pool = PgPool::connect(&std::env::var("DATABASE_URL")?).await?;
    sqlx::raw_sql(include_str!("../migrations/001.sql"))
        .execute(&pool)
        .await?;
    let (tx, _) = broadcast::channel(256);
    let (stop, shutdown) = tokio::sync::watch::channel(false);
    let state = App {
        shutdown,
        finish_requests: Arc::new(Mutex::new(HashMap::new())),
        presence: Arc::new(Default::default()),
        pool,
        events: Arc::new(tx),
        endpoint: std::env::var("PUBLIC_URL").unwrap_or_else(|_| "http://127.0.0.1:8787".into()),
        limits: Arc::new(Limiter {
            trust_forwarded: std::env::var("TRUST_FORWARDED_FOR").is_ok_and(|v| v == "1"),
            disabled: std::env::var("DISABLE_RATE_LIMITS").is_ok_and(|v| v == "1"),
            windows: Mutex::new(HashMap::new()),
        }),
    };
    let maintenance_task = tokio::spawn(maintenance(state.clone()));
    let app = Router::new()
        .route(
            "/brand/logo.png",
            get(|| async {
                use axum::http::header;
                (
                    [
                        (header::CONTENT_TYPE, "image/png"),
                        (header::CACHE_CONTROL, "public, max-age=3600"),
                    ],
                    miliastra_core::invitation_page::LOGO,
                )
            }),
        )
        .route("/invite/{id}", get(invitation_page))
        .route("/invitations/resolve", post(resolve_invitation))
        .route("/health", get(|| async { "ok" }))
        .route("/projects", post(create))
        .route("/projects/{id}", get(view))
        .route("/projects/{id}/join", post(join))
        .route("/projects/{id}/invite", post(invitation))
        .route("/projects/{id}/members/remove", post(remove_member))
        .route("/projects/{id}/members/owner", post(transfer_ownership))
        .route("/projects/{id}/locks/acquire", post(acquire))
        .route("/projects/{id}/locks/renew", post(renew))
        .route("/projects/{id}/locks/release", post(release))
        .route("/projects/{id}/locks/request", post(request_finish))
        .route(
            "/projects/{id}/access-requests",
            post(request_access).get(pending_access),
        )
        .route("/projects/{id}/access-requests/status", post(access_status))
        .route("/projects/{id}/access-requests/result", post(record_access))
        .route("/projects/{id}/publish", post(publish))
        .route("/projects/{id}/names", post(publish_names))
        .route("/projects/{id}/history", get(history))
        .route("/projects/{id}/events", get(events))
        .layer(axum::middleware::map_response(
            |mut response: Response| async move {
                response.headers_mut().insert(
                    "x-miliastra-contract",
                    miliastra_core::contract_fingerprint()
                        .parse()
                        .expect("hex contract hash"),
                );
                response
            },
        ))
        .layer(DefaultBodyLimit::max(
            miliastra_core::constants::MAX_METADATA_BYTES,
        ))
        .layer(middleware::from_fn(log_requests))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(
        std::env::var("BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8787".into()),
    )
    .await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        // Docker stops containers with SIGTERM; finish open requests first.
        #[cfg(unix)]
        {
            let mut term =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("signal handler");
            tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = term.recv() => {} }
        }
        #[cfg(not(unix))]
        let _ = tokio::signal::ctrl_c().await;
        let _ = stop.send(true);
    })
    .await?;
    let _ = maintenance_task.await;
    Ok(())
}

#[cfg(test)]
mod privacy_tests {
    use super::*;
    use std::io::Write;
    #[derive(Clone)]
    struct Capture(Arc<Mutex<Vec<u8>>>);
    impl Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    #[tokio::test(flavor = "current_thread")]
    async fn request_logs_use_templates_and_never_record_identifiers_or_searches() {
        let output = Arc::new(Mutex::new(vec![]));
        let writer = output.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_ansi(false)
            .without_time()
            .with_writer(move || Capture(writer.clone()))
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);
        let app = Router::new()
            .route("/projects/{id}", get(|| async { "ok" }))
            .layer(middleware::from_fn(log_requests));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client = reqwest_for_tests::Client::new();
        client
            .get(format!(
                "http://{addr}/projects/private-project?search=private-email"
            ))
            .send()
            .await
            .unwrap();
        client
            .get(format!(
                "http://{addr}/private-unknown-path?token=private-token"
            ))
            .send()
            .await
            .unwrap();
        task.abort();
        let log = String::from_utf8(output.lock().unwrap().clone()).unwrap();
        assert!(log.contains("/projects/{id}"), "{log}");
        assert!(log.contains("unmatched"), "{log}");
        for private in [
            "private-project",
            "private-email",
            "private-unknown-path",
            "private-token",
            "127.0.0.1",
        ] {
            assert!(!log.contains(private), "{log}");
        }
    }
}
