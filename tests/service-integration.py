"""Focused integration scenarios; requires the service at MCOLLAB_TEST_URL.
Creates only synthetic project metadata, never real level files.
"""

import concurrent.futures, json, os, urllib.request, urllib.error, uuid, base64, secrets, hashlib, subprocess, threading
from pathlib import Path

SOURCE_ROOT = Path(__file__).resolve().parents[1]
os.chdir(SOURCE_ROOT)
from urllib.parse import urlsplit, parse_qs, urlencode

FIXTURE_KEYS = {}
FIXTURE_STATE = {}
FIXTURE_LOCK = threading.RLock()


def new_fixture_key():
    key = secrets.token_hex(32)
    kid = hashlib.sha256(bytes.fromhex(key)).hexdigest()
    return "mcollab-key-v2:" + base64.urlsafe_b64encode(
        json.dumps(
            dict(current=kid, index=secrets.token_hex(32), keys={kid: key})
        ).encode()
    ).decode().rstrip("=")


def codec(pid, operation, route, value):
    with FIXTURE_LOCK:
        data = dict(
            bundle=FIXTURE_KEYS[pid],
            endpoint=URL,
            project=pid,
            operation=operation,
            route=route,
            value=value,
            state=FIXTURE_STATE.get(pid),
        )
        result = subprocess.run(
            ["node", "tests/private-fixture.cjs"],
            input=json.dumps(data),
            text=True,
            capture_output=True,
            check=True,
        )
        result = json.loads(result.stdout)
        FIXTURE_STATE[pid] = result["state"]
        return result["value"]


def raw_request(path, body=None, token=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(
        URL + path,
        data=json.dumps(body).encode() if body is not None else None,
        headers=headers,
    )
    try:
        with op.open(req, timeout=20) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            body = json.loads(raw)
        except json.JSONDecodeError:
            body = {"error": raw}
        return e.code, body


URL = os.environ.get("MCOLLAB_TEST_URL", "http://127.0.0.1:18787")
op = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def request(path, body=None, token=None):
    # Encrypt requests like the app does, so the checks below can use plain values.
    split = urlsplit(path)
    segments = split.path.strip("/").split("/")
    pid = (
        segments[1]
        if len(segments) > 1 and segments[0] == "projects"
        else body.get("project")
        if isinstance(body, dict) and split.path == "/invitations/resolve"
        else None
    )
    route = (
        "/" + ("/".join(segments[2:]))
        if pid and segments[0] == "projects"
        else split.path
    )
    filters = parse_qs(split.query) if route == "/history" else {}
    if set(filters) - {"section", "before"}:
        return raw_request(path, body, token)
    if body is not None:
        body = json.loads(json.dumps(body))
        if path == "/projects":
            pid = str(uuid.uuid4())
            FIXTURE_KEYS[pid] = new_fixture_key()
            body.setdefault("baselineId", str(uuid.uuid4()))
            body["storage"].setdefault("driveId", None)
        publication = (
            body.get("baselineId")
            if path == "/projects"
            else body.get("id")
            if route == "/publish"
            else None
        )
        if publication:
            for r in body.get("baseline", body.get("revisions", [])):
                r["artifact"] = f"History/{publication}/" + (
                    "shared.gilh"
                    if r["section"] == "shared"
                    else str(int(r["section"]) + 1) + ".gis"
                )
        try:
            body = codec(pid, "encode", route, body) if pid else body
        except subprocess.CalledProcessError:
            return 409, {"error": "Local client rejected invalid private metadata"}
    if filters:
        path = split.path + (
            "?" + urlencode({"before": filters["before"][0]})
            if "before" in filters
            else ""
        )
    status, value = raw_request(path, body, token)
    if status == 200 and pid:
        value = codec(pid, "decode", route, value)
        if route == "/history":

            def matches(u):
                if filters.get("section") and not any(
                    r["section"] == filters["section"][0]
                    for r in u["revisions"] + u.get("nameChanges", [])
                ):
                    return False
                return True

            value["entries"] = [u for u in value["entries"] if matches(u)]
    return status, value


def rev(section, h, parent=None):
    return dict(
        section=section,
        name="Boats" if section == "5" else section,
        hash=h * 64,
        contentHash="b" * 64,
        parent=parent,
        artifact="History/" + str(uuid.uuid4()) + "/" + str(int(section) + 1) + ".gis",
        size=100,
        sharedDependency=None,
    )


code, owner = request(
    "/projects",
    dict(
        name="Integration " + str(uuid.uuid4()),
        displayName="Owner",
        storage=dict(kind="folder", location=""),
        baseline=[],
    ),
)
assert code == 200, owner
pid = owner["project"]["id"]
base = "/projects/" + pid
t = owner["token"]
invite = owner["invitation"]["invite"]
# Looking up an invitation doesn't join or reveal who's in the project.
code, resolved = request("/invitations/resolve", dict(project=pid, invite=invite))
assert code == 200, resolved
assert resolved["owner"]["id"] == owner["member"], resolved
assert {k: v for k, v in resolved.items() if k != "owner"} == dict(
    version=1,
    endpoint=URL,
    project=pid,
    invite=invite,
    projectName="Shared project",
    storageKind="folder",
    storage=dict(kind="folder", location="", driveId=None),
)
assert (
    request("/invitations/resolve", dict(project=pid, invite=str(uuid.uuid4())))[0]
    == 409
)
assert request("/invitations/resolve", dict(project=pid, invite="../invalid"))[0] == 400
assert (
    request("/invitations/resolve", dict(project=pid, invite=invite, bytes="blocked"))[
        0
    ]
    == 422
)
with op.open(URL + "/invite/" + pid, timeout=10) as page:
    assert page.headers["Cache-Control"] == "no-store"
    assert page.headers["Referrer-Policy"] == "no-referrer"
    html = page.read()
    assert b"Open miliastra/collab" in html and b"Download invitation" not in html
code, guest = request(base + "/join", dict(invite=invite, displayName="Alex"))
assert code == 200, guest
g = guest["token"]
assert request(base)[0] == 401
with concurrent.futures.ThreadPoolExecutor() as pool:
    results = list(
        pool.map(
            lambda token: request(base + "/locks/acquire", dict(section="5"), token),
            [t, g],
        )
    )
assert sorted(r[0] for r in results) == [200, 409], results
winner = t if results[0][0] == 200 else g
loser = g if winner == t else t
lease = next(r[1] for r in results if r[0] == 200)
assert (
    request(base + "/locks/renew", dict(section="5", fence=lease["fence"] + 1), winner)[
        0
    ]
    == 409
)
# Sharing several slices is all-or-nothing when one isn't reserved.
update = dict(
    id=str(uuid.uuid4()),
    summary="Fixed the boat deck",
    details="No more falling through.",
    revisions=[rev("5", "a"), rev("6", "c")],
    fences={"5": lease["fence"]},
    restores=None,
)
assert request(base + "/publish", update, winner)[0] == 409
assert request(base, token=t)[1]["heads"] == {}
update["revisions"] = update["revisions"][:1]
code, published = request(base + "/publish", update, winner)
assert code == 200, published
code, retry = request(base + "/publish", update, winner)
assert code == 200 and retry["id"] == published["id"]
assert request(base + "/history", token=t)[1]["entries"][0]["sequence"] == 1
assert raw_request(base + "/history?q=never-send-private-search", token=t)[0] == 400
# Stale parent and empty changelog are rejected.
stale = {**update, "id": str(uuid.uuid4())}
assert request(base + "/publish", stale, winner)[0] == 409
blank = {**update, "id": str(uuid.uuid4()), "summary": "  "}
assert request(base + "/publish", blank, winner)[0] == 409
# After a takeover, the old holder can't renew or share, even with an unexpired lease.
taker = g if winner == t else t
code, takeover = request(
    base + "/locks/acquire", dict(section="5", takeover=True), taker
)
assert code == 200, takeover
assert (
    request(base + "/locks/renew", dict(section="5", fence=lease["fence"]), winner)[0]
    == 409
)
# Published changelogs can't be edited.
assert (
    request(
        base + "/history/" + published["id"] + "/corrections", dict(text="Unused"), t
    )[0]
    == 404
)
entry = request(base + "/history", token=t)[1]["entries"][0]
assert entry["summary"] == "Fixed the boat deck" and "corrections" not in entry
assert request(base + "/history?section=5", token=t)[1]["entries"]
assert request(base + "/history?section=6", token=t)[1]["entries"] == []
assert request(base + "/history?before=1", token=t)[1]["entries"] == []
# Restoring an old version creates a new update with a reason.
code, owner_lease = request(
    base + "/locks/acquire", dict(section="5", takeover=True), t
)
assert code == 200
followup = {
    **update,
    "id": str(uuid.uuid4()),
    "summary": "Reworked the deck",
    "revisions": [rev("5", "c", "a" * 64)],
    "fences": {"5": owner_lease["fence"]},
}
code, newer = request(base + "/publish", followup, t)
assert code == 200, newer
restore = {
    **followup,
    "id": str(uuid.uuid4()),
    "summary": "Restore deck because the new layout blocks fishing",
    "revisions": [rev("5", "a", "c" * 64)],
    "restores": published["id"],
}
code, restored_update = request(base + "/publish", restore, t)
assert code == 200, restored_update
assert (
    restored_update["sequence"] == 3 and restored_update["restores"] == published["id"]
)
assert len(request(base + "/history", token=t)[1]["entries"]) == 3
# A revision ID from an older update can't be reused.
historical = raw_request(base + "/history", token=t)[1]["entries"][-1]["revisions"][0][
    "revision"
]
recycle = codec(
    pid,
    "encode",
    "/publish",
    {
        **restore,
        "id": str(uuid.uuid4()),
        "revisions": [rev("5", "e", "a" * 64)],
        "restores": None,
    },
)
recycle["revisions"][0]["revision"] = historical
assert raw_request(base + "/publish", recycle, t)[0] == 409

assert [
    u["sequence"] for u in request(base + "/history?before=3", token=t)[1]["entries"]
] == [2, 1]

# The coordinator rejects file data in requests.
assert (
    request(base + "/publish", {**update, "bytes": "private level bytes"}, winner)[0]
    == 422
)
assert request(base + "/locks/acquire", dict(section="../escape"), winner)[0] == 409


# An invitation stops working once it expires.
import hashlib

expiry_sql = (
    "UPDATE projects SET state=jsonb_set(state,'{invites,"
    + hashlib.sha256(invite.encode()).hexdigest()
    + "}','0'::jsonb) WHERE id='"
    + pid
    + "';"
)
subprocess.run(
    [
        os.environ.get("PSQL", ".tools/pgsql/bin/psql.exe"),
        os.environ.get(
            "MCOLLAB_TEST_DATABASE_URL", "postgres://collab@127.0.0.1:55432/postgres"
        ),
        "-v",
        "ON_ERROR_STOP=1",
        "-c",
        expiry_sql,
    ],
    check=True,
    capture_output=True,
)
assert request("/invitations/resolve", dict(project=pid, invite=invite))[0] == 409

print(
    "Service integration passed: concurrent locks, authentication, fencing, atomic publication, retry, stale heads, immutable changelogs, slice filtering and pagination, hosted invitation validation/expiry, metadata-only protocol."
)

# Any member can rename slices; renaming never changes slice versions.
code, nowner = request(
    "/projects",
    dict(
        name="Names " + str(uuid.uuid4()),
        displayName="Names owner",
        storage=dict(kind="folder", location=""),
        baseline=[rev("5", "a"), rev("6", "c")],
    ),
)
assert code == 200, nowner
nb = "/projects/" + nowner["project"]["id"]
nt = nowner["token"]
code, nguest = request(
    nb + "/join", dict(invite=nowner["invitation"]["invite"], displayName="Names guest")
)
assert code == 200
initial = request(nb, token=nt)[1]
assert (
    initial["sectionNames"] == {"5": "Boats", "6": "6"} and initial["namesVersion"] == 0
)
names = dict(
    id=str(uuid.uuid4()),
    parentVersion=0,
    summary="Clarified area names",
    details="Metadata only",
    changes=[
        dict(section="5", before="Boats", after="Ships"),
        dict(section="6", before="6", after="Islands"),
    ],
)
assert request(nb + "/names", {**names, "summary": " "}, nt)[0] == 409
assert (
    request(
        nb + "/names",
        {
            **names,
            "changes": [
                names["changes"][0],
                dict(section="6", before="wrong", after="Islands"),
            ],
        },
        nt,
    )[0]
    == 409
)
assert request(nb, token=nt)[1]["sectionNames"] == initial["sectionNames"]
assert request(nb + "/names", {**names, "bytes": "private"}, nt)[0] == 422
code, nu = request(nb + "/names", names, nt)
assert code == 200, nu
assert nu["revisions"] == [] and nu["nameChanges"] == names["changes"]
assert request(nb + "/names", names, nt)[1]["id"] == nu["id"]
assert request(nb + "/names", {**names, "id": str(uuid.uuid4())}, nt)[0] == 409
assert request(nb + "/names", {**names, "summary": "Reused"}, nt)[0] == 409
nv = request(nb, token=nguest["token"])[1]
assert (
    nv["heads"] == initial["heads"]
    and nv["sectionNames"] == {"5": "Ships", "6": "Islands"}
    and nv["namesVersion"] == 1
)
assert request(nb + "/history?section=6", token=nt)[1]["entries"][0]["id"] == nu["id"]
print(
    "Section names service proof passed: member permission, atomic rename, stale version, idempotent retry, strict metadata-only schema, guest synchronization, indexed History."
)
# Any member can invite; "ask to share" only reaches someone holding the slice; folder
# access requests carry only ciphertext, which is cleared once handled.
code, fowner = request(
    "/projects",
    dict(
        name="Access " + str(uuid.uuid4()),
        displayName="Owner",
        storage=dict(kind="google", location="folder-id"),
        baseline=[],
    ),
)
assert code == 200, fowner
fbase = "/projects/" + fowner["project"]["id"]
ft = fowner["token"]
finvite = fowner["invitation"]["invite"]
code, fguest = request(fbase + "/join", dict(invite=finvite, displayName="Sam"))
assert code == 200, fguest
fg = fguest["token"]
code, member_invite = request(fbase + "/invite", {}, fg)
assert code == 200, member_invite
view = request(fbase, token=ft)[1]
assert "invites" not in view, view
assert finvite not in json.dumps(view) and member_invite["invite"] not in json.dumps(
    view
)
assert all(m["joined"] > 0 for m in view["members"]), view["members"]
assert request(fbase + "/locks/request", dict(section="5"), fg)[0] == 409
assert request(fbase + "/locks/acquire", dict(section="5"), ft)[0] == 200
code, asked = request(fbase + "/locks/request", dict(section="5"), fg)
assert code == 200 and asked["holder"] == "Owner", asked
assert request(fbase + "/locks/request", dict(section="5"), fg)[0] == 409
assert request(fbase + "/locks/request", dict(section="5"), ft)[0] == 409
sealed = dict(version=1, keyId="a" * 64, nonce="b" * 24, ciphertext="c" * 2080)
access_body = dict(invite=finvite, id=str(uuid.uuid4()), sealed=sealed)
code, ar = request(fbase + "/access-requests", access_body)
assert code == 200, ar
assert (
    request(
        fbase + "/access-requests",
        dict(invite=finvite, email="sam@example.com", displayName="Sam"),
    )[0]
    == 422
)
assert request(fbase + "/access-requests", access_body)[1]["id"] == ar["id"]
assert (
    request(
        fbase + "/access-requests",
        dict(invite=str(uuid.uuid4()), id=str(uuid.uuid4()), sealed=sealed),
    )[0]
    == 409
)
assert (
    request(fbase + "/access-requests/status", dict(invite=finvite, id=ar["id"]))[1][
        "status"
    ]
    == "pending"
)
assert (
    request(
        fbase + "/access-requests/status",
        dict(invite=member_invite["invite"], id=ar["id"]),
    )[0]
    == 409
)
assert request(fbase + "/access-requests", token=fg)[0] == 409
pending = request(fbase + "/access-requests", token=ft)[1]
assert [p["sealed"] for p in pending] == [sealed] and all(
    "email" not in p and "name" not in p for p in pending
), pending
assert (
    request(
        fbase + "/access-requests/result",
        dict(id=ar["id"], granted=True, message="Folder shared"),
        fg,
    )[0]
    == 409
)
assert (
    request(
        fbase + "/access-requests/result",
        dict(id=ar["id"], granted=True, message="Folder shared"),
        ft,
    )[0]
    == 200
)
st = request(fbase + "/access-requests/status", dict(invite=finvite, id=ar["id"]))[1]
assert {k: st[k] for k in ("status", "message")} == {
    "status": "granted",
    "message": "Folder shared",
}, st
assert (
    raw_request(fbase + "/access-requests/status", dict(invite=finvite, id=ar["id"]))[
        1
    ]["ownerOnline"]
    is False
)
assert request(fbase + "/access-requests", token=ft)[1] == []
print(
    "Friction-reduction service proof passed: member invitations, open-invitation metadata without secrets, join dates, throttled finish requests, invitation-authorized folder access requests with encrypted contacts."
)
# Any member, not only the owner, can rename slices.
gn = dict(
    id=str(uuid.uuid4()),
    parentVersion=1,
    summary="Guest rename",
    details="",
    changes=[dict(section="6", before="Islands", after="Isles")],
)
code, gu = request(nb + "/names", gn, nguest["token"])
assert code == 200, gu
assert request(nb, token=nt)[1]["sectionNames"]["6"] == "Isles"
print("Member rename proof passed: a non-owner renamed a slice and the owner sees it.")
# Only the owner can remove members or hand over ownership; a removed member's
# invitations stop working.
assert request(fbase + "/members/remove", dict(member=fowner["member"]), fg)[0] == 409
assert request(fbase + "/members/owner", dict(member=fguest["member"]), fg)[0] == 409
assert request(fbase + "/members/owner", dict(member=fguest["member"]), ft)[0] == 200
assert request(fbase + "/members/remove", dict(member=fguest["member"]), ft)[0] == 409
assert request(fbase + "/members/remove", dict(member=fowner["member"]), fg)[0] == 200
code, denied = request(fbase, token=ft)
assert code == 401 and "removed" in denied["error"], denied
assert request(fbase + "/join", dict(invite=finvite, displayName="Late"))[0] == 409
assert [m["owner"] for m in request(fbase, token=fg)[1]["members"]] == [True]
print(
    "Team management proof passed: owner-only removal and handover, removed members are told why and their invitations stop working."
)
