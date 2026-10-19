pub use crate::coordination::{
    AccessRequest, SealedAccess, ACCESS_REQUEST_LIFETIME, REMOVED_MESSAGE,
};
use crate::{
    constants::*,
    errors::{ErrorCode, ServiceError},
};
use crate::{
    control::{self, *},
    hash, opaque, Invitation,
};
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
const MAX_PENDING_ACCESS_REQUESTS: usize = 50;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectState {
    pub id: String,
    pub project_hash: String,
    pub members: BTreeMap<String, Member>,
    pub tokens: BTreeMap<String, String>,
    pub invites: BTreeMap<String, i64>,
    pub invite_creators: BTreeMap<String, String>,
    pub invite_bootstraps: BTreeMap<String, String>,
    pub locks: BTreeMap<String, Lease>,
    pub fences: BTreeMap<String, u64>,
    pub heads: BTreeMap<String, Revision>,
    pub names_version: u64,
    pub sequence: u64,
    pub history: Vec<Update>,
    pub access_requests: BTreeMap<String, AccessRequest>,
    pub removed_tokens: BTreeSet<String>,
}
impl ProjectState {
    pub fn create(req: CreateProject, at: i64, endpoint: String) -> Result<(Self, Joined)> {
        for id in [&req.id, &req.member_id, &req.baseline_id] {
            ensure!(
                uuid::Uuid::parse_str(id)?.to_string() == *id,
                "Invalid identifier"
            );
        }
        control::fingerprint(&req.profile_hash)?;
        control::fingerprint(&req.project_hash)?;
        control::fingerprint(&req.manifest_hash)?;
        control::bootstrap(&req.bootstrap)?;
        ensure!(
            req.baseline.len() <= MAX_PROJECT_RESOURCES,
            "Invalid baseline"
        );
        let mut heads = BTreeMap::new();
        let mut ids = BTreeSet::new();
        for r in &req.baseline {
            control::revision(r)?;
            ensure!(r.parent.is_none(), "Baseline has a parent");
            ensure!(
                heads.insert(r.section.clone(), r.clone()).is_none()
                    && ids.insert(r.revision.clone()),
                "Duplicate baseline revision"
            );
        }
        for r in &req.baseline {
            if r.section != "shared" {
                ensure!(
                    r.shared_dependency == heads.get("shared").map(|s| s.revision.clone()),
                    "Invalid baseline dependency"
                );
            }
        }
        let secret = format!(
            "{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        );
        let invite = uuid::Uuid::new_v4().to_string();
        let ih = hash(invite.as_bytes());
        let receipt = Update {
            id: req.baseline_id,
            author_id: req.member_id.clone(),
            manifest_hash: req.manifest_hash,
            at,
            sequence: 1,
            revisions: req.baseline,
            restores: None,
            name_sections: vec![],
            names_parent: None,
        };
        let empty = heads.is_empty();
        let state = Self {
            id: req.id.clone(),
            project_hash: req.project_hash,
            members: BTreeMap::from([(
                req.member_id.clone(),
                Member {
                    id: req.member_id.clone(),
                    profile_hash: req.profile_hash,
                    owner: true,
                    joined: at,
                },
            )]),
            tokens: BTreeMap::from([(hash(secret.as_bytes()), req.member_id.clone())]),
            invites: BTreeMap::from([(ih.clone(), at + 7 * 86400)]),
            invite_creators: BTreeMap::from([(ih.clone(), req.member_id.clone())]),
            invite_bootstraps: BTreeMap::from([(ih, req.bootstrap)]),
            locks: BTreeMap::new(),
            fences: BTreeMap::new(),
            heads,
            names_version: 0,
            sequence: if empty { 0 } else { 1 },
            history: if empty { vec![] } else { vec![receipt] },
            access_requests: BTreeMap::new(),
            removed_tokens: BTreeSet::new(),
        };
        let joined = Joined {
            project: state.view(at),
            member: req.member_id,
            token: secret,
            invitation: Some(Invitation {
                version: 1,
                endpoint,
                project: req.id,
                invite,
            }),
        };
        Ok((state, joined))
    }
    pub fn publish_names(&mut self, member: &str, req: PublishNames, now: i64) -> Result<Update> {
        ensure!(self.members.contains_key(member), "Not a member");
        control::fingerprint(&req.manifest_hash)?;
        uuid::Uuid::parse_str(&req.id)?;
        if let Some(old) = self.history.iter().find(|u| u.id == req.id) {
            ensure!(
                old.author_id == member
                    && old.manifest_hash == req.manifest_hash
                    && old.names_parent == Some(req.parent_version)
                    && old.name_sections == req.sections
                    && old.revisions.is_empty(),
                "Update ID already used"
            );
            return Ok(old.clone());
        }
        ensure!(
            req.parent_version == self.names_version,
            "Section names changed; refresh and review your draft"
        );
        ensure!(
            !req.sections.is_empty() && req.sections.len() <= 64,
            "Choose section names to share"
        );
        let mut seen = BTreeSet::new();
        for id in &req.sections {
            ensure!(
                id != "shared"
                    && opaque::resource(id)
                    && self.heads.contains_key(id)
                    && seen.insert(id.clone()),
                "Unknown or duplicate section"
            );
        }
        let receipt = Update {
            id: req.id,
            author_id: member.into(),
            manifest_hash: req.manifest_hash,
            at: now,
            sequence: self.sequence + 1,
            revisions: vec![],
            restores: None,
            name_sections: req.sections,
            names_parent: Some(req.parent_version),
        };
        self.names_version += 1;
        self.sequence = receipt.sequence;
        self.history.push(receipt.clone());
        Ok(receipt)
    }
    pub fn authenticate(&self, token: &str) -> Result<String> {
        let key = crate::hash(token.as_bytes());
        ensure!(
            !self.removed_tokens.contains(&key),
            ServiceError::new(ErrorCode::Removed, REMOVED_MESSAGE)
        );
        self.tokens.get(&key).cloned().ok_or_else(|| {
            anyhow::Error::new(ServiceError::new(
                ErrorCode::Unauthorized,
                "Sign in again to continue",
            ))
        })
    }
    fn owner_check(&self, member: &str, what: &str) -> Result<()> {
        ensure!(
            self.members.get(member).is_some_and(|m| m.owner),
            "Only the project owner can {what}"
        );
        Ok(())
    }
    pub fn remove_member(&mut self, by: &str, member: &str) -> Result<()> {
        self.owner_check(by, "remove creators")?;
        ensure!(
            by != member,
            "Hand over ownership before leaving the project"
        );
        ensure!(self.members.remove(member).is_some(), "Not a member");
        let tokens: Vec<String> = self
            .tokens
            .iter()
            .filter(|(_, m)| m.as_str() == member)
            .map(|(t, _)| t.clone())
            .collect();
        for t in tokens {
            self.tokens.remove(&t);
            if self.removed_tokens.len() < 10_000 {
                self.removed_tokens.insert(t);
            }
        }
        self.locks.retain(|_, l| l.member != member);
        let theirs: Vec<String> = self
            .invite_creators
            .iter()
            .filter(|(_, m)| m.as_str() == member)
            .map(|(k, _)| k.clone())
            .collect();
        for k in theirs {
            self.invites.remove(&k);
            self.invite_creators.remove(&k);
            self.invite_bootstraps.remove(&k);
        }
        Ok(())
    }
    pub fn transfer_ownership(&mut self, by: &str, to: &str) -> Result<()> {
        self.owner_check(by, "hand over ownership")?;
        ensure!(by != to, "You are already the owner");
        ensure!(self.members.contains_key(to), "Not a member");
        for m in self.members.values_mut() {
            m.owner = m.id == to;
        }
        Ok(())
    }
    pub fn view(&self, now: i64) -> ProjectView {
        ProjectView {
            id: self.id.clone(),
            project_hash: self.project_hash.clone(),
            members: self.members.values().cloned().collect(),
            locks: self
                .locks
                .values()
                .filter(|l| l.expires > now)
                .cloned()
                .collect(),
            heads: self.heads.clone(),
            names_version: self.names_version,
            sequence: self.sequence,
            presence: vec![],
        }
    }
    fn valid_invite(&self, invite: &str, now: i64) -> Result<String> {
        let key = hash(invite.as_bytes());
        ensure!(
            self.invites.get(&key).is_some_and(|t| *t > now),
            "Invitation expired; ask the owner for a new invitation"
        );
        Ok(key)
    }
    pub fn cleanup(&mut self, now: i64) -> bool {
        let before = (
            self.invites.len(),
            self.invite_creators.len(),
            self.locks.len(),
            self.access_requests.len(),
        );
        self.invites.retain(|_, expiry| *expiry > now);
        self.invite_creators
            .retain(|key, _| self.invites.contains_key(key));
        self.invite_bootstraps
            .retain(|key, _| self.invites.contains_key(key));
        self.locks.retain(|_, lease| lease.expires > now);
        self.access_requests
            .retain(|_, r| now - r.at < ACCESS_REQUEST_LIFETIME);
        before
            != (
                self.invites.len(),
                self.invite_creators.len(),
                self.locks.len(),
                self.access_requests.len(),
            )
    }
    pub fn request_access(
        &mut self,
        invite: &str,
        id: &str,
        sealed: SealedAccess,
        now: i64,
    ) -> Result<String> {
        let key = self.valid_invite(invite, now)?;
        uuid::Uuid::parse_str(id)?;
        sealed.validate()?;
        self.cleanup(now);
        let payload_hash = hash(&serde_json::to_vec(&sealed)?);
        if let Some(old) = self.access_requests.get(id) {
            ensure!(
                old.invite == key && old.payload_hash == payload_hash,
                "Folder access request ID already used"
            );
            return Ok(id.into());
        }
        ensure!(
            self.access_requests
                .values()
                .filter(|r| r.status == "pending")
                .count()
                < MAX_PENDING_ACCESS_REQUESTS,
            "Too many people are waiting for folder access; ask the owner to check the app"
        );
        self.access_requests.insert(
            id.into(),
            AccessRequest {
                id: id.into(),
                invite: key,
                sealed,
                payload_hash,
                at: now,
                status: "pending".into(),
                message: String::new(),
            },
        );
        Ok(id.into())
    }
    pub fn access_status(&self, invite: &str, id: &str, now: i64) -> Result<(String, String)> {
        let key = hash(invite.as_bytes());
        let r = self
            .access_requests
            .get(id)
            .filter(|r| r.invite == key && now - r.at < ACCESS_REQUEST_LIFETIME)
            .ok_or_else(|| {
                anyhow::anyhow!("Folder access request not found; join again from the invitation")
            })?;
        Ok((r.status.clone(), r.message.clone()))
    }
    pub fn pending_access(&self, member: &str, now: i64) -> Result<Vec<AccessRequest>> {
        ensure!(
            self.members.get(member).is_some_and(|m| m.owner),
            "Only the owner can share the team folder"
        );
        Ok(self
            .access_requests
            .values()
            .filter(|r| r.status == "pending" && now - r.at < ACCESS_REQUEST_LIFETIME)
            .cloned()
            .collect())
    }
    pub fn record_access(&mut self, member: &str, id: &str, result: &str) -> Result<()> {
        ensure!(
            self.members.get(member).is_some_and(|m| m.owner),
            "Only the owner can share the team folder"
        );
        opaque::field(result, &format!("access-result:{id}"))?;
        let r = self
            .access_requests
            .get_mut(id)
            .ok_or_else(|| anyhow::anyhow!("Folder access request not found"))?;
        r.status = "settled".into();
        r.message = result.into();
        r.sealed.ciphertext.clear();
        r.sealed.nonce.clear();
        Ok(())
    }
    pub fn create_invite(&mut self, member: &str, now: i64, bootstrap: String) -> Result<String> {
        ensure!(self.members.contains_key(member), "Not a member");
        control::bootstrap(&bootstrap)?;
        let code = uuid::Uuid::new_v4().to_string();
        self.invites.retain(|_, t| *t > now);
        let invites = &self.invites;
        self.invite_creators.retain(|k, _| invites.contains_key(k));
        let key = hash(code.as_bytes());
        self.invites.insert(key.clone(), now + 7 * 86400);
        self.invite_bootstraps.insert(key.clone(), bootstrap);
        self.invite_creators.insert(key, member.into());
        Ok(code)
    }
    pub fn acquire(
        &mut self,
        member: &str,
        section: &str,
        now: i64,
        takeover: bool,
    ) -> Result<Lease> {
        ensure!(opaque::resource(section), "Unknown section");
        self.members
            .get(member)
            .ok_or_else(|| anyhow::anyhow!("Not a member"))?;
        if let Some(l) = self.locks.get(section) {
            if l.expires > now && l.member != member {
                ensure!(takeover, "This slice is reserved by another creator");
            }
        }
        let same = self
            .locks
            .get(section)
            .is_some_and(|l| l.member == member && l.expires > now);
        let fence = self.fences.entry(section.into()).or_default();
        if !same {
            *fence += 1;
        }
        let lease = Lease {
            section: section.into(),
            member: member.into(),
            fence: *fence,
            expires: now + LEASE_TTL_SECS,
        };
        self.locks.insert(section.into(), lease.clone());
        Ok(lease)
    }
    pub fn owner_id(&self) -> Option<&str> {
        self.members
            .values()
            .find(|m| m.owner)
            .map(|m| m.id.as_str())
    }
    pub fn owner_for_invitation(&self) -> serde_json::Value {
        self.members
            .values()
            .find(|m| m.owner)
            .map(|m| serde_json::json!({ "id": m.id }))
            .unwrap_or(serde_json::Value::Null)
    }
    pub fn other_holder(&self, member: &str, section: &str, now: i64) -> Option<Lease> {
        self.locks
            .get(section)
            .filter(|l| l.expires > now && l.member != member)
            .cloned()
    }
    pub fn renew(&mut self, member: &str, section: &str, fence: u64, now: i64) -> Result<Lease> {
        let l = self.locks.get_mut(section).ok_or_else(|| {
            anyhow::Error::new(ServiceError::new(
                ErrorCode::ReservationLost,
                "Reservation expired",
            ))
        })?;
        ensure!(
            l.member == member && l.fence == fence && l.expires > now,
            ServiceError::new(
                ErrorCode::ReservationLost,
                "Reservation changed; reserve the section again"
            )
        );
        l.expires = now + LEASE_TTL_SECS;
        Ok(l.clone())
    }
    pub fn finish_request(&self, member: &str, section: &str, now: i64) -> Result<(Lease, String)> {
        ensure!(opaque::resource(section), "Unknown section");
        let m = self
            .members
            .get(member)
            .ok_or_else(|| anyhow::anyhow!("Not a member"))?;
        let l = self
            .locks
            .get(section)
            .filter(|l| l.expires > now)
            .ok_or_else(|| anyhow::anyhow!("Nobody is working on this slice now"))?;
        ensure!(l.member != member, "You already have this slice reserved");
        Ok((l.clone(), m.id.clone()))
    }
    pub fn release(&mut self, member: &str, section: &str, fence: u64) -> Result<()> {
        if let Some(l) = self.locks.get(section) {
            ensure!(
                l.member == member && l.fence == fence,
                "Reservation has changed"
            );
            self.locks.remove(section);
        }
        Ok(())
    }
    pub fn publish(&mut self, member: &str, req: PublishRequest, now: i64) -> Result<Update> {
        ensure!(self.members.contains_key(member), "Not a member");
        uuid::Uuid::parse_str(&req.id)?;
        control::fingerprint(&req.manifest_hash)?;
        if let Some(old) = self.history.iter().find(|u| u.id == req.id) {
            ensure!(
                old.author_id == member
                    && old.manifest_hash == req.manifest_hash
                    && old.revisions == req.revisions
                    && old.restores == req.restores
                    && old.names_parent.is_none(),
                "Update ID already used"
            );
            return Ok(old.clone());
        }
        ensure!(
            !req.revisions.is_empty() && req.revisions.len() <= MAX_PROJECT_RESOURCES,
            "Choose changed sections"
        );
        if let Some(source) = &req.restores {
            ensure!(
                self.history.iter().any(|u| &u.id == source),
                "Restore source not found"
            );
        }
        let mut sections = BTreeSet::new();
        let mut ids = BTreeSet::new();
        for r in &req.revisions {
            control::revision(r)?;
            ensure!(
                sections.insert(r.section.clone()) && ids.insert(r.revision.clone()),
                "Duplicate section or revision"
            );
            ensure!(
                !self
                    .history
                    .iter()
                    .any(|u| u.revisions.iter().any(|old| old.revision == r.revision))
                    && !self.heads.values().any(|old| old.revision == r.revision),
                "Revision ID already used"
            );
            let lease = self
                .locks
                .get(&r.section)
                .ok_or_else(|| anyhow::anyhow!("Reserve this slice before sharing"))?;
            ensure!(
                lease.member == member
                    && lease.expires > now
                    && req.fences.get(&r.section) == Some(&lease.fence),
                "This slice is no longer reserved by you"
            );
            ensure!(
                self.heads.get(&r.section).map(|h| h.revision.clone()) == r.parent,
                "This slice changed since you started; your draft is preserved"
            );
            if r.section != "shared" {
                let shared = req
                    .revisions
                    .iter()
                    .find(|s| s.section == "shared")
                    .or_else(|| self.heads.get("shared"));
                ensure!(
                    r.shared_dependency == shared.map(|s| s.revision.clone()),
                    "Shared settings changed; reconcile before sharing"
                );
            }
        }
        ensure!(
            req.fences.len() == req.revisions.len(),
            "Unexpected reservation"
        );
        let receipt = Update {
            id: req.id,
            author_id: member.into(),
            manifest_hash: req.manifest_hash,
            at: now,
            sequence: self.sequence + 1,
            revisions: req.revisions,
            restores: req.restores,
            name_sections: vec![],
            names_parent: None,
        };
        for r in &receipt.revisions {
            self.heads.insert(r.section.clone(), r.clone());
        }
        self.sequence = receipt.sequence;
        self.history.push(receipt.clone());
        Ok(receipt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn id() -> String {
        uuid::Uuid::new_v4().to_string()
    }
    fn section() -> String {
        "a".repeat(64)
    }
    fn state() -> (ProjectState, String, String) {
        let owner = id();
        let guest = id();
        let (mut state, _) = ProjectState::create(
            CreateProject {
                id: id(),
                member_id: owner.clone(),
                profile_hash: "b".repeat(64),
                project_hash: "c".repeat(64),
                bootstrap: opaque::fixture("storage-bootstrap", "synthetic locator"),
                baseline: vec![],
                baseline_id: id(),
                manifest_hash: "d".repeat(64),
            },
            0,
            "http://127.0.0.1:9".into(),
        )
        .unwrap();
        state.members.insert(
            guest.clone(),
            Member {
                id: guest.clone(),
                profile_hash: "e".repeat(64),
                owner: false,
                joined: 0,
            },
        );
        (state, owner, guest)
    }
    fn request(section: &str, fence: u64, parent: Option<String>) -> PublishRequest {
        PublishRequest {
            id: id(),
            manifest_hash: "f".repeat(64),
            revisions: vec![Revision {
                section: section.into(),
                revision: id(),
                parent,
                shared_dependency: None,
            }],
            fences: BTreeMap::from([(section.into(), fence)]),
            restores: None,
        }
    }
    #[test]
    fn expiry_takeover_and_release_preserve_fencing() {
        let (mut p, a, b) = state();
        let s = section();
        let lease = p.acquire(&a, &s, 1, false).unwrap();
        assert!(p.acquire(&b, &s, 2, false).is_err());
        let newer = p.acquire(&b, &s, 122, false).unwrap();
        assert!(newer.fence > lease.fence);
        assert!(p.renew(&a, &s, lease.fence, 123).is_err());
        assert!(p.release(&a, &s, lease.fence).is_err());
        assert!(p.publish(&a, request(&s, lease.fence, None), 123).is_err());
        p.release(&b, &s, newer.fence).unwrap();
        assert!(p.locks.is_empty());
        assert!(p.fences[&s] > lease.fence);
    }
    #[test]
    fn multi_section_publication_is_atomic_and_retry_is_immutable() {
        let (mut p, a, _) = state();
        let s = section();
        let lease = p.acquire(&a, &s, 1, false).unwrap();
        let req = request(&s, lease.fence, None);
        let mut invalid = req.clone();
        invalid.revisions.push(Revision {
            section: "b".repeat(64),
            revision: id(),
            parent: None,
            shared_dependency: None,
        });
        assert!(p.publish(&a, invalid, 2).is_err());
        assert!(p.heads.is_empty() && p.history.is_empty());
        let accepted = p.publish(&a, req.clone(), 2).unwrap();
        assert_eq!(p.publish(&a, req.clone(), 400).unwrap(), accepted);
        assert_eq!(p.history.len(), 1);
        let mut changed = req.clone();
        changed.manifest_hash = "1".repeat(64);
        assert!(p.publish(&a, changed, 3).is_err());
        let stale = request(&s, lease.fence, None);
        assert!(p.publish(&a, stale, 3).is_err());
        let mut reused = request(
            &s,
            lease.fence,
            Some(accepted.revisions[0].revision.clone()),
        );
        reused.revisions[0].revision = accepted.revisions[0].revision.clone();
        assert!(p.publish(&a, reused, 3).is_err());
    }
    #[test]
    fn random_revision_ancestry_dependencies_and_restore_source_are_checked() {
        let (mut p, a, _) = state();
        let s = section();
        let shared = p.acquire(&a, "shared", 1, false).unwrap();
        let first = p
            .publish(&a, request("shared", shared.fence, None), 2)
            .unwrap();
        let lease = p.acquire(&a, &s, 2, false).unwrap();
        let mut req = request(&s, lease.fence, None);
        assert!(p.publish(&a, req.clone(), 3).is_err());
        req.revisions[0].shared_dependency = Some(first.revisions[0].revision.clone());
        let u = p.publish(&a, req.clone(), 3).unwrap();
        let mut restore = request(&s, lease.fence, Some(u.revisions[0].revision.clone()));
        restore.revisions[0].shared_dependency = req.revisions[0].shared_dependency.clone();
        restore.restores = Some(id());
        assert!(p.publish(&a, restore.clone(), 4).is_err());
        restore.restores = Some(u.id);
        assert!(p.publish(&a, restore, 4).is_ok());
    }
    #[test]
    fn name_versions_and_receipt_fingerprints_replace_name_text() {
        let (mut p, a, b) = state();
        let s = section();
        let lease = p.acquire(&a, &s, 1, false).unwrap();
        p.publish(&a, request(&s, lease.fence, None), 2).unwrap();
        let req = PublishNames {
            id: id(),
            manifest_hash: "f".repeat(64),
            parent_version: 0,
            sections: vec![s.clone()],
        };
        let before = p.heads.clone();
        let receipt = p.publish_names(&b, req.clone(), 3).unwrap();
        assert_eq!(p.heads, before);
        assert_eq!(p.publish_names(&b, req.clone(), 4).unwrap(), receipt);
        assert_eq!(p.names_version, 1);
        let mut stale = req;
        stale.id = id();
        assert!(p.publish_names(&a, stale, 4).is_err());
        let mut payload = serde_json::to_value(&receipt).unwrap();
        payload["summary"] = "no descriptions allowed".into();
        assert!(serde_json::from_value::<Update>(payload).is_err());
    }
    #[test]
    fn expiring_bootstrap_is_removed_but_receipts_and_fences_survive() {
        let (mut p, a, _) = state();
        let s = section();
        let lease = p.acquire(&a, &s, 0, false).unwrap();
        p.publish(&a, request(&s, lease.fence, None), 1).unwrap();
        assert!(!p.invite_bootstraps.is_empty());
        assert!(p.cleanup(7 * 86400));
        assert!(p.invites.is_empty() && p.invite_bootstraps.is_empty() && p.locks.is_empty());
        assert_eq!(p.history.len(), 1);
        assert_eq!(p.fences[&s], lease.fence);
        let stored = serde_json::to_value(&p).unwrap();
        for field in ["name", "storage", "section_names", "summary", "details"] {
            assert!(stored.get(field).is_none());
        }
    }
    #[test]
    fn membership_removal_revokes_credentials_and_owner_transfer_stays_explicit() {
        let (mut p, a, b) = state();
        p.tokens.insert(hash(b"guest"), b.clone());
        assert!(p.remove_member(&b, &a).is_err());
        let invite = p
            .create_invite(&b, 1, opaque::fixture("storage-bootstrap", "locator"))
            .unwrap();
        assert!(p.transfer_ownership(&b, &a).is_err());
        p.remove_member(&a, &b).unwrap();
        assert_eq!(
            p.authenticate("guest").unwrap_err().to_string(),
            REMOVED_MESSAGE
        );
        assert!(
            !p.invites.contains_key(&hash(invite.as_bytes()))
                && !p.invite_bootstraps.contains_key(&hash(invite.as_bytes()))
        );
    }
}
