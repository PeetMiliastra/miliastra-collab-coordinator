//! Checks which clients are active
use crate::model::{Presence, PresenceStatus};
use anyhow::{ensure, Result};
use std::{collections::HashMap, sync::Mutex};

const MAX_STATUS: usize = 4096;

/// Purpose string used when encrypting a member's status.
pub fn status_purpose(member: &str) -> String {
    format!("presence:{member}")
}

#[derive(Default)]
pub struct PresenceBoard {
    // project -> member -> (open connections, latest encrypted status)
    projects: Mutex<HashMap<String, HashMap<String, (u32, Option<String>)>>>,
}

impl PresenceBoard {
    pub fn connect(&self, project: &str, member: &str) {
        let mut projects = self.projects.lock().unwrap();
        let entry = projects
            .entry(project.into())
            .or_default()
            .entry(member.into())
            .or_insert((0, None));
        entry.0 += 1;
    }
    pub fn disconnect(&self, project: &str, member: &str) {
        let mut projects = self.projects.lock().unwrap();
        if let Some(members) = projects.get_mut(project) {
            if let Some(entry) = members.get_mut(member) {
                entry.0 = entry.0.saturating_sub(1);
                if entry.0 == 0 {
                    members.remove(member);
                }
            }
            if members.is_empty() {
                projects.remove(project);
            }
        }
    }
    /// Stores a connected member's encrypted status. Plain text is rejected.
    pub fn set_status(&self, project: &str, member: &str, status: &str) -> Result<()> {
        ensure!(status.len() <= MAX_STATUS, "Status is too large");
        crate::opaque::field(status, &status_purpose(member))?;
        let mut projects = self.projects.lock().unwrap();
        let entry = projects
            .get_mut(project)
            .and_then(|m| m.get_mut(member))
            .ok_or_else(|| anyhow::anyhow!("Not connected"))?;
        entry.1 = Some(status.into());
        Ok(())
    }
    pub fn is_connected(&self, project: &str, member: &str) -> bool {
        self.projects
            .lock()
            .unwrap()
            .get(project)
            .is_some_and(|m| m.contains_key(member))
    }
    pub fn list(&self, project: &str) -> Vec<Presence> {
        let projects = self.projects.lock().unwrap();
        let mut out: Vec<Presence> = projects
            .get(project)
            .map(|members| {
                members
                    .iter()
                    .map(|(member, (_, status))| Presence {
                        member: member.clone(),
                        status: status.clone().map(PresenceStatus::Encrypted),
                    })
                    .collect()
            })
            .unwrap_or_default();
        out.sort_by(|a, b| a.member.cmp(&b.member));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn presence_follows_connections_and_accepts_only_encrypted_status() {
        let board = PresenceBoard::default();
        board.connect("p", "a");
        board.connect("p", "a");
        board.connect("p", "b");
        assert_eq!(board.list("p").len(), 2);
        assert!(board.is_connected("p", "b") && !board.is_connected("p", "c"));
        assert!(
            board.set_status("p", "a", "in game").is_err(),
            "plaintext refused"
        );
        assert!(board.set_status("p", "stranger", "m2:{}").is_err());
        let sealed = crate::opaque::fixture(&status_purpose("a"), "activity");
        board.set_status("p", "a", &sealed).unwrap();
        let wire = serde_json::to_value(board.list("p")).unwrap();
        assert_eq!(wire[0]["status"].as_str(), Some(sealed.as_str()));
        assert!(
            wire[0]["status"].as_object().is_none(),
            "service must relay ciphertext only"
        );
        board.disconnect("p", "a");
        assert_eq!(board.list("p").len(), 2, "a still has one connection");
        board.disconnect("p", "a");
        assert_eq!(
            board
                .list("p")
                .iter()
                .map(|p| p.member.as_str())
                .collect::<Vec<_>>(),
            ["b"]
        );
        board.disconnect("p", "b");
        assert!(board.list("p").is_empty());
        assert!(board.list("other").is_empty());
    }
}
