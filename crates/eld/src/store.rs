//! eld's persisted desired state: settings with their source, the last
//! applied policy, and JIT grants. The store is the only writer of
//! `<stateDir>/state.json` and writes atomically.

use eld_api::{time, PolicyMetadata, Role, SettingValue, Source};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::sync::Mutex;

/// A just-in-time role grant (`docs/PERMISSIONS.md` §4).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Grant {
    pub user: String,
    pub role: Role,
    /// Unix seconds.
    pub expires: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ticket: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,
    pub granted_by: String,
}

/// The last policy document applied.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppliedPolicy {
    #[serde(flatten)]
    pub meta: PolicyMetadata,
    pub source: Source,
    pub applied_at: String,
    /// `applied` or `partial` (some keys rejected).
    pub status: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct State {
    revision: u64,
    settings: BTreeMap<String, SettingValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    policy: Option<AppliedPolicy>,
    #[serde(default)]
    grants: Vec<Grant>,
}

/// One mutation inside a commit. `value: None` deletes the key.
#[derive(Debug, Clone, PartialEq)]
pub struct Change {
    pub key: String,
    pub value: Option<Value>,
    pub source: Source,
    pub set_by: String,
}

/// Errors from [`Store::commit`].
#[derive(Debug)]
pub enum CommitError {
    /// `If-Match` did not match the current ETag.
    Stale {
        current: String,
    },
    Io(String),
}

/// Persisted desired state.
pub struct Store {
    path: Option<PathBuf>,
    st: Mutex<State>,
}

fn etag(rev: u64) -> String {
    format!("\"r{rev}\"")
}

impl Store {
    /// In-memory store (tests).
    pub fn memory() -> Store {
        Store { path: None, st: Mutex::new(State::default()) }
    }

    /// Loads or initialises `dir/state.json`.
    pub fn open(dir: &str) -> Result<Store, String> {
        std::fs::create_dir_all(dir).map_err(|e| format!("{dir}: {e}"))?;
        let path = PathBuf::from(dir).join("state.json");
        let st = match std::fs::read_to_string(&path) {
            Ok(t) => serde_json::from_str(&t).map_err(|e| format!("{}: {e}", path.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => State::default(),
            Err(e) => return Err(format!("{}: {e}", path.display())),
        };
        Ok(Store { path: Some(path), st: Mutex::new(st) })
    }

    /// Opaque revision tag for optimistic concurrency.
    pub fn etag(&self) -> String {
        etag(self.st.lock().unwrap().revision)
    }

    pub fn get(&self, key: &str) -> Option<SettingValue> {
        self.st.lock().unwrap().settings.get(key).cloned()
    }

    /// All stored values, sorted by key.
    pub fn all(&self) -> Vec<SettingValue> {
        self.st.lock().unwrap().settings.values().cloned().collect()
    }

    pub fn policy(&self) -> Option<AppliedPolicy> {
        self.st.lock().unwrap().policy.clone()
    }

    /// Unexpired grants.
    pub fn active_grants(&self, now: u64) -> Vec<Grant> {
        self.st.lock().unwrap().grants.iter().filter(|g| g.expires > now).cloned().collect()
    }

    /// Applies changes (and optionally records a policy) atomically. Returns
    /// the new ETag.
    pub fn commit(
        &self,
        if_match: Option<&str>,
        changes: &[Change],
        policy: Option<AppliedPolicy>,
    ) -> Result<String, CommitError> {
        let mut st = self.st.lock().unwrap();
        if let Some(m) = if_match {
            if m != "*" && m != etag(st.revision) {
                return Err(CommitError::Stale { current: etag(st.revision) });
            }
        }
        if changes.is_empty() && policy.is_none() {
            return Ok(etag(st.revision));
        }
        let mut next = st.clone();
        let now = time::now_rfc3339();
        for c in changes {
            match &c.value {
                None => {
                    next.settings.remove(&c.key);
                }
                Some(v) => {
                    next.settings.insert(
                        c.key.clone(),
                        SettingValue {
                            key: c.key.clone(),
                            value: v.clone(),
                            source: c.source,
                            set_by: c.set_by.clone(),
                            updated: now.clone(),
                        },
                    );
                }
            }
        }
        if policy.is_some() {
            next.policy = policy;
        }
        next.revision += 1;
        self.save(&next).map_err(CommitError::Io)?;
        *st = next;
        Ok(etag(st.revision))
    }

    /// Stores a grant, replacing one for the same user and role.
    pub fn add_grant(&self, g: Grant) -> Result<(), String> {
        self.mutate_grants(|gs| {
            gs.retain(|x| !(x.user == g.user && x.role == g.role));
            gs.push(g);
            true
        })
    }

    /// Removes a grant; reports whether one existed.
    pub fn revoke_grant(&self, user: &str, role: Role) -> Result<bool, String> {
        let mut found = false;
        self.mutate_grants(|gs| {
            let before = gs.len();
            gs.retain(|x| !(x.user == user && x.role == role));
            found = gs.len() != before;
            found
        })?;
        Ok(found)
    }

    /// Drops expired grants and returns them.
    pub fn expire_grants(&self, now: u64) -> Result<Vec<Grant>, String> {
        let mut expired = vec![];
        self.mutate_grants(|gs| {
            let (keep, gone): (Vec<_>, Vec<_>) = gs.drain(..).partition(|g| g.expires > now);
            *gs = keep;
            expired = gone;
            !expired.is_empty()
        })?;
        Ok(expired)
    }

    fn mutate_grants(&self, f: impl FnOnce(&mut Vec<Grant>) -> bool) -> Result<(), String> {
        let mut st = self.st.lock().unwrap();
        let mut next = st.clone();
        if !f(&mut next.grants) {
            return Ok(());
        }
        next.revision += 1;
        self.save(&next)?;
        *st = next;
        Ok(())
    }

    fn save(&self, st: &State) -> Result<(), String> {
        let Some(path) = &self.path else { return Ok(()) };
        let tmp = path.with_extension("json.tmp");
        let body = serde_json::to_vec_pretty(st).map_err(|e| e.to_string())?;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| format!("{}: {e}", tmp.display()))?;
        f.write_all(&body).and_then(|_| f.sync_all()).map_err(|e| format!("{}: {e}", tmp.display()))?;
        std::fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn change(key: &str, v: Value) -> Change {
        Change { key: key.into(), value: Some(v), source: Source::Mdm, set_by: "t".into() }
    }

    #[test]
    fn commit_and_etag() {
        let s = Store::memory();
        let e0 = s.etag();
        let e1 = s.commit(Some(&e0), &[change("updates.ring", json!("pilot"))], None).unwrap();
        assert_ne!(e0, e1);
        assert!(matches!(s.commit(Some(&e0), &[], None), Err(CommitError::Stale { .. })));
        assert_eq!(s.get("updates.ring").unwrap().value, json!("pilot"));
    }

    #[test]
    fn persists_atomically() {
        let dir = std::env::temp_dir().join(format!("eld-store-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let d = dir.to_str().unwrap();
        let s = Store::open(d).unwrap();
        s.commit(None, &[change("device.name", json!("lt-1"))], None).unwrap();
        s.add_grant(Grant {
            user: "alice".into(),
            role: Role::LocalAdmin,
            expires: 100,
            ticket: String::new(),
            reason: String::new(),
            granted_by: "bob".into(),
        })
        .unwrap();
        let s2 = Store::open(d).unwrap();
        assert_eq!(s2.get("device.name").unwrap().value, json!("lt-1"));
        assert_eq!(s2.active_grants(50).len(), 1);
        assert_eq!(s2.expire_grants(200).unwrap().len(), 1);
        assert!(s2.active_grants(50).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
