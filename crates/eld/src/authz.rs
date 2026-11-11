//! Authentication (socket peer credentials -> [`Caller`]) and role checks.
//!
//! eld v0 checks roles itself and records the matching polkit action id in
//! the audit log. Delegating the decision to polkitd arrives with the
//! D-Bus transport.

use eld_api::{Caller, Role, Source};
use std::collections::BTreeSet;

use crate::config::{assignable, Config};
use crate::store::Store;
use crate::sys::System;

/// Rank of human roles; a higher level satisfies a lower requirement.
fn level(r: Role) -> u8 {
    match r {
        Role::User => 1,
        Role::PowerUser => 2,
        Role::Helpdesk => 3,
        Role::LocalAdmin => 4,
        Role::BreakGlass => 5,
        // For ordinary actions the MDM acts like a local admin and the EDR
        // like helpdesk (read, collect logs, lock).
        Role::SvcMdm => 4,
        Role::SvcEdr => 3,
    }
}

/// Whether any of `have` satisfies `need`.
pub fn allowed(have: &[Role], need: Role) -> bool {
    have.iter().any(|&r| match need {
        Role::SvcMdm => r == Role::SvcMdm,
        // EDR response actions: the EDR itself, the MDM, or a local admin.
        Role::SvcEdr => matches!(r, Role::SvcEdr | Role::SvcMdm | Role::LocalAdmin | Role::BreakGlass),
        _ => level(r) >= level(need),
    })
}

/// polkit action id for an API operation, recorded in every audit record.
pub fn polkit_action(op: &str, target: &str) -> String {
    match op {
        "action.run" => format!("org.enterpriselinux.{target}"),
        _ => format!("org.enterpriselinux.{}", op.replace('.', "-")),
    }
}

/// Peer credentials of a connection, captured once right after `accept()`
/// with `SO_PEERCRED`, `SO_PEERGROUPS` and `SO_PEERSEC`. The kernel records
/// these at `connect()` time, so they describe the process that connected,
/// not whatever process holds that pid later.
///
/// Authorization uses only these values. eld never reads `/proc/<pid>` to
/// decide roles: a client can connect, let the connecting process exit and
/// keep the socket open until another user's process reuses the pid.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PeerCred {
    pub uid: u32,
    pub gid: u32,
    /// For audit records only, never for authorization.
    pub pid: i32,
    /// Supplementary group ids at connect time.
    pub groups: Vec<u32>,
    /// SELinux/AppArmor label at connect time (empty without an LSM).
    pub label: String,
}

/// Turns socket peer credentials into a [`Caller`] with roles.
pub struct Resolver<'a> {
    pub sys: &'a dyn System,
    pub config: &'a Config,
    pub store: &'a Store,
    pub now: u64,
}

impl Resolver<'_> {
    /// Builds the caller for a peer from its accept-time credentials.
    pub fn resolve(&self, peer: &PeerCred) -> Caller {
        let (uid, gid) = (peer.uid, peer.gid);
        let user = self.user_name(uid);
        let mut c = Caller {
            uid,
            gid,
            pid: peer.pid,
            user,
            label: peer.label.trim_end_matches('\0').to_string(),
            roles: vec![],
            source: Source::User,
            principal: String::new(),
        };

        for sp in &self.config.service_principals {
            if sp.uid == Some(uid) || (!sp.user.is_empty() && sp.user == c.user) {
                c.principal = sp.name.clone();
                c.roles = vec![sp.role];
                c.source = if sp.role == Role::SvcMdm { Source::Mdm } else { Source::LocalAdmin };
                return c;
            }
        }

        let mut roles = BTreeSet::from([Role::User]);
        if uid == 0 {
            roles.insert(Role::LocalAdmin);
        }
        let groups = self.group_names(gid, &peer.groups);
        for g in &groups {
            if let Some(r) = self.config.group_roles.get(g) {
                roles.insert(*r);
            }
        }
        // Policy mappings: roles.<role> lists group references. Directory
        // groups are expected to surface as local group names through the
        // identity stack (authd/SSSD), so "entra:group:X" matches group X.
        for role in [Role::PowerUser, Role::Helpdesk, Role::LocalAdmin] {
            let Some(v) = self.store.get(&format!("roles.{role}")) else { continue };
            for r in v.value.as_array().into_iter().flatten().filter_map(|x| x.as_str()) {
                let name = r.rsplit(':').next().unwrap_or(r);
                if groups.iter().any(|g| g == name) {
                    roles.insert(role);
                }
            }
        }
        for g in self.store.active_grants(self.now) {
            if !c.user.is_empty() && g.user == c.user && assignable(g.role) {
                roles.insert(g.role);
            }
        }
        c.roles = roles.into_iter().collect();
        if allowed(&c.roles, Role::LocalAdmin) {
            c.source = Source::LocalAdmin;
        }
        c
    }

    fn user_name(&self, uid: u32) -> String {
        let want = uid.to_string();
        if let Ok(b) = self.sys.read_file("/etc/passwd") {
            for line in String::from_utf8_lossy(&b).lines() {
                let f: Vec<&str> = line.split(':').collect();
                if f.len() > 2 && f[2] == want {
                    return f[0].to_string();
                }
            }
        }
        // Directory users (authd/SSSD) are not in /etc/passwd.
        match self.sys.run("getent", &["passwd", &want]) {
            Ok(o) if o.success() => o.stdout.split(':').next().unwrap_or("").to_string(),
            _ => String::new(),
        }
    }

    /// Names of the caller's primary and supplementary groups, from the
    /// group ids captured at accept (never from `/proc/<pid>`).
    fn group_names(&self, gid: u32, groups: &[u32]) -> Vec<String> {
        let mut gids = BTreeSet::from([gid.to_string()]);
        gids.extend(groups.iter().map(u32::to_string));
        let table =
            self.sys.read_file("/etc/group").map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default();
        let mut out = vec![];
        for g in gids {
            let local = table.lines().find_map(|l| {
                let f: Vec<&str> = l.split(':').collect();
                (f.len() > 2 && f[2] == g).then(|| f[0].to_string())
            });
            match local {
                Some(name) => out.push(name),
                None => {
                    if let Ok(o) = self.sys.run("getent", &["group", &g]) {
                        if o.success() {
                            if let Some(name) = o.stdout.split(':').next().filter(|n| !n.is_empty()) {
                                out.push(name.to_string());
                            }
                        }
                    }
                }
            }
        }
        out.sort();
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ServicePrincipal;
    use crate::store::{Change, Grant};
    use crate::sys::{FakeRunner, Host};
    use serde_json::json;

    fn host() -> (Host, std::path::PathBuf) {
        let root =
            std::env::temp_dir().join(format!("eld-authz-{}-{:?}", std::process::id(), std::thread::current().id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("etc")).unwrap();
        std::fs::write(
            root.join("etc/passwd"),
            "root:x:0:0::/root:/bin/sh\nalice:x:1000:1000::/home/alice:/bin/sh\nmdm:x:990:990::/:/sbin/nologin\n",
        )
        .unwrap();
        std::fs::write(root.join("etc/group"), "alice:x:1000:\nit-linux-admins:x:2000:alice\nhelpdesk:x:2001:\n")
            .unwrap();
        // What /proc says about pid 42 *now*. Authorization must ignore it.
        std::fs::create_dir_all(root.join("proc/42/attr")).unwrap();
        std::fs::write(root.join("proc/42/status"), "Name:\tx\nGroups:\t1000 2000\n").unwrap();
        std::fs::write(root.join("proc/42/attr/current"), "unconfined\n").unwrap();
        (Host::fake(&root, FakeRunner::new()), root)
    }

    #[test]
    fn role_hierarchy() {
        assert!(allowed(&[Role::LocalAdmin], Role::Helpdesk));
        assert!(!allowed(&[Role::User], Role::Helpdesk));
        assert!(allowed(&[Role::SvcMdm], Role::LocalAdmin));
        assert!(!allowed(&[Role::LocalAdmin], Role::SvcMdm));
        assert!(allowed(&[Role::LocalAdmin], Role::SvcEdr));
        assert!(!allowed(&[Role::Helpdesk], Role::SvcEdr));
        assert!(!allowed(&[Role::SvcEdr], Role::LocalAdmin));
    }

    fn peer(uid: u32, gid: u32, groups: &[u32]) -> PeerCred {
        PeerCred { uid, gid, pid: 42, groups: groups.to_vec(), label: String::new() }
    }

    /// Sam H1: the pid in SO_PEERCRED may belong to another process by the
    /// time the request is read. Here /proc/42 claims membership of the admin
    /// group, but the accept-time credentials do not: no admin role.
    #[test]
    fn pid_reuse_does_not_change_roles() {
        let (h, root) = host();
        let mut cfg = Config::default();
        cfg.group_roles.insert("it-linux-admins".into(), Role::LocalAdmin);
        let store = Store::memory();
        let r = Resolver { sys: &h, config: &cfg, store: &store, now: 100 };
        let c = r.resolve(&peer(1000, 1000, &[1000]));
        assert_eq!(c.roles, vec![Role::User]);
        assert_eq!(c.pid, 42);
        assert!(c.label.is_empty(), "label must come from SO_PEERSEC, not /proc");
        // Groups captured at accept are honoured even when /proc has no entry.
        let c = r.resolve(&PeerCred { pid: 4242, ..peer(1000, 1000, &[1000, 2000]) });
        assert!(c.roles.contains(&Role::LocalAdmin));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn resolves_roles_from_groups_policy_and_grants() {
        let (h, root) = host();
        let store = Store::memory();
        let mut cfg = Config::default();
        let r = Resolver { sys: &h, config: &cfg, store: &store, now: 100 };
        let c = r.resolve(&peer(1000, 1000, &[1000, 2000]));
        assert_eq!(c.user, "alice");
        assert_eq!(c.roles, vec![Role::User]);
        assert_eq!(c.source, Source::User);

        store
            .commit(
                None,
                &[Change {
                    key: "roles.local-admin".into(),
                    value: Some(json!(["entra:group:it-linux-admins"])),
                    source: Source::Mdm,
                    set_by: "t".into(),
                }],
                None,
            )
            .unwrap();
        let c = r.resolve(&peer(1000, 1000, &[1000, 2000]));
        assert!(c.roles.contains(&Role::LocalAdmin));
        assert_eq!(c.source, Source::LocalAdmin);

        let store2 = Store::memory();
        store2
            .add_grant(Grant {
                user: "alice".into(),
                role: Role::Helpdesk,
                expires: 200,
                ticket: String::new(),
                reason: String::new(),
                granted_by: "bob".into(),
            })
            .unwrap();
        let r2 = Resolver { sys: &h, config: &cfg, store: &store2, now: 100 };
        assert!(r2.resolve(&peer(1000, 1000, &[1000, 2000])).roles.contains(&Role::Helpdesk));
        let r3 = Resolver { now: 300, ..r2 };
        assert!(!r3.resolve(&peer(1000, 1000, &[1000, 2000])).roles.contains(&Role::Helpdesk));

        cfg.service_principals.push(ServicePrincipal {
            name: "intune".into(),
            user: "mdm".into(),
            uid: None,
            role: Role::SvcMdm,
        });
        let r4 = Resolver { sys: &h, config: &cfg, store: &store, now: 100 };
        let c = r4.resolve(&peer(990, 990, &[]));
        assert_eq!(c.principal, "intune");
        assert_eq!(c.roles, vec![Role::SvcMdm]);
        assert_eq!(c.source, Source::Mdm);
        let _ = std::fs::remove_dir_all(root);
    }
}
