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

/// The local group a role-mapping reference names: `local:group:X` or a
/// bare `X`. Directory references (`entra:group:X`, `entra:user:X`,
/// `ad:group:X`, ...) return `None`: a directory name must never be matched
/// against a local group or user of the same name, so until an identity
/// provider integration exists they match nothing.
pub fn local_group_ref(r: &str) -> Option<&str> {
    match r.strip_prefix("local:group:") {
        Some(name) => Some(name).filter(|n| !n.is_empty() && !n.contains(':')),
        None => Some(r).filter(|n| !n.is_empty() && !n.contains(':')),
    }
}

/// Warnings for role mappings in `store` that can never match (directory
/// references such as `entra:group:X`).
pub fn unmatched_ref_warnings(store: &Store) -> Vec<String> {
    let mut out = vec![];
    for role in [Role::PowerUser, Role::Helpdesk, Role::LocalAdmin] {
        let Some(v) = store.get(&format!("roles.{role}")) else { continue };
        for r in v.value.as_array().into_iter().flatten().filter_map(|x| x.as_str()) {
            if local_group_ref(r).is_none() {
                out.push(format!(
                    "roles.{role}: {r} matches nothing: directory references are not resolved yet (no identity-provider integration) and never match local names"
                ));
            }
        }
    }
    out
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
            // By uid only (Sam M3): names can be supplied by the directory.
            if sp.uid == Some(uid) {
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
        // Policy mappings: roles.<role> lists group references. Only local
        // references match (see local_group_ref); entra:* and other directory
        // references match nothing until an identity-provider integration
        // can resolve them by object id.
        for role in [Role::PowerUser, Role::Helpdesk, Role::LocalAdmin] {
            let Some(v) = self.store.get(&format!("roles.{role}")) else { continue };
            for r in v.value.as_array().into_iter().flatten().filter_map(|x| x.as_str()) {
                let Some(name) = local_group_ref(r) else { continue };
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

    /// entra:group:X must never be satisfied by a local group named X.
    #[test]
    fn entra_refs_never_match_local_names() {
        let (h, root) = host();
        let cfg = Config::default();
        let store = Store::memory();
        let set = |refs: serde_json::Value| {
            store
                .commit(
                    None,
                    &[Change {
                        key: "roles.local-admin".into(),
                        value: Some(refs),
                        source: Source::Mdm,
                        set_by: "t".into(),
                    }],
                    None,
                )
                .unwrap();
        };
        let r = Resolver { sys: &h, config: &cfg, store: &store, now: 100 };
        // alice is in the local group "it-linux-admins" (gid 2000).
        let alice = peer(1000, 1000, &[1000, 2000]);
        for refs in [
            json!(["entra:group:it-linux-admins"]),
            json!(["entra:user:alice"]),
            json!(["ad:group:it-linux-admins"]),
            json!(["entra:it-linux-admins"]),
        ] {
            set(refs.clone());
            assert_eq!(r.resolve(&alice).roles, vec![Role::User], "{refs}");
            assert_eq!(unmatched_ref_warnings(&store).len(), 1);
        }
        set(json!(["local:group:it-linux-admins"]));
        assert!(r.resolve(&alice).roles.contains(&Role::LocalAdmin));
        set(json!(["it-linux-admins"]));
        assert!(r.resolve(&alice).roles.contains(&Role::LocalAdmin));
        assert!(unmatched_ref_warnings(&store).is_empty());
        assert_eq!(local_group_ref("local:group:"), None);
        let _ = std::fs::remove_dir_all(root);
    }

    /// Sam M3: a directory account named like the MDM agent's local account
    /// does not get the MDM role.
    #[test]
    fn directory_el_agent_is_not_mdm() {
        let root =
            std::env::temp_dir().join(format!("eld-authz-m3-{}-{:?}", std::process::id(), std::thread::current().id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("etc")).unwrap();
        std::fs::write(root.join("etc/passwd"), "root:x:0:0::/root:/bin/sh\n").unwrap();
        std::fs::write(root.join("etc/group"), "").unwrap();
        // el-agent exists only in the directory (SSSD/authd), uid 5000.
        let h = Host::fake(
            &root,
            FakeRunner::new().on("getent passwd 5000", 0, "el-agent:*:5000:5000::/home/el-agent:/bin/bash\n"),
        );
        let mut cfg = Config::default();
        cfg.service_principals.push(ServicePrincipal {
            name: "mdm-agent".into(),
            user: "el-agent".into(),
            uid: None,
            role: Role::SvcMdm,
        });
        let w = cfg.pin_service_principals("root:x:0:0::/root:/bin/sh\n", 999);
        assert_eq!(w.len(), 1);
        let store = Store::memory();
        let r = Resolver { sys: &h, config: &cfg, store: &store, now: 100 };
        let c = r.resolve(&peer(5000, 5000, &[]));
        assert_eq!(c.user, "el-agent");
        assert_eq!(c.roles, vec![Role::User]);
        assert!(c.principal.is_empty());
        assert_eq!(c.source, Source::User);
        let _ = std::fs::remove_dir_all(root);
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
                    value: Some(json!(["local:group:it-linux-admins"])),
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
        let passwd = std::fs::read_to_string(root.join("etc/passwd")).unwrap();
        assert!(cfg.pin_service_principals(&passwd, 999).is_empty());
        let r4 = Resolver { sys: &h, config: &cfg, store: &store, now: 100 };
        let c = r4.resolve(&peer(990, 990, &[]));
        assert_eq!(c.principal, "intune");
        assert_eq!(c.roles, vec![Role::SvcMdm]);
        assert_eq!(c.source, Source::Mdm);
        let _ = std::fs::remove_dir_all(root);
    }
}
