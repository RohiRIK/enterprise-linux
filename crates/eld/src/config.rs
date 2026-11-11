//! `/etc/eld/eld.json`. Every field has a safe default.

use eld_api::Role;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;

/// Daemon configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct Config {
    pub socket: String,
    pub state_dir: String,
    /// JSON-lines audit log. Empty disables the file sink.
    pub audit_log: String,
    /// Also send audit records to journald's native socket.
    pub journald: bool,
    /// Maps local (or identity-stack provided) group names to roles, for
    /// bootstrap before any policy arrives.
    pub group_roles: BTreeMap<String, Role>,
    /// MDM/EDR agents. Matched by uid only: a principal named by `user` is
    /// pinned at startup to the uid of a *local system* account in
    /// /etc/passwd ([`Config::pin_service_principals`]).
    pub service_principals: Vec<ServicePrincipal>,
    /// Cap on destructive actions per minute across all callers.
    pub destructive_per_minute: u32,
    /// Longest JIT grant, in minutes.
    pub max_grant_minutes: u64,
}

/// An agent identity with one scoped role.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServicePrincipal {
    /// e.g. `intune`
    pub name: String,
    /// Local system account the agent runs as (looked up in /etc/passwd,
    /// never in the directory).
    #[serde(default)]
    pub user: String,
    /// Pinned uid. Set by the operator, or filled in from `user` at startup.
    #[serde(default)]
    pub uid: Option<u32>,
    /// `svc:mdm` or `svc:edr`.
    pub role: Role,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            socket: eld_api::DEFAULT_SOCKET.into(),
            state_dir: "/var/lib/eld".into(),
            audit_log: "/var/log/eld/audit.jsonl".into(),
            journald: true,
            group_roles: BTreeMap::new(),
            service_principals: vec![],
            destructive_per_minute: 3,
            max_grant_minutes: 480,
        }
    }
}

/// Roles that a group mapping or a JIT grant may hand out. Break-glass and
/// service roles never can.
pub fn assignable(r: Role) -> bool {
    matches!(r, Role::PowerUser | Role::Helpdesk | Role::LocalAdmin)
}

impl Config {
    /// Reads `path` over the defaults. A missing file is not an error.
    pub fn load(path: &Path) -> Result<Config, String> {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Config::default()),
            Err(e) => return Err(format!("{}: {e}", path.display())),
        };
        let c: Config = serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        c.validate().map_err(|e| format!("{}: {e}", path.display()))?;
        for w in c.warnings() {
            eprintln!("eld: {}: {w}", path.display());
        }
        Ok(c)
    }

    /// Settings that load but can never take effect.
    pub fn warnings(&self) -> Vec<String> {
        self.group_roles
            .keys()
            .filter(|g| g.contains(':'))
            .map(|g| format!("groupRoles: {g} matches nothing; use the plain local group name (directory references such as entra:group:X are not resolved yet)"))
            .collect()
    }

    pub fn validate(&self) -> Result<(), String> {
        for sp in &self.service_principals {
            if !matches!(sp.role, Role::SvcMdm | Role::SvcEdr) {
                return Err(format!("service principal {}: role must be svc:mdm or svc:edr", sp.name));
            }
            if sp.user.is_empty() && sp.uid.is_none() {
                return Err(format!("service principal {}: set user or uid", sp.name));
            }
        }
        for (g, r) in &self.group_roles {
            if !assignable(*r) {
                return Err(format!("group {g}: role {r} cannot be mapped to a group"));
            }
        }
        Ok(())
    }
}

impl Config {
    /// Pins every service principal to a uid (review finding M3).
    ///
    /// Every principal must be an account listed in the local `/etc/passwd`
    /// file itself (`passwd` is that file's text, parsed directly, never
    /// NSS/getent) with a system uid (1..=`sys_uid_max`). A uid in range is
    /// not enough on its own: directory providers can map low uids too.
    /// A principal given by `user` is pinned to that entry's uid; one given
    /// by `uid` only must have an entry with that uid; if both are set they
    /// must agree. A directory account (SSSD/authd) or a regular local user
    /// never becomes a service principal.
    /// Principals that cannot be pinned are dropped; the returned messages
    /// say why.
    pub fn pin_service_principals(&mut self, passwd: &str, sys_uid_max: u32) -> Vec<String> {
        let entries = passwd_entries(passwd);
        let by_name = |n: &str| entries.iter().filter(|(name, _)| *name == n).map(|(_, u)| *u).collect::<Vec<_>>();
        let by_uid = |u: u32| entries.iter().filter(|(_, uid)| *uid == u).count();
        let mut warnings = vec![];
        self.service_principals.retain_mut(|sp| {
            let why = if sp.user.is_empty() {
                let Some(u) = sp.uid else { return false };
                match by_uid(u) {
                    0 => format!("uid {u} is not in /etc/passwd (directory accounts are refused)"),
                    1 if u == 0 || u > sys_uid_max => format!("uid {u} is not a system uid (1..={sys_uid_max})"),
                    1 => return true,
                    n => format!("uid {u} appears on {n} lines of /etc/passwd (ambiguous)"),
                }
            } else {
                match (by_name(&sp.user).as_slice(), sp.uid) {
                    ([], _) => format!("{} is not in /etc/passwd (directory accounts are refused)", sp.user),
                    ([_, _, ..], _) => format!("{} appears more than once in /etc/passwd (ambiguous)", sp.user),
                    ([u], _) if *u == 0 || *u > sys_uid_max => {
                        format!("{} has uid {u}, not a system uid (1..={sys_uid_max})", sp.user)
                    }
                    ([u], Some(pinned)) if *u != pinned => {
                        format!("{} has uid {u} in /etc/passwd but the config pins uid {pinned}", sp.user)
                    }
                    ([u], _) if by_uid(*u) > 1 => {
                        format!("uid {u} of {} is shared with another /etc/passwd entry (ambiguous)", sp.user)
                    }
                    ([u], _) => {
                        sp.uid = Some(*u);
                        return true;
                    }
                }
            };
            warnings.push(format!("service principal {} disabled: {why}", sp.name));
            false
        });
        warnings
    }
}

/// `(name, uid)` of each real entry in /etc/passwd text. Blank lines,
/// comments and NIS compat lines (`#`, `+`, `-`) are skipped, as are lines
/// without a numeric uid. Duplicates are kept so callers can refuse them.
pub fn passwd_entries(passwd: &str) -> Vec<(&str, u32)> {
    passwd
        .lines()
        .map(str::trim_end)
        .filter(|l| !l.trim().is_empty() && !l.starts_with(['#', '+', '-']))
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            if f.len() < 3 || f[0].is_empty() {
                return None;
            }
            Some((f[0], f[2].parse::<u32>().ok()?))
        })
        .collect()
}

/// `SYS_UID_MAX` from /etc/login.defs text, default 999.
pub fn sys_uid_max(login_defs: &str) -> u32 {
    login_defs
        .lines()
        .find_map(|l| {
            let mut w = l.split_whitespace();
            (w.next() == Some("SYS_UID_MAX")).then(|| w.next().and_then(|v| v.parse().ok())).flatten()
        })
        .unwrap_or(999)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unassignable_group_role() {
        let c: Config = serde_json::from_str(r#"{"groupRoles": {"wheel": "break-glass"}}"#).unwrap();
        assert!(c.validate().is_err());
        let c: Config = serde_json::from_str(r#"{"groupRoles": {"it": "local-admin"}}"#).unwrap();
        assert!(c.validate().is_ok());
    }

    #[test]
    fn warns_about_directory_group_roles() {
        let c: Config =
            serde_json::from_str(r#"{"groupRoles": {"entra:group:X": "helpdesk", "eld-admins": "local-admin"}}"#)
                .unwrap();
        let w = c.warnings();
        assert_eq!(w.len(), 1);
        assert!(w[0].contains("entra:group:X"));
    }

    #[test]
    fn principal_needs_service_role() {
        let c: Config =
            serde_json::from_str(r#"{"servicePrincipals": [{"name": "x", "user": "x", "role": "local-admin"}]}"#)
                .unwrap();
        assert!(c.validate().is_err());
    }

    /// Sam M3: only a local system account can be the MDM principal.
    #[test]
    fn pins_principals_to_local_system_uids() {
        let sp = |user: &str, uid: Option<u32>| ServicePrincipal {
            name: format!("p-{user}"),
            user: user.into(),
            uid,
            role: Role::SvcMdm,
        };
        let passwd = "root:x:0:0::/root:/bin/sh\nel-agent:x:990:990::/nonexistent:/usr/sbin/nologin\n\
                      alice:x:1000:1000::/home/alice:/bin/sh\nagent2:x:991:991::/:/sbin/nologin\n\
                      edr:x:777:777::/:/sbin/nologin\n";
        let mut c = Config {
            service_principals: vec![
                sp("el-agent", None),
                sp("dir-agent", None),
                sp("alice", None),
                sp("root", None),
                sp("agent2", Some(500)),
                sp("", Some(777)),
                // uid-only principals: a low uid that is not in the file
                // (a directory account mapped below SYS_UID_MAX) is refused,
                // as is a regular uid that is.
                sp("", Some(900)),
                sp("", Some(1000)),
            ],
            ..Config::default()
        };
        let w = c.pin_service_principals(passwd, sys_uid_max("SYS_UID_MIN 100\nSYS_UID_MAX   999\n"));
        let kept: Vec<_> = c.service_principals.iter().map(|p| (p.user.as_str(), p.uid)).collect();
        assert_eq!(kept, vec![("el-agent", Some(990)), ("", Some(777))]);
        assert_eq!(w.len(), 6, "{w:?}");
        assert!(w[0].contains("directory accounts are refused"));
        assert_eq!(sys_uid_max(""), 999);
    }

    /// L-12c: comments and blanks are skipped; duplicate names or uids make
    /// the principal ambiguous and it is disabled, never first-match.
    #[test]
    fn passwd_comments_and_duplicates() {
        let sp = |name: &str, user: &str, uid: Option<u32>| ServicePrincipal {
            name: name.into(),
            user: user.into(),
            uid,
            role: Role::SvcMdm,
        };
        let passwd = "# el-agent:x:900:900::/:/sbin/nologin\n\n   \n#900\n+el-agent::901:901:::\n-x:x:902:902:::\n\
                      dup:x:980:980::/:/sbin/nologin\ndup:x:981:981::/:/sbin/nologin\n\
                      a1:x:970:970::/:/sbin/nologin\na2:x:970:970::/:/sbin/nologin\n\
                      ok:x:960:960::/:/sbin/nologin\nbad:x:notanumber:1::/:/bin/sh\n";
        assert_eq!(passwd_entries(passwd).len(), 5);
        let mut c = Config {
            service_principals: vec![
                sp("commented", "el-agent", None),
                sp("comment-uid", "", Some(900)),
                sp("nis", "", Some(901)),
                sp("dup-name", "dup", None),
                sp("dup-uid", "a1", None),
                sp("dup-uid-only", "", Some(970)),
                sp("ok", "ok", None),
            ],
            ..Config::default()
        };
        let w = c.pin_service_principals(passwd, 999);
        let kept: Vec<_> = c.service_principals.iter().map(|p| (p.name.as_str(), p.uid)).collect();
        assert_eq!(kept, vec![("ok", Some(960))]);
        assert_eq!(w.len(), 6, "{w:?}");
        assert!(w.iter().filter(|m| m.contains("ambiguous")).count() == 3, "{w:?}");
    }

    #[test]
    fn shipped_example_config_loads() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../dist/eld.json");
        let c = Config::load(&path).unwrap();
        assert_eq!(c.service_principals[0].role, Role::SvcMdm);
    }
}
