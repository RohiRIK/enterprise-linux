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
    /// MDM/EDR agents, identified by the Unix account they run as.
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
    /// Unix account the agent runs as.
    #[serde(default)]
    pub user: String,
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
        Ok(c)
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
    fn principal_needs_service_role() {
        let c: Config =
            serde_json::from_str(r#"{"servicePrincipals": [{"name": "x", "user": "x", "role": "local-admin"}]}"#)
                .unwrap();
        assert!(c.validate().is_err());
    }

    #[test]
    fn shipped_example_config_loads() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../dist/eld.json");
        let c = Config::load(&path).unwrap();
        assert_eq!(c.service_principals[0].role, Role::SvcMdm);
    }
}
