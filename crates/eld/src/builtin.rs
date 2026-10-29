//! Namespaces backed by eld's own state rather than the host: `policy`,
//! `roles` (including JIT grants) and `audit`.

use eld_api::{
    severity, status, time, ActionRequest, ActionResult, ActionSpec, Object, ParamSpec, Role, SettingSpec, SettingType,
};
use serde_json::{json, Value};
use std::sync::Arc;

use crate::audit::Auditor;
use crate::config::assignable;
use crate::provider::{obj, param, ActionError, Env, Provider};
use crate::store::{Grant, Store};

/// `policy`: which policy document is applied.
pub struct Policy(pub Arc<Store>);

impl Provider for Policy {
    fn namespace(&self) -> &'static str {
        "policy"
    }

    fn facts(&self, _env: &Env) -> Result<Object, String> {
        Ok(match self.0.policy() {
            Some(p) => obj(json!({
                "name": p.meta.name,
                "version": p.meta.version,
                "source": p.source,
                "applied_at": p.applied_at,
                "status": p.status,
            })),
            None => obj(json!({"status": "none"})),
        })
    }
}

/// `roles`: role mappings and just-in-time grants.
pub struct Roles {
    pub store: Arc<Store>,
    pub max_grant_minutes: u64,
}

/// Unix/directory user names: conservative charset, no leading dash.
fn valid_user(u: &str) -> bool {
    !u.is_empty()
        && u.len() <= 256
        && !u.starts_with('-')
        && u.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '@'))
}

impl Provider for Roles {
    fn namespace(&self) -> &'static str {
        "roles"
    }

    fn facts(&self, env: &Env) -> Result<Object, String> {
        let mut mappings = Object::new();
        for role in ["power-user", "helpdesk", "local-admin"] {
            mappings.insert(role.into(), (env.setting)(&format!("roles.{role}")).unwrap_or(json!([])));
        }
        let grants: Vec<Value> = self
            .store
            .active_grants(env.now)
            .into_iter()
            .map(|g| {
                json!({
                    "user": g.user,
                    "role": g.role,
                    "expires": time::rfc3339(g.expires),
                    "ticket": g.ticket,
                    "granted_by": g.granted_by,
                })
            })
            .collect();
        Ok(obj(json!({"mappings": mappings, "grants": grants})))
    }

    fn settings(&self) -> Vec<SettingSpec> {
        let d = "Directory groups (e.g. entra:group:IT-Linux-Admins) whose members get this role";
        vec![
            SettingSpec::new("roles.power-user", SettingType::List, d),
            SettingSpec::new("roles.helpdesk", SettingType::List, d),
            SettingSpec::new("roles.local-admin", SettingType::List, d),
        ]
    }

    fn actions(&self) -> Vec<ActionSpec> {
        vec![
            ActionSpec::new(
                "roles.grant-temporary",
                Role::Helpdesk,
                "Grant a role to a user for a limited time (JIT elevation). Effective for the eld API; sudo/polkit rule rendering is not built yet.",
            )
            .param(ParamSpec::new("user", "string", true, "User name"))
            .param(ParamSpec::new("role", "string", true, "power-user, helpdesk or local-admin"))
            .param(ParamSpec::new("for", "duration", true, "e.g. 30m"))
            .param(ParamSpec::new("ticket", "string", false, "Ticket or incident reference"))
            .param(ParamSpec::new("reason", "string", false, "Why the grant is needed")),
            ActionSpec::new("roles.revoke", Role::Helpdesk, "Revoke a JIT grant before it expires")
                .param(ParamSpec::new("user", "string", true, "User name"))
                .param(ParamSpec::new("role", "string", true, "Role to revoke")),
        ]
    }

    fn run(&self, env: &Env, name: &str, req: &ActionRequest) -> Result<ActionResult, ActionError> {
        let user = param(req, "user")?;
        if !valid_user(user) {
            return Err(ActionError::BadRequest(format!("invalid user name {user:?}")));
        }
        let role = Role::parse(param(req, "role")?)
            .filter(|r| assignable(*r))
            .ok_or_else(|| ActionError::BadRequest("role must be power-user, helpdesk or local-admin".into()))?;
        let by = env.caller.map(|c| c.who()).unwrap_or_default();
        let mut res = ActionResult { action: name.into(), status: status::OK.into(), ..Default::default() };
        match name {
            "roles.grant-temporary" => {
                if env.caller.is_some_and(|c| c.user == user) {
                    return Err(ActionError::Forbidden("cannot grant a role to yourself".into()));
                }
                let dur = time::parse_duration(param(req, "for")?)
                    .ok_or_else(|| ActionError::BadRequest("for must be a duration like 30m or 2h".into()))?;
                if dur.as_secs() == 0 || dur.as_secs() > self.max_grant_minutes * 60 {
                    return Err(ActionError::BadRequest(format!(
                        "for must be between 1s and {}m",
                        self.max_grant_minutes
                    )));
                }
                let g = Grant {
                    user: user.into(),
                    role,
                    expires: env.now + dur.as_secs(),
                    ticket: req.params.get("ticket").cloned().unwrap_or_default(),
                    reason: req.params.get("reason").cloned().unwrap_or_default(),
                    granted_by: by,
                };
                if req.dry_run {
                    res.status = status::DRY_RUN.into();
                } else {
                    self.store.add_grant(g.clone()).map_err(ActionError::Forbidden)?;
                    let sev = if role == Role::LocalAdmin { severity::WARNING } else { severity::INFO };
                    (env.emit)(
                        "roles.granted",
                        sev,
                        obj(
                            json!({"user": g.user, "role": role, "expires": time::rfc3339(g.expires), "ticket": g.ticket}),
                        ),
                    );
                }
                res.data = obj(json!({"user": g.user, "role": role, "expires": time::rfc3339(g.expires)}));
            }
            "roles.revoke" => {
                if req.dry_run {
                    res.status = status::DRY_RUN.into();
                } else {
                    let found = self.store.revoke_grant(user, role).map_err(ActionError::Forbidden)?;
                    if found {
                        (env.emit)("roles.revoked", severity::INFO, obj(json!({"user": user, "role": role})));
                    } else {
                        res.message = "no active grant".into();
                    }
                    res.data = obj(json!({"revoked": found}));
                }
            }
            _ => return Err(ActionError::Unknown(name.into())),
        }
        Ok(res)
    }
}

/// `audit`: forwarding target and export of recent records.
pub struct Audit(pub Arc<Auditor>);

impl Provider for Audit {
    fn namespace(&self) -> &'static str {
        "audit"
    }

    fn facts(&self, env: &Env) -> Result<Object, String> {
        Ok(obj(json!({
            "forward_target": (env.setting)("audit.forward.target").unwrap_or(json!("none")),
            "forwarding": "not-implemented",
        })))
    }

    fn settings(&self) -> Vec<SettingSpec> {
        vec![SettingSpec::new(
            "audit.forward.target",
            SettingType::String,
            "Log forwarding target (syslog/TLS or OTLP URL)",
        )]
    }

    fn actions(&self) -> Vec<ActionSpec> {
        vec![ActionSpec::new("audit.export", Role::Helpdesk, "Return the most recent audit records")
            .param(ParamSpec::new("count", "int", false, "How many records (default 100, max 1000)"))]
    }

    fn run(&self, _env: &Env, name: &str, req: &ActionRequest) -> Result<ActionResult, ActionError> {
        if name != "audit.export" {
            return Err(ActionError::Unknown(name.into()));
        }
        let n = match req.params.get("count") {
            None => 100,
            Some(s) => s
                .parse::<usize>()
                .ok()
                .filter(|n| (1..=1000).contains(n))
                .ok_or_else(|| ActionError::BadRequest("count must be 1..1000".into()))?,
        };
        Ok(ActionResult {
            action: name.into(),
            status: status::OK.into(),
            data: obj(json!({"records": self.0.recent(n)})),
            ..Default::default()
        })
    }
}
