//! Namespaces backed by eld's own state rather than the host: `policy`,
//! `roles` (including JIT grants) and `audit`.

use eld_api::{
    severity, status, time, ActionRequest, ActionResult, ActionSpec, Object, ParamSpec, Role, SettingSpec, SettingType,
};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

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
///
/// JIT flow (docs/PERMISSIONS.md §4): a user asks for a role for themselves
/// with `roles.request-temporary`; helpdesk (or higher) approves a pending
/// request with `roles.approve`. Helpdesk never grants on its own
/// initiative: `roles.grant-temporary` needs local-admin or the MDM.
pub struct Roles {
    pub store: Arc<Store>,
    pub max_grant_minutes: u64,
    /// Pending requests, in memory: a restart drops them and users ask again.
    pub pending: Mutex<Vec<PendingRequest>>,
}

impl Roles {
    pub fn new(store: Arc<Store>, max_grant_minutes: u64) -> Roles {
        Roles { store, max_grant_minutes, pending: Mutex::new(vec![]) }
    }
}

/// A user's own request for a temporary role, waiting for approval.
#[derive(Debug, Clone)]
pub struct PendingRequest {
    pub user: String,
    pub uid: u32,
    pub role: Role,
    pub secs: u64,
    pub ticket: String,
    pub reason: String,
    pub requested_at: u64,
}

/// How long a request waits for approval.
const REQUEST_TTL_SECS: u64 = 3600;
/// Pending requests kept at most (one per user and role).
const MAX_PENDING: usize = 256;
/// Longest ticket or reason stored.
const MAX_TEXT: usize = 256;

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
        let pending: Vec<Value> = self
            .pending
            .lock()
            .unwrap()
            .iter()
            .filter(|r| env.now < r.requested_at + REQUEST_TTL_SECS)
            .map(|r| json!({"user": r.user, "role": r.role, "for_seconds": r.secs, "ticket": r.ticket}))
            .collect();
        Ok(obj(json!({"mappings": mappings, "grants": grants, "pending": pending})))
    }

    fn settings(&self) -> Vec<SettingSpec> {
        let d = "Local groups (local:group:X or X) whose members get this role. Directory references (entra:group:X) are accepted but match nothing until identity-provider integration exists";
        vec![
            SettingSpec::new("roles.power-user", SettingType::List, d),
            SettingSpec::new("roles.helpdesk", SettingType::List, d),
            SettingSpec::new("roles.local-admin", SettingType::List, d),
        ]
    }

    fn actions(&self) -> Vec<ActionSpec> {
        vec![
            ActionSpec::new(
                "roles.request-temporary",
                Role::User,
                "Ask for a role for yourself for a limited time. Helpdesk approves it with roles.approve.",
            )
            .param(ParamSpec::new("role", "string", true, "power-user, helpdesk or local-admin"))
            .param(ParamSpec::new("for", "duration", true, "e.g. 30m"))
            .param(ParamSpec::new("ticket", "string", false, "Ticket or incident reference"))
            .param(ParamSpec::new("reason", "string", false, "Why the grant is needed")),
            ActionSpec::new(
                "roles.approve",
                Role::Helpdesk,
                "Approve another user's pending roles.request-temporary (JIT elevation). Effective for the eld API; sudo/polkit rule rendering is not built yet.",
            )
            .param(ParamSpec::new("user", "string", true, "User who asked"))
            .param(ParamSpec::new("role", "string", true, "Role they asked for")),
            ActionSpec::new(
                "roles.grant-temporary",
                Role::LocalAdmin,
                "Grant a role to another user for a limited time without a request (local-admin or MDM only). Effective for the eld API; sudo/polkit rule rendering is not built yet.",
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
        let role = Role::parse(param(req, "role")?)
            .filter(|r| assignable(*r))
            .ok_or_else(|| ActionError::BadRequest("role must be power-user, helpdesk or local-admin".into()))?;
        let by = env.caller.map(|c| c.who()).unwrap_or_default();
        let mut res = ActionResult { action: name.into(), status: status::OK.into(), ..Default::default() };
        match name {
            "roles.request-temporary" => {
                let Some(c) = env.caller.filter(|c| valid_user(&c.user)) else {
                    return Err(ActionError::Forbidden(
                        "only a named local or directory user can ask for a role".into(),
                    ));
                };
                let secs = self.duration(req)?;
                let (ticket, reason) = (text(req, "ticket")?, text(req, "reason")?);
                let p = PendingRequest {
                    user: c.user.clone(),
                    uid: c.uid,
                    role,
                    secs,
                    ticket,
                    reason,
                    requested_at: env.now,
                };
                if req.dry_run {
                    res.status = status::DRY_RUN.into();
                } else {
                    let mut q = self.pending.lock().unwrap();
                    q.retain(|r| env.now < r.requested_at + REQUEST_TTL_SECS && !(r.user == p.user && r.role == role));
                    if q.len() >= MAX_PENDING {
                        return Err(ActionError::Forbidden("too many pending requests; try again later".into()));
                    }
                    q.push(p.clone());
                    drop(q);
                    (env.emit)(
                        "roles.requested",
                        severity::INFO,
                        obj(json!({"user": p.user, "role": role, "for_seconds": secs, "ticket": p.ticket})),
                    );
                }
                res.data = obj(json!({"user": p.user, "role": role, "status": "pending"}));
            }
            "roles.approve" => {
                let user = param(req, "user")?;
                if env.caller.is_some_and(|c| c.user == user) {
                    return Err(ActionError::Forbidden("cannot approve your own request".into()));
                }
                let mut q = self.pending.lock().unwrap();
                q.retain(|r| env.now < r.requested_at + REQUEST_TTL_SECS);
                let Some(i) = q.iter().position(|r| r.user == user && r.role == role) else {
                    return Err(ActionError::BadRequest(format!("no pending request from {user} for {role}")));
                };
                if env.caller.is_some_and(|c| c.uid == q[i].uid) {
                    return Err(ActionError::Forbidden("cannot approve your own request".into()));
                }
                let p = q[i].clone();
                let g = Grant {
                    user: p.user.clone(),
                    role,
                    expires: env.now + p.secs,
                    ticket: p.ticket.clone(),
                    reason: p.reason.clone(),
                    granted_by: by,
                };
                if req.dry_run {
                    res.status = status::DRY_RUN.into();
                } else {
                    self.store.add_grant(g.clone()).map_err(ActionError::Forbidden)?;
                    q.remove(i);
                    drop(q);
                    self.granted(env, &g);
                }
                res.data = obj(json!({"user": g.user, "role": role, "expires": time::rfc3339(g.expires)}));
            }
            "roles.grant-temporary" => {
                let user = param(req, "user")?;
                if !valid_user(user) {
                    return Err(ActionError::BadRequest(format!("invalid user name {user:?}")));
                }
                if env.caller.is_some_and(|c| c.user == user) {
                    return Err(ActionError::Forbidden("cannot grant a role to yourself".into()));
                }
                let secs = self.duration(req)?;
                let g = Grant {
                    user: user.into(),
                    role,
                    expires: env.now + secs,
                    ticket: text(req, "ticket")?,
                    reason: text(req, "reason")?,
                    granted_by: by,
                };
                if req.dry_run {
                    res.status = status::DRY_RUN.into();
                } else {
                    self.store.add_grant(g.clone()).map_err(ActionError::Forbidden)?;
                    self.granted(env, &g);
                }
                res.data = obj(json!({"user": g.user, "role": role, "expires": time::rfc3339(g.expires)}));
            }
            "roles.revoke" => {
                let user = param(req, "user")?;
                if !valid_user(user) {
                    return Err(ActionError::BadRequest(format!("invalid user name {user:?}")));
                }
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

impl Roles {
    fn duration(&self, req: &ActionRequest) -> Result<u64, ActionError> {
        let dur = time::parse_duration(param(req, "for")?)
            .ok_or_else(|| ActionError::BadRequest("for must be a duration like 30m or 2h".into()))?;
        if dur.as_secs() == 0 || dur.as_secs() > self.max_grant_minutes * 60 {
            return Err(ActionError::BadRequest(format!("for must be between 1s and {}m", self.max_grant_minutes)));
        }
        Ok(dur.as_secs())
    }

    fn granted(&self, env: &Env, g: &Grant) {
        let sev = if g.role == Role::LocalAdmin { severity::WARNING } else { severity::INFO };
        (env.emit)(
            "roles.granted",
            sev,
            obj(json!({"user": g.user, "role": g.role, "expires": time::rfc3339(g.expires), "ticket": g.ticket})),
        );
    }
}

/// An optional free-text parameter, capped at [`MAX_TEXT`] bytes.
fn text(req: &ActionRequest, name: &str) -> Result<String, ActionError> {
    let v = req.params.get(name).cloned().unwrap_or_default();
    if v.len() > MAX_TEXT {
        return Err(ActionError::BadRequest(format!("{name} is longer than {MAX_TEXT} bytes")));
    }
    Ok(v)
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
