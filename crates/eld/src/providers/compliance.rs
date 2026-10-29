//! `compliance`: evaluates rules over the facts of other namespaces
//! (encryption, security, updates) and reports an overall state. Anything
//! it cannot read makes a rule "unknown", never "pass" or "fail".

use eld_api::{status, ActionRequest, ActionResult, ActionSpec, Object, Role, SettingSpec, SettingType};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::Arc;

use crate::provider::{ActionError, Env, Provider, UNKNOWN};

/// Rule outcomes.
pub mod outcome {
    pub const PASS: &str = "pass";
    pub const FAIL: &str = "fail";
    pub const UNKNOWN: &str = "unknown";
    pub const NOT_APPLICABLE: &str = "not-applicable";
}

/// Every rule id with its description, in report order.
pub const RULES: &[(&str, &str)] = &[
    ("encryption.root-encrypted", "Root filesystem is encrypted"),
    ("security.secure-boot", "Secure Boot is enabled"),
    ("security.mac-enforcing", "Mandatory access control (SELinux/AppArmor) is enforcing"),
    ("security.firewall-active", "Host firewall is active"),
    ("security.ssh-server-off", "SSH server is not running"),
    ("security.usbguard-active", "USBGuard is active when USB storage is restricted"),
    ("updates.no-security-pending", "No security updates are pending"),
];

/// Rules required when `compliance.required` is unset.
pub fn default_required() -> Vec<&'static str> {
    RULES.iter().map(|(id, _)| *id).filter(|id| *id != "updates.no-security-pending").collect()
}

/// The compliance provider.
pub struct Compliance;

/// Creates the provider.
pub fn new() -> Arc<dyn Provider> {
    Arc::new(Compliance)
}

impl Provider for Compliance {
    fn namespace(&self) -> &'static str {
        "compliance"
    }

    fn facts(&self, env: &Env) -> Result<Object, String> {
        Ok(evaluate(env))
    }

    fn settings(&self) -> Vec<SettingSpec> {
        vec![SettingSpec::new(
            "compliance.required",
            SettingType::List,
            "Rule ids that must pass for the device to be compliant",
        )
        .with_default(json!(default_required()))]
    }

    fn actions(&self) -> Vec<ActionSpec> {
        vec![ActionSpec::new("compliance.evaluate", Role::User, "Re-evaluate compliance now and publish the result")]
    }

    fn run(&self, env: &Env, name: &str, _req: &ActionRequest) -> Result<ActionResult, ActionError> {
        match name {
            // Read-only, so a dry run evaluates too.
            "compliance.evaluate" => {
                let facts = evaluate(env);
                let mut ev = Object::new();
                ev.insert("state".into(), facts["state"].clone());
                ev.insert("failing".into(), facts["failing"].clone());
                (env.emit)("compliance.evaluated", eld_api::severity::INFO, ev);
                Ok(ActionResult { action: name.into(), status: status::OK.into(), data: facts, ..Default::default() })
            }
            _ => Err(ActionError::Unknown(name.to_string())),
        }
    }
}

/// One rule outcome with a human-readable detail.
struct Outcome(&'static str, String);

impl Outcome {
    fn na(why: &str) -> Self {
        Outcome(outcome::NOT_APPLICABLE, why.into())
    }
}

/// Facts of other namespaces, read once each.
struct Sources<'e, 'a> {
    env: &'e Env<'a>,
    cache: BTreeMap<&'static str, Result<Object, String>>,
}

impl Sources<'_, '_> {
    fn ns(&mut self, ns: &'static str) -> &Result<Object, String> {
        let env = self.env;
        self.cache.entry(ns).or_insert_with(|| (env.facts)(ns))
    }

    /// Looks up a dotted fact path; `Err(detail)` when it is unavailable.
    fn get(&mut self, ns: &'static str, path: &str) -> Result<Value, String> {
        let facts = match self.ns(ns) {
            Ok(f) => f,
            Err(e) => return Err(format!("{ns} facts unavailable: {e}")),
        };
        let mut parts = path.split('.');
        let first = parts.next().unwrap_or_default();
        let mut v = facts.get(first);
        for p in parts {
            v = v.and_then(|x| x.get(p));
        }
        match v {
            None | Some(Value::Null) => Err(format!("{ns}.{path} not reported")),
            Some(Value::String(s)) if s == UNKNOWN => Err(format!("{ns}.{path} is unknown")),
            Some(x) => Ok(x.clone()),
        }
    }

    /// Pass when the fact equals `want`, fail on any other value of the
    /// same JSON type, unknown otherwise.
    fn expect(&mut self, ns: &'static str, path: &str, want: Value) -> Outcome {
        match self.get(ns, path) {
            Err(d) => Outcome(outcome::UNKNOWN, d),
            Ok(v) if v == want => Outcome(outcome::PASS, format!("{ns}.{path} = {v}")),
            Ok(v) if std::mem::discriminant(&v) == std::mem::discriminant(&want) => {
                Outcome(outcome::FAIL, format!("{ns}.{path} = {v}, expected {want}"))
            }
            Ok(v) => Outcome(outcome::UNKNOWN, format!("{ns}.{path} has unexpected value {v}")),
        }
    }
}

fn check(id: &str, src: &mut Sources, env: &Env) -> Outcome {
    match id {
        "encryption.root-encrypted" => {
            if (env.setting)("encryption.required") == Some(Value::Bool(false)) {
                return Outcome::na("encryption.required is false");
            }
            match src.get("encryption", "root.status") {
                Err(d) => Outcome(outcome::UNKNOWN, d),
                Ok(Value::String(s)) if s == "encrypted" => {
                    Outcome(outcome::PASS, "root filesystem is encrypted".into())
                }
                Ok(Value::String(s)) if s == "unencrypted" => {
                    Outcome(outcome::FAIL, "root filesystem is not encrypted".into())
                }
                Ok(v) => Outcome(outcome::UNKNOWN, format!("encryption.root.status has unexpected value {v}")),
            }
        }
        "security.secure-boot" => src.expect("security", "secure_boot", Value::Bool(true)),
        "security.mac-enforcing" => src.expect("security", "mac.mode", json!("enforcing")),
        "security.firewall-active" => src.expect("security", "firewall.active", Value::Bool(true)),
        "security.ssh-server-off" => src.expect("security", "ssh_server.active", Value::Bool(false)),
        "security.usbguard-active" => {
            let usb = (env.setting)("security.usb.storage");
            match usb.as_ref().and_then(Value::as_str) {
                Some("block") | Some("read-only") => src.expect("security", "usbguard.active", Value::Bool(true)),
                _ => Outcome::na("security.usb.storage is not block or read-only"),
            }
        }
        "updates.no-security-pending" => match src.get("updates", "security_pending") {
            Err(d) => Outcome(outcome::UNKNOWN, d),
            Ok(v) => match v.as_u64() {
                Some(0) => Outcome(outcome::PASS, "no security updates pending".into()),
                Some(n) => Outcome(outcome::FAIL, format!("{n} security updates pending")),
                None => Outcome(outcome::UNKNOWN, format!("updates.security_pending has unexpected value {v}")),
            },
        },
        _ => Outcome(outcome::UNKNOWN, "unknown rule".into()),
    }
}

/// Rule ids from `compliance.required`, or the defaults when unset.
fn required(env: &Env) -> Vec<String> {
    match (env.setting)("compliance.required") {
        Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).map(String::from).collect(),
        _ => default_required().into_iter().map(String::from).collect(),
    }
}

/// Evaluates every rule and returns the `compliance` facts: `state`,
/// `rules`, `failing` and `evaluated_at`.
pub fn evaluate(env: &Env) -> Object {
    let req = required(env);
    let mut src = Sources { env, cache: BTreeMap::new() };
    let mut rules = Vec::new();
    let mut failing = Vec::new();
    let mut any_unknown = false;
    for (id, description) in RULES {
        let Outcome(st, detail) = check(id, &mut src, env);
        let is_required = req.iter().any(|r| r == id);
        if is_required && st == outcome::FAIL {
            failing.push(Value::String((*id).into()));
        }
        if is_required && st == outcome::UNKNOWN {
            any_unknown = true;
        }
        rules.push(json!({
            "id": id,
            "description": description,
            "required": is_required,
            "status": st,
            "detail": detail,
        }));
    }
    // A required id this build does not know cannot be shown to pass.
    if req.iter().any(|r| !RULES.iter().any(|(id, _)| id == r)) {
        any_unknown = true;
    }
    let state = if !failing.is_empty() {
        "noncompliant"
    } else if any_unknown {
        UNKNOWN
    } else {
        "compliant"
    };
    let mut f = Object::new();
    f.insert("state".into(), Value::String(state.into()));
    f.insert("rules".into(), Value::Array(rules));
    f.insert("failing".into(), Value::Array(failing));
    f.insert("evaluated_at".into(), Value::String(eld_api::time::rfc3339(env.now)));
    f
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::obj;
    use crate::sys::{FakeRunner, Host};
    use std::cell::RefCell;

    fn good() -> BTreeMap<&'static str, Object> {
        let mut m = BTreeMap::new();
        m.insert("encryption", obj(json!({"root": {"status": "encrypted"}})));
        m.insert(
            "security",
            obj(json!({
                "secure_boot": true,
                "mac": {"type": "selinux", "mode": "enforcing"},
                "firewall": {"backend": "firewalld", "active": true},
                "ssh_server": {"active": false},
                "usbguard": {"installed": true, "active": true},
            })),
        );
        m.insert("updates", obj(json!({"reboot_required": false, "security_pending": 3})));
        m
    }

    /// Runs `f` with canned facts and settings; returns its result and the
    /// emitted events.
    fn with_env<R>(
        facts: BTreeMap<&'static str, Object>,
        settings: Object,
        f: impl FnOnce(&Env) -> R,
    ) -> (R, Vec<(String, Object)>) {
        let host = Host::fake(std::env::temp_dir(), FakeRunner::new());
        let events = RefCell::new(Vec::new());
        let setting = |k: &str| settings.get(k).cloned();
        let emit = |t: &str, _: &str, d: Object| events.borrow_mut().push((t.to_string(), d));
        let facts_fn = |ns: &str| facts.get(ns).cloned().ok_or_else(|| format!("no provider {ns}"));
        let env =
            Env { sys: &host, setting: &setting, emit: &emit, caller: None, facts: &facts_fn, now: 1_793_217_293 };
        let r = f(&env);
        (r, events.into_inner())
    }

    fn rule<'a>(f: &'a Object, id: &str) -> &'a Value {
        f["rules"].as_array().unwrap().iter().find(|r| r["id"] == id).unwrap()
    }

    #[test]
    fn compliant_by_default_ignores_pending_updates() {
        let (f, _) = with_env(good(), Object::new(), evaluate);
        assert_eq!(f["state"], "compliant");
        assert_eq!(f["failing"], json!([]));
        assert_eq!(rule(&f, "updates.no-security-pending")["status"], "fail");
        assert_eq!(rule(&f, "updates.no-security-pending")["required"], false);
        assert_eq!(rule(&f, "security.usbguard-active")["status"], "not-applicable");
        assert_eq!(f["evaluated_at"], eld_api::time::rfc3339(1_793_217_293));
        assert_eq!(f["rules"].as_array().unwrap().len(), RULES.len());
    }

    #[test]
    fn failing_required_rule_is_noncompliant() {
        let mut facts = good();
        facts.insert("encryption", obj(json!({"root": {"status": "unencrypted"}})));
        facts.get_mut("security").unwrap()["mac"]["mode"] = json!("permissive");
        let (f, _) = with_env(facts, Object::new(), evaluate);
        assert_eq!(f["state"], "noncompliant");
        assert_eq!(f["failing"], json!(["encryption.root-encrypted", "security.mac-enforcing"]));
    }

    #[test]
    fn unknowns_and_missing_namespaces() {
        let mut facts = good();
        facts.get_mut("security").unwrap()["secure_boot"] = json!("unknown");
        facts.remove("encryption");
        let (f, _) = with_env(facts, Object::new(), evaluate);
        assert_eq!(f["state"], "unknown");
        assert_eq!(rule(&f, "security.secure-boot")["status"], "unknown");
        assert_eq!(rule(&f, "encryption.root-encrypted")["status"], "unknown");
        assert!(rule(&f, "encryption.root-encrypted")["detail"].as_str().unwrap().contains("unavailable"));
        // missing key inside a namespace
        let mut facts = good();
        facts.insert("security", obj(json!({"secure_boot": true})));
        let (f, _) = with_env(facts, Object::new(), evaluate);
        assert_eq!(rule(&f, "security.firewall-active")["status"], "unknown");
        assert_eq!(f["state"], "unknown");
        // a failure still wins over unknown
        let mut facts = good();
        facts.insert("security", obj(json!({"secure_boot": false})));
        let (f, _) = with_env(facts, Object::new(), evaluate);
        assert_eq!(f["state"], "noncompliant");
        assert_eq!(f["failing"], json!(["security.secure-boot"]));
    }

    #[test]
    fn settings_change_applicability_and_required() {
        let mut facts = good();
        facts.insert("encryption", obj(json!({"root": {"status": "unencrypted"}})));
        facts.get_mut("security").unwrap()["usbguard"]["active"] = json!(false);
        let settings = obj(json!({
            "encryption.required": false,
            "security.usb.storage": "read-only",
            "compliance.required": ["encryption.root-encrypted", "security.usbguard-active", "updates.no-security-pending"],
        }));
        let (f, _) = with_env(facts, settings, evaluate);
        assert_eq!(rule(&f, "encryption.root-encrypted")["status"], "not-applicable");
        assert_eq!(rule(&f, "security.usbguard-active")["status"], "fail");
        assert_eq!(rule(&f, "security.secure-boot")["required"], false);
        assert_eq!(f["failing"], json!(["security.usbguard-active", "updates.no-security-pending"]));
        assert_eq!(f["state"], "noncompliant");
    }

    #[test]
    fn evaluate_action_emits_event() {
        let (res, events) = with_env(good(), Object::new(), |env| {
            Compliance.run(env, "compliance.evaluate", &ActionRequest::default())
        });
        let res = res.unwrap();
        assert_eq!(res.status, status::OK);
        assert_eq!(res.data["state"], "compliant");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].0, "compliance.evaluated");
        assert_eq!(events[0].1["failing"], json!([]));
        let (err, _) =
            with_env(good(), Object::new(), |env| Compliance.run(env, "compliance.nope", &ActionRequest::default()));
        assert!(matches!(err, Err(ActionError::Unknown(_))));
    }

    #[test]
    fn default_setting_matches_default_required() {
        let s = Compliance.settings();
        assert_eq!(s[0].default, Some(json!(default_required())));
        assert!(!default_required().contains(&"updates.no-security-pending"));
    }
}
