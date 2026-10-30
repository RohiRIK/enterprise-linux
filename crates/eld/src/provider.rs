//! The plugin contract every domain (device, os, updates, encryption, ...)
//! implements, and the registry eld serves from.

use eld_api::{status, ActionRequest, ActionResult, ActionSpec, Caller, Object, SettingSpec};
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::Arc;

use crate::sys::System;

/// Value reported for a fact eld could not determine. Facts use it rather
/// than guessing, so an MDM can tell `false` from "unknown".
pub const UNKNOWN: &str = "unknown";

/// `json!("unknown")`.
pub fn unknown() -> Value {
    Value::String(UNKNOWN.into())
}

/// What eld hands a provider on every call.
pub struct Env<'a> {
    pub sys: &'a dyn System,
    /// Current desired value of a fully qualified key (from policy or a
    /// local admin). Never returns defaults.
    pub setting: &'a dyn Fn(&str) -> Option<Value>,
    /// Publishes an event on the bus and to the audit log:
    /// `(type, severity, data)`.
    pub emit: &'a dyn Fn(&str, &str, Object),
    /// Authenticated caller for actions; `None` for internal fact reads.
    pub caller: Option<&'a Caller>,
    /// Reads another namespace's facts (used by compliance).
    pub facts: &'a dyn Fn(&str) -> Result<Object, String>,
    /// Current Unix time in seconds.
    pub now: u64,
}

/// Why an action did not produce a result.
#[derive(Debug, PartialEq)]
pub enum ActionError {
    /// Invalid parameters (HTTP 400).
    BadRequest(String),
    /// Allowed by role but refused by policy (HTTP 403).
    Forbidden(String),
    /// Unknown action name (HTTP 404).
    Unknown(String),
}

/// One domain of the control API.
pub trait Provider: Send + Sync {
    /// Key prefix, e.g. `encryption`.
    fn namespace(&self) -> &'static str;

    /// Read-only state. Keys are relative to the namespace and may nest.
    /// Must never return secrets. Degrade per key (report [`UNKNOWN`]);
    /// return an error only when nothing can be read at all.
    fn facts(&self, env: &Env) -> Result<Object, String>;

    /// Desired-state keys this provider owns, fully qualified.
    fn settings(&self) -> Vec<SettingSpec> {
        vec![]
    }

    /// Imperative operations, fully qualified.
    fn actions(&self) -> Vec<ActionSpec> {
        vec![]
    }

    /// Runs one of the declared actions. Role checks are done by eld
    /// before this is called; dry runs and confirmations are handled here.
    fn run(&self, _env: &Env, name: &str, _req: &ActionRequest) -> Result<ActionResult, ActionError> {
        Err(ActionError::Unknown(name.to_string()))
    }
}

/// All providers, indexed by namespace, setting key and action name.
pub struct Registry {
    providers: BTreeMap<&'static str, Arc<dyn Provider>>,
    settings: BTreeMap<String, SettingSpec>,
    actions: BTreeMap<String, (ActionSpec, &'static str)>,
}

impl Registry {
    /// Validates and indexes providers.
    pub fn new(ps: Vec<Arc<dyn Provider>>) -> Result<Self, String> {
        let mut r = Registry { providers: BTreeMap::new(), settings: BTreeMap::new(), actions: BTreeMap::new() };
        for p in ps {
            let ns = p.namespace();
            let prefix = format!("{ns}.");
            for s in p.settings() {
                if !s.key.starts_with(&prefix) {
                    return Err(format!("setting {} outside namespace {ns}", s.key));
                }
                if r.settings.insert(s.key.clone(), s.clone()).is_some() {
                    return Err(format!("duplicate setting {}", s.key));
                }
            }
            for a in p.actions() {
                if !a.name.starts_with(&prefix) {
                    return Err(format!("action {} outside namespace {ns}", a.name));
                }
                if r.actions.insert(a.name.clone(), (a.clone(), ns)).is_some() {
                    return Err(format!("duplicate action {}", a.name));
                }
            }
            if r.providers.insert(ns, p).is_some() {
                return Err(format!("duplicate namespace {ns}"));
            }
        }
        Ok(r)
    }

    pub fn namespaces(&self) -> Vec<&'static str> {
        self.providers.keys().copied().collect()
    }

    pub fn provider(&self, ns: &str) -> Option<&Arc<dyn Provider>> {
        self.providers.get(ns)
    }

    pub fn setting(&self, key: &str) -> Option<&SettingSpec> {
        self.settings.get(key)
    }

    pub fn settings(&self) -> impl Iterator<Item = &SettingSpec> {
        self.settings.values()
    }

    pub fn action(&self, name: &str) -> Option<(&ActionSpec, &Arc<dyn Provider>)> {
        self.actions.get(name).map(|(a, ns)| (a, &self.providers[ns]))
    }

    pub fn actions(&self) -> impl Iterator<Item = &ActionSpec> {
        self.actions.values().map(|(a, _)| a)
    }
}

/// Runs `cmds` in order unless `dry_run`, stopping at the first failure,
/// and returns a result that lists them.
pub fn run_planned(sys: &dyn System, action: &str, dry_run: bool, cmds: Vec<Vec<String>>) -> ActionResult {
    let mut res = ActionResult { action: action.into(), commands: cmds.clone(), ..Default::default() };
    if dry_run {
        res.status = status::DRY_RUN.into();
        return res;
    }
    let mut outputs = Vec::new();
    for c in &cmds {
        let args: Vec<&str> = c[1..].iter().map(String::as_str).collect();
        match sys.run(&c[0], &args) {
            Ok(o) if o.success() => outputs.push(Value::String(o.stdout)),
            Ok(o) => {
                outputs.push(Value::String(o.stdout));
                res.status = status::FAILED.into();
                res.message = format!("{} exited {}: {}", c[0], o.code, o.stderr.trim());
                res.data.insert("output".into(), Value::Array(outputs));
                return res;
            }
            Err(e) => {
                res.status = status::FAILED.into();
                res.message = e.to_string();
                res.data.insert("output".into(), Value::Array(outputs));
                return res;
            }
        }
    }
    res.status = status::OK.into();
    res.data.insert("output".into(), Value::Array(outputs));
    res
}

/// Result for a declared action this build refuses to run.
pub fn not_implemented(action: &str, why: &str) -> ActionResult {
    ActionResult {
        action: action.into(),
        status: status::NOT_IMPLEMENTED.into(),
        message: why.into(),
        ..Default::default()
    }
}

/// Builds a command line from string slices.
pub fn cmd(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| s.to_string()).collect()
}

/// Returns a required action parameter or a bad-request error.
pub fn param<'r>(req: &'r ActionRequest, name: &str) -> Result<&'r str, ActionError> {
    req.params
        .get(name)
        .map(String::as_str)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| ActionError::BadRequest(format!("missing parameter {name}")))
}

/// Converts `{"a": 1}`-style literals into an [`Object`]; for tests and
/// small fact maps.
pub fn obj(v: Value) -> Object {
    match v {
        Value::Object(m) => m,
        other => {
            let mut m = Object::new();
            m.insert("value".into(), other);
            m
        }
    }
}

/// Test helper: an [`Env`] with no settings, no events and no other
/// namespaces.
#[cfg(test)]
pub fn with_test_env<R>(sys: &dyn System, f: impl FnOnce(&Env) -> R) -> R {
    let setting = |_: &str| None;
    let emit = |_: &str, _: &str, _: Object| {};
    let facts = |ns: &str| Err(format!("no namespace {ns} in test"));
    let env = Env { sys, setting: &setting, emit: &emit, caller: None, facts: &facts, now: 1_793_217_293 };
    f(&env)
}
