//! Validation of setting values, flattening of policy documents, and
//! planning of settings writes with source precedence.

use eld_api::{result, Caller, DevicePolicy, KeyResult, Object, SettingSpec, SettingType};
use serde_json::Value;
use std::collections::BTreeMap;

use crate::provider::Registry;
use crate::store::{Change, Store};

/// Upper bound for any string value.
const MAX_STRING: usize = 4096;
/// Upper bound for list length.
const MAX_LIST: usize = 1024;

fn check_string(s: &str) -> Result<(), String> {
    if s.len() > MAX_STRING {
        return Err(format!("value longer than {MAX_STRING} bytes"));
    }
    if s.chars().any(|c| c.is_control() && c != '\t' && c != '\n') {
        return Err("value contains control characters".into());
    }
    Ok(())
}

/// Validates `v` against `spec` and returns the canonical value.
pub fn normalize(spec: &SettingSpec, v: &Value) -> Result<Value, String> {
    match spec.kind {
        SettingType::String => {
            let s = v.as_str().ok_or("want a string")?;
            check_string(s)?;
            Ok(v.clone())
        }
        SettingType::Enum => {
            let s = v.as_str().ok_or_else(|| format!("want one of {:?}", spec.values))?;
            if spec.values.iter().any(|e| e == s) {
                Ok(v.clone())
            } else {
                Err(format!("{s:?} is not one of {:?}", spec.values))
            }
        }
        SettingType::Bool => v.as_bool().map(Value::Bool).ok_or_else(|| "want true or false".into()),
        SettingType::Int => {
            if let Some(i) = v.as_i64() {
                return Ok(Value::from(i));
            }
            match v.as_f64() {
                Some(f) if f.fract() == 0.0 && f.abs() < 1e15 => Ok(Value::from(f as i64)),
                _ => Err("want an integer".into()),
            }
        }
        SettingType::List => {
            let items = v.as_array().ok_or("want a list of strings")?;
            if items.len() > MAX_LIST {
                return Err(format!("list longer than {MAX_LIST} items"));
            }
            for x in items {
                check_string(x.as_str().ok_or("list items must be strings")?)?;
            }
            Ok(v.clone())
        }
    }
}

/// Flattens a nested policy `spec` into dotted keys. Objects are descended;
/// arrays and scalars are leaves.
pub fn flatten(spec: &Object) -> BTreeMap<String, Value> {
    fn walk(prefix: &str, m: &Object, out: &mut BTreeMap<String, Value>) {
        for (k, v) in m {
            let key = if prefix.is_empty() { k.clone() } else { format!("{prefix}.{k}") };
            match v {
                Value::Object(sub) => walk(&key, sub, out),
                other => {
                    out.insert(key, other.clone());
                }
            }
        }
    }
    let mut out = BTreeMap::new();
    walk("", spec, &mut out);
    out
}

/// Computes per-key results and the store changes for writing `values` as
/// `caller`. When `full` is true the values are a complete document for
/// the caller's source: keys that source set before but no longer mentions
/// are removed.
pub fn plan(
    reg: &Registry,
    store: &Store,
    caller: &Caller,
    values: &BTreeMap<String, Value>,
    full: bool,
) -> (Vec<KeyResult>, Vec<Change>) {
    let mut results = vec![];
    let mut changes = vec![];
    let reject = |key: &str, reason: String| KeyResult {
        key: key.into(),
        result: result::REJECTED.into(),
        reason,
        old: None,
        new: None,
    };
    for (key, raw) in values {
        let Some(spec) = reg.setting(key) else {
            results.push(reject(key, "unknown setting".into()));
            continue;
        };
        let nv = match normalize(spec, raw) {
            Ok(v) => v,
            Err(e) => {
                results.push(reject(key, e));
                continue;
            }
        };
        let cur = store.get(key);
        if let Some(c) = &cur {
            if c.source.rank() > caller.source.rank() {
                results.push(KeyResult {
                    old: Some(c.value.clone()),
                    new: Some(nv),
                    ..reject(
                        key,
                        format!("set by {}, which takes precedence over {}", c.source.as_str(), caller.source.as_str()),
                    )
                });
                continue;
            }
            if c.value == nv && c.source == caller.source {
                results.push(KeyResult {
                    key: key.clone(),
                    result: result::UNCHANGED.into(),
                    reason: String::new(),
                    old: Some(c.value.clone()),
                    new: None,
                });
                continue;
            }
        }
        results.push(KeyResult {
            key: key.clone(),
            result: result::APPLIED.into(),
            reason: String::new(),
            old: cur.map(|c| c.value),
            new: Some(nv.clone()),
        });
        changes.push(Change { key: key.clone(), value: Some(nv), source: caller.source, set_by: caller.who() });
    }
    if full {
        for cur in store.all() {
            if values.contains_key(&cur.key) || cur.source != caller.source {
                continue;
            }
            results.push(KeyResult {
                key: cur.key.clone(),
                result: result::REMOVED.into(),
                reason: String::new(),
                old: Some(cur.value),
                new: None,
            });
            changes.push(Change { key: cur.key, value: None, source: caller.source, set_by: caller.who() });
        }
    }
    (results, changes)
}

/// Checks the policy envelope.
pub fn validate_policy(p: &DevicePolicy) -> Result<(), String> {
    if p.api_version != "enterprise-linux/v1" {
        return Err("apiVersion must be enterprise-linux/v1".into());
    }
    if p.kind != "DevicePolicy" {
        return Err("kind must be DevicePolicy".into());
    }
    if p.metadata.name.trim().is_empty() || p.metadata.version.trim().is_empty() {
        return Err("metadata.name and metadata.version are required".into());
    }
    check_string(&p.metadata.name).and_then(|_| check_string(&p.metadata.version))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::{Env, Provider};
    use eld_api::{Role, Source};
    use serde_json::json;
    use std::sync::Arc;

    struct P;
    impl Provider for P {
        fn namespace(&self) -> &'static str {
            "updates"
        }
        fn facts(&self, _: &Env) -> Result<Object, String> {
            Ok(Object::new())
        }
        fn settings(&self) -> Vec<SettingSpec> {
            vec![
                SettingSpec::enumeration("updates.ring", &["canary", "pilot", "broad"], ""),
                SettingSpec::new("updates.maxDeferralDays", SettingType::Int, ""),
                SettingSpec::new("updates.window", SettingType::String, ""),
            ]
        }
    }

    fn caller(source: Source) -> Caller {
        Caller {
            uid: 0,
            gid: 0,
            pid: 1,
            user: "root".into(),
            label: String::new(),
            roles: vec![Role::LocalAdmin],
            source,
            principal: String::new(),
        }
    }

    fn reg() -> Registry {
        Registry::new(vec![Arc::new(P)]).unwrap()
    }

    #[test]
    fn normalizes_types() {
        let r = reg();
        let int = r.setting("updates.maxDeferralDays").unwrap();
        assert_eq!(normalize(int, &json!(7.0)).unwrap(), json!(7));
        assert!(normalize(int, &json!(7.5)).is_err());
        let ring = r.setting("updates.ring").unwrap();
        assert!(normalize(ring, &json!("nightly")).is_err());
        let s = r.setting("updates.window").unwrap();
        assert!(normalize(s, &json!("a\u{1b}b")).is_err());
    }

    #[test]
    fn flattens_policy_spec() {
        let spec = json!({"updates": {"ring": "broad", "maxDeferralDays": 7}, "apps": {"bundles": ["base"]}});
        let f = flatten(spec.as_object().unwrap());
        assert_eq!(f["updates.ring"], json!("broad"));
        assert_eq!(f["apps.bundles"], json!(["base"]));
    }

    #[test]
    fn precedence_and_removal() {
        let r = reg();
        let s = Store::memory();
        let mdm = caller(Source::Mdm);
        let admin = caller(Source::LocalAdmin);
        let vals: BTreeMap<_, _> = [("updates.ring".to_string(), json!("pilot"))].into();
        let (res, ch) = plan(&r, &s, &mdm, &vals, true);
        assert_eq!(res[0].result, result::APPLIED);
        s.commit(None, &ch, None).unwrap();

        // Local admin cannot override the MDM.
        let vals2: BTreeMap<_, _> = [("updates.ring".to_string(), json!("canary"))].into();
        let (res, ch) = plan(&r, &s, &admin, &vals2, false);
        assert_eq!(res[0].result, result::REJECTED);
        assert!(ch.is_empty());

        // Same document again is unchanged.
        let (res, ch) = plan(&r, &s, &mdm, &vals, true);
        assert_eq!(res[0].result, result::UNCHANGED);
        assert!(ch.is_empty());

        // A full document without the key removes it.
        let (res, ch) = plan(&r, &s, &mdm, &BTreeMap::new(), true);
        assert_eq!(res[0].result, result::REMOVED);
        assert_eq!(ch[0].value, None);

        // Unknown keys are rejected.
        let bad: BTreeMap<_, _> = [("updates.nope".to_string(), json!(1))].into();
        assert_eq!(plan(&r, &s, &mdm, &bad, false).0[0].result, result::REJECTED);
    }
}
