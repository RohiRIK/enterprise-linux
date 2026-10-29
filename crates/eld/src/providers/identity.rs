//! `identity`: which login provider is active (authd, SSSD, Himmelblau),
//! the joined realm and domains, and whether an offline credential cache
//! exists. Settings are stored and reported only.

use eld_api::{status, ActionRequest, ActionResult, ActionSpec, Object, Role, SettingSpec, SettingType};
use serde_json::{json, Value};
use std::sync::Arc;

use crate::provider::{self, cmd, unknown, ActionError, Env, Provider};
use crate::sys::System;

/// Login providers in detection order: (systemd unit, reported name).
const PROVIDERS: &[(&str, &str)] = &[("authd", "authd"), ("sssd", "sssd"), ("himmelblaud", "himmelblau")];

const SSSD_CONF: &str = "/etc/sssd/sssd.conf";
const SSSD_DB: &str = "/var/lib/sss/db";

/// The identity provider.
pub struct Identity;

/// Creates the provider.
pub fn new() -> Arc<dyn Provider> {
    Arc::new(Identity)
}

impl Provider for Identity {
    fn namespace(&self) -> &'static str {
        "identity"
    }

    fn facts(&self, env: &Env) -> Result<Object, String> {
        let mut f = Object::new();
        f.insert("provider".into(), active_provider(env.sys));
        f.insert("joined".into(), json!({ "realm": realm(env.sys), "domains": sssd_domains(env.sys) }));
        f.insert("sssd_cache_present".into(), cache_present(env.sys));
        Ok(f)
    }

    fn settings(&self) -> Vec<SettingSpec> {
        vec![
            SettingSpec::new("identity.allowedLoginGroups", SettingType::List, "Directory groups allowed to log in"),
            SettingSpec::new("identity.deniedLoginGroups", SettingType::List, "Directory groups denied login"),
            SettingSpec::new(
                "identity.offlineGraceDays",
                SettingType::Int,
                "Days cached credentials allow login without reaching the IdP",
            )
            .with_default(json!(7)),
        ]
    }

    fn actions(&self) -> Vec<ActionSpec> {
        vec![ActionSpec::new(
            "identity.resync",
            Role::Helpdesk,
            "Invalidate cached directory users and groups so they are fetched again",
        )]
    }

    fn run(&self, env: &Env, name: &str, req: &ActionRequest) -> Result<ActionResult, ActionError> {
        match name {
            "identity.resync" => {
                if unit_active(env.sys, "sssd") == Some(true) {
                    Ok(provider::run_planned(env.sys, name, req.dry_run, vec![cmd(&["sss_cache", "-E"])]))
                } else {
                    Ok(ActionResult {
                        action: name.into(),
                        status: status::FAILED.into(),
                        message: "resync is only implemented for SSSD in this build".into(),
                        ..Default::default()
                    })
                }
            }
            _ => Err(ActionError::Unknown(name.to_string())),
        }
    }
}

/// `systemctl is-active <unit>`: `Some(true|false)`, or `None` if it could
/// not be asked.
fn unit_active(sys: &dyn System, unit: &str) -> Option<bool> {
    if !sys.installed("systemctl") {
        return None;
    }
    sys.run("systemctl", &["is-active", unit]).ok().map(|o| o.success())
}

/// First active login provider, "none", or "unknown".
fn active_provider(sys: &dyn System) -> Value {
    if !sys.installed("systemctl") {
        return unknown();
    }
    let mut undetermined = false;
    for (unit, name) in PROVIDERS {
        match unit_active(sys, unit) {
            Some(true) => return Value::String((*name).into()),
            Some(false) => {}
            None => undetermined = true,
        }
    }
    if undetermined {
        unknown()
    } else {
        Value::String("none".into())
    }
}

/// Joined realm from `realm list`: name, `null` when not joined, or
/// "unknown" when realmd is not installed or fails.
fn realm(sys: &dyn System) -> Value {
    if !sys.installed("realm") {
        return unknown();
    }
    match sys.run("realm", &["list", "--name-only"]) {
        Ok(o) if o.success() => o
            .stdout
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty())
            .map(|l| Value::String(l.into()))
            .unwrap_or(Value::Null),
        _ => unknown(),
    }
}

/// `domains =` from the `[sssd]` section; `[]` without an sssd.conf and
/// "unknown" when it exists but is unreadable (it is root-only).
fn sssd_domains(sys: &dyn System) -> Value {
    if !sys.exists(SSSD_CONF) {
        return json!([]);
    }
    let Ok(b) = sys.read_file(SSSD_CONF) else {
        return unknown();
    };
    let text = String::from_utf8_lossy(&b);
    let mut section = String::new();
    for line in text.lines().map(str::trim) {
        if let Some(s) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            section = s.trim().to_string();
            continue;
        }
        if section != "sssd" {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            if k.trim() == "domains" {
                let list: Vec<Value> =
                    v.split(',').map(str::trim).filter(|d| !d.is_empty()).map(|d| Value::String(d.into())).collect();
                return Value::Array(list);
            }
        }
    }
    json!([])
}

/// True when the SSSD cache directory holds files.
fn cache_present(sys: &dyn System) -> Value {
    match sys.read_dir(SSSD_DB) {
        Ok(entries) => Value::Bool(!entries.is_empty()),
        Err(_) if sys.exists(SSSD_DB) => unknown(),
        Err(_) => Value::Bool(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::with_test_env;
    use crate::sys::{FakeRunner, Host};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static N: AtomicUsize = AtomicUsize::new(0);

    fn root() -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "eld-test-{}-id-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn write(root: &Path, p: &str, s: &str) {
        let p = root.join(p.trim_start_matches('/'));
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, s).unwrap();
    }

    fn systemctl(authd: bool, sssd: bool, himmelblau: bool) -> FakeRunner {
        let st = |a: bool| {
            if a {
                (0, "active\n")
            } else {
                (3, "inactive\n")
            }
        };
        let (a, b, c) = (st(authd), st(sssd), st(himmelblau));
        FakeRunner::new().on("systemctl is-active authd", a.0, a.1).on("systemctl is-active sssd", b.0, b.1).on(
            "systemctl is-active himmelblaud",
            c.0,
            c.1,
        )
    }

    #[test]
    fn rhel_sssd_joined() {
        let r = root();
        write(&r, "/etc/os-release", "ID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\n");
        write(&r, SSSD_CONF, "[sssd]\nservices = nss, pam\ndomains = corp.example.com, lab.example.com\n\n[domain/corp.example.com]\nid_provider = ad\n");
        write(&r, "/var/lib/sss/db/cache_corp.example.com.ldb", "");
        let fr = systemctl(false, true, false).on("realm list --name-only", 0, "corp.example.com\n");
        let host = Host::fake(&r, fr);
        let f = with_test_env(&host, |env| Identity.facts(env)).unwrap();
        assert_eq!(f["provider"], "sssd");
        assert_eq!(f["joined"]["realm"], "corp.example.com");
        assert_eq!(f["joined"]["domains"], json!(["corp.example.com", "lab.example.com"]));
        assert_eq!(f["sssd_cache_present"], true);
    }

    #[test]
    fn debian_authd_not_joined() {
        let r = root();
        write(&r, "/etc/os-release", "ID=ubuntu\nID_LIKE=debian\n");
        let fr = systemctl(true, false, false).on("realm list --name-only", 0, "");
        let host = Host::fake(&r, fr);
        let f = with_test_env(&host, |env| Identity.facts(env)).unwrap();
        assert_eq!(f["provider"], "authd");
        assert_eq!(f["joined"]["realm"], Value::Null);
        assert_eq!(f["joined"]["domains"], json!([]));
        assert_eq!(f["sssd_cache_present"], false);
    }

    #[test]
    fn himmelblau_and_none() {
        let host = Host::fake(root(), systemctl(false, false, true));
        let f = with_test_env(&host, |env| Identity.facts(env)).unwrap();
        assert_eq!(f["provider"], "himmelblau");
        let host = Host::fake(root(), systemctl(false, false, false));
        let f = with_test_env(&host, |env| Identity.facts(env)).unwrap();
        assert_eq!(f["provider"], "none");
    }

    #[test]
    fn missing_tools_are_unknown() {
        let host = Host::fake(root(), FakeRunner::new());
        let f = with_test_env(&host, |env| Identity.facts(env)).unwrap();
        assert_eq!(f["provider"], "unknown");
        assert_eq!(f["joined"]["realm"], "unknown");
    }

    #[cfg(unix)]
    #[test]
    fn unreadable_sssd_conf_is_unknown() {
        use std::os::unix::fs::PermissionsExt;
        let r = root();
        write(&r, SSSD_CONF, "[sssd]\ndomains = x\n");
        let p = r.join("etc/sssd/sssd.conf");
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o000)).unwrap();
        let host = Host::fake(&r, FakeRunner::new());
        let readable = std::fs::read(&p).is_ok(); // root ignores modes
        let f = with_test_env(&host, |env| Identity.facts(env)).unwrap();
        if !readable {
            assert_eq!(f["joined"]["domains"], "unknown");
        }
    }

    #[test]
    fn resync_sssd_dry_run_and_run() {
        let host = Host::fake(root(), systemctl(false, true, false).on("sss_cache -E", 0, ""));
        let dry = ActionRequest { dry_run: true, ..Default::default() };
        let res = with_test_env(&host, |env| Identity.run(env, "identity.resync", &dry)).unwrap();
        assert_eq!(res.status, status::DRY_RUN);
        assert_eq!(res.commands, vec![cmd(&["sss_cache", "-E"])]);
        let res = with_test_env(&host, |env| Identity.run(env, "identity.resync", &ActionRequest::default())).unwrap();
        assert_eq!(res.status, status::OK);
    }

    #[test]
    fn resync_without_sssd_fails() {
        let host = Host::fake(root(), systemctl(true, false, false));
        let res = with_test_env(&host, |env| Identity.run(env, "identity.resync", &ActionRequest::default())).unwrap();
        assert_eq!(res.status, status::FAILED);
        assert!(res.message.contains("only implemented for SSSD"));
        let err =
            with_test_env(&host, |env| Identity.run(env, "identity.nope", &ActionRequest::default())).unwrap_err();
        assert!(matches!(err, ActionError::Unknown(_)));
    }
}
