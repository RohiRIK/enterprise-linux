//! `apps`: installed Flatpak apps and native package counts, and Flatpak
//! install/remove/repair gated by the `apps.allowed` / `apps.blocked`
//! policy. Bundle contents are owned by the catalog (docs/CURATED-APPS.md);
//! this provider only reports which bundles are selected.

use eld_api::{status, ActionRequest, ActionResult, ActionSpec, Object, ParamSpec, Role, SettingSpec, SettingType};
use serde_json::{json, Value};
use std::sync::Arc;

use crate::provider::{cmd, param, run_planned, unknown, ActionError, Env, Provider};
use crate::sys::{family, Family, System};

/// The `apps` provider.
pub struct Apps;

/// Creates the provider.
pub fn new() -> Arc<dyn Provider> {
    Arc::new(Apps)
}

/// Roles that may install allowed apps even when self-service is off.
const ELEVATED: &[Role] = &[Role::Helpdesk, Role::LocalAdmin, Role::BreakGlass, Role::SvcMdm];

/// Remote used when `apps.install` gets no `remote` parameter.
const DEFAULT_REMOTE: &str = "flathub";

/// Checks a Flatpak application ID: reverse-DNS with at least three
/// segments, the first starting with an ASCII letter, `[A-Za-z0-9_-]` only.
pub fn valid_app_id(id: &str) -> bool {
    if id.is_empty() || id.len() > 255 {
        return false;
    }
    let segs: Vec<&str> = id.split('.').collect();
    segs.len() >= 3
        && segs[0].starts_with(|c: char| c.is_ascii_alphabetic())
        && segs.iter().all(|s| !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'))
}

/// Checks a Flatpak remote name: `[a-z0-9-]`, 1 to 64 characters, not
/// starting with `-` (it would be read as an option).
fn valid_remote(r: &str) -> bool {
    !r.is_empty()
        && !r.starts_with('-')
        && r.len() <= 64
        && r.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// A list setting as strings; missing or malformed means empty.
fn list_setting(env: &Env, key: &str) -> Vec<String> {
    match (env.setting)(key) {
        Some(Value::Array(a)) => a.into_iter().filter_map(|v| v.as_str().map(String::from)).collect(),
        _ => vec![],
    }
}

/// Parses `flatpak list --app --columns=application,version,origin`.
fn parse_flatpak(out: &str) -> Vec<Value> {
    out.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let mut c = l.split('\t').map(str::trim);
            let id = c.next().unwrap_or("");
            let version = c.next().unwrap_or("");
            let origin = c.next().unwrap_or("");
            json!({"id": id, "version": version, "origin": origin})
        })
        .collect()
}

fn flatpak_facts(sys: &dyn System) -> Value {
    if !sys.installed("flatpak") {
        return json!({"installed": false, "apps": []});
    }
    let apps = match sys.run("flatpak", &["list", "--app", "--columns=application,version,origin"]) {
        Ok(o) if o.success() => Value::Array(parse_flatpak(&o.stdout)),
        _ => unknown(),
    };
    json!({"installed": true, "apps": apps})
}

fn line_count(sys: &dyn System, tool: &str, args: &[&str]) -> Value {
    if !sys.installed(tool) {
        return unknown();
    }
    match sys.run(tool, args) {
        Ok(o) if o.success() => json!(o.stdout.lines().filter(|l| !l.trim().is_empty()).count()),
        _ => unknown(),
    }
}

fn package_facts(sys: &dyn System) -> Value {
    match family(sys) {
        Family::Debian => {
            json!({"manager": "dpkg", "count": line_count(sys, "dpkg-query", &["-W", "-f", ".\n"])})
        }
        Family::Rhel | Family::Suse => {
            json!({"manager": "rpm", "count": line_count(sys, "rpm", &["-qa"])})
        }
        Family::Unknown => json!({"manager": "unknown", "count": "unknown"}),
    }
}

/// The validated `id` parameter.
fn app_id(req: &ActionRequest) -> Result<&str, ActionError> {
    let id = param(req, "id")?;
    if !valid_app_id(id) {
        return Err(ActionError::BadRequest(format!("invalid app id {id:?}")));
    }
    Ok(id)
}

/// Applies the allow/block lists and the self-service switch.
fn check_install_policy(env: &Env, id: &str) -> Result<(), ActionError> {
    let allowed = list_setting(env, "apps.allowed");
    let blocked = list_setting(env, "apps.blocked");
    if blocked.iter().any(|b| b == id) {
        return Err(ActionError::Forbidden(format!("{id} is blocked by policy")));
    }
    if !allowed.iter().any(|a| a == id) {
        return Err(ActionError::Forbidden(format!("{id} is not in apps.allowed")));
    }
    let elevated = env.caller.is_some_and(|c| c.roles.iter().any(|r| ELEVATED.contains(r)));
    let self_service = matches!((env.setting)("apps.allowSelfService"), Some(Value::Bool(true)));
    if !elevated && !self_service {
        return Err(ActionError::Forbidden("self-service is disabled by policy".into()));
    }
    Ok(())
}

fn failed(name: &str, msg: &str) -> ActionResult {
    ActionResult { action: name.into(), status: status::FAILED.into(), message: msg.into(), ..Default::default() }
}

impl Provider for Apps {
    fn namespace(&self) -> &'static str {
        "apps"
    }

    fn facts(&self, env: &Env) -> Result<Object, String> {
        let bundles = match (env.setting)("apps.bundles") {
            Some(v @ Value::Array(_)) => v,
            _ => json!([]),
        };
        let mut o = Object::new();
        o.insert("flatpak".into(), flatpak_facts(env.sys));
        o.insert("packages".into(), package_facts(env.sys));
        o.insert("bundles".into(), bundles);
        Ok(o)
    }

    fn settings(&self) -> Vec<SettingSpec> {
        vec![
            SettingSpec::new("apps.bundles", SettingType::List, "Selected app bundles (see docs/CURATED-APPS.md).")
                .with_default(json!([])),
            SettingSpec::new("apps.allowSelfService", SettingType::Bool, "Let users install allowed apps themselves.")
                .with_default(json!(false)),
            SettingSpec::new("apps.allowed", SettingType::List, "Flatpak app IDs that may be installed.")
                .with_default(json!([])),
            SettingSpec::new("apps.blocked", SettingType::List, "Flatpak app IDs that must not be installed.")
                .with_default(json!([])),
        ]
    }

    fn actions(&self) -> Vec<ActionSpec> {
        let id = |req: bool| ParamSpec::new("id", "string", req, "Flatpak application ID (reverse-DNS).");
        vec![
            ActionSpec::new("apps.install", Role::User, "Install an allowed Flatpak app system-wide.")
                .param(id(true))
                .param(ParamSpec::new("remote", "string", false, "Flatpak remote, default flathub.")),
            ActionSpec::new("apps.remove", Role::Helpdesk, "Uninstall a Flatpak app.").param(id(true)),
            ActionSpec::new("apps.repair", Role::Helpdesk, "Repair the system Flatpak installation.").param(id(false)),
        ]
    }

    fn run(&self, env: &Env, name: &str, req: &ActionRequest) -> Result<ActionResult, ActionError> {
        let cmds = match name {
            "apps.install" => {
                let id = app_id(req)?;
                let remote = req.params.get("remote").map(String::as_str).filter(|r| !r.is_empty());
                let remote = remote.unwrap_or(DEFAULT_REMOTE);
                if !valid_remote(remote) {
                    return Err(ActionError::BadRequest(format!("invalid remote {remote:?}")));
                }
                check_install_policy(env, id)?;
                cmd(&["flatpak", "install", "-y", "--noninteractive", "--system", remote, id])
            }
            "apps.remove" => {
                let id = app_id(req)?;
                cmd(&["flatpak", "uninstall", "-y", "--noninteractive", "--system", id])
            }
            "apps.repair" => {
                // Repair is installation-wide; an id, if given, is only validated.
                if req.params.get("id").is_some_and(|v| !v.is_empty()) {
                    app_id(req)?;
                }
                cmd(&["flatpak", "repair", "--system"])
            }
            _ => return Err(ActionError::Unknown(name.to_string())),
        };
        if !env.sys.installed("flatpak") {
            return Ok(failed(name, "flatpak is not installed"));
        }
        Ok(run_planned(env.sys, name, req.dry_run, vec![cmds]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::with_test_env;
    use crate::sys::{FakeRunner, Host};
    use eld_api::{Caller, Source};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static N: AtomicUsize = AtomicUsize::new(0);

    fn root(os_release: &str) -> std::path::PathBuf {
        let n = N.fetch_add(1, Ordering::SeqCst);
        let d = std::env::temp_dir().join(format!("eld-test-{}-apps-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("etc")).unwrap();
        std::fs::write(d.join("etc/os-release"), os_release).unwrap();
        d
    }

    fn caller(roles: &[Role]) -> Caller {
        Caller {
            uid: 1000,
            gid: 1000,
            pid: 1,
            user: "alice".into(),
            label: String::new(),
            roles: roles.to_vec(),
            source: Source::User,
            principal: String::new(),
        }
    }

    /// Runs `f` with the given settings and caller.
    fn with_env<R>(sys: &dyn System, settings: Value, who: Option<&Caller>, f: impl FnOnce(&Env) -> R) -> R {
        let setting = move |k: &str| settings.get(k).cloned();
        let emit = |_: &str, _: &str, _: Object| {};
        let facts = |_: &str| Err(String::new());
        let env = Env { sys, setting: &setting, emit: &emit, caller: who, facts: &facts, now: 0 };
        f(&env)
    }

    fn req(params: &[(&str, &str)], dry_run: bool) -> ActionRequest {
        ActionRequest {
            params: params.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            dry_run,
            confirm_token: None,
        }
    }

    const FIREFOX: &str = "org.mozilla.firefox";

    #[test]
    fn app_id_validation() {
        assert!(valid_app_id(FIREFOX));
        assert!(valid_app_id("com.github.tchx84.Flatseal"));
        assert!(valid_app_id("org.gnome.Text-Editor_2"));
        assert!(!valid_app_id("org.mozilla"));
        assert!(!valid_app_id("1org.mozilla.firefox"));
        assert!(!valid_app_id("org..firefox"));
        assert!(!valid_app_id("org.mozilla.fire fox"));
        assert!(!valid_app_id("org.mozilla.firefox;rm"));
        assert!(!valid_app_id("--system.a.b"));
        assert!(!valid_app_id(&format!("a.b.{}", "c".repeat(260))));
        assert!(valid_remote("my-remote2"));
        assert!(!valid_remote("Flathub"));
        assert!(!valid_remote("--user"));
    }

    #[test]
    fn debian_facts() {
        let r = root("ID=ubuntu\nID_LIKE=debian\n");
        let host = Host::fake(
            &r,
            FakeRunner::new()
                .on(
                    "flatpak list --app --columns=application,version,origin",
                    0,
                    "org.mozilla.firefox\t131.0\tflathub\norg.gnome.Calculator\t\tcurated\n",
                )
                .on("dpkg-query -W -f .\n", 0, ".\n.\n.\n"),
        );
        let f = with_env(&host, json!({"apps.bundles": ["base", "office"]}), None, |env| Apps.facts(env)).unwrap();
        assert_eq!(f["flatpak"]["installed"], true);
        assert_eq!(f["flatpak"]["apps"][0], json!({"id": FIREFOX, "version": "131.0", "origin": "flathub"}));
        assert_eq!(f["flatpak"]["apps"][1]["version"], "");
        assert_eq!(f["packages"], json!({"manager": "dpkg", "count": 3}));
        assert_eq!(f["bundles"], json!(["base", "office"]));
    }

    #[test]
    fn rhel_facts_without_flatpak() {
        let r = root("ID=rhel\nID_LIKE=fedora\n");
        let host = Host::fake(&r, FakeRunner::new().on("rpm -qa", 0, "bash-5.1\nkernel-5.14\n"));
        let f = with_test_env(&host, |env| Apps.facts(env)).unwrap();
        assert_eq!(f["flatpak"], json!({"installed": false, "apps": []}));
        assert_eq!(f["packages"], json!({"manager": "rpm", "count": 2}));
        assert_eq!(f["bundles"], json!([]));

        let host = Host::fake(&r, FakeRunner::new());
        let f = with_test_env(&host, |env| Apps.facts(env)).unwrap();
        assert_eq!(f["packages"]["count"], "unknown");
    }

    #[test]
    fn install_policy() {
        let r = root("ID=ubuntu\n");
        let host = Host::fake(&r, FakeRunner::new().with_installed(&["flatpak"]));
        let user = caller(&[Role::User]);
        let helpdesk = caller(&[Role::User, Role::Helpdesk]);
        let policy = json!({"apps.allowed": [FIREFOX], "apps.blocked": ["org.evil.App"]});
        let id = [("id", FIREFOX)];

        // Not allowed, blocked.
        let e = with_env(&host, policy.clone(), Some(&helpdesk), |env| {
            Apps.run(env, "apps.install", &req(&[("id", "org.other.App")], true))
        });
        assert!(matches!(e, Err(ActionError::Forbidden(_))));
        let e = with_env(
            &host,
            json!({"apps.allowed": ["org.evil.App"], "apps.blocked": ["org.evil.App"]}),
            Some(&helpdesk),
            |env| Apps.run(env, "apps.install", &req(&[("id", "org.evil.App")], true)),
        );
        assert!(matches!(e, Err(ActionError::Forbidden(_))));

        // A plain user needs self-service.
        let e = with_env(&host, policy.clone(), Some(&user), |env| Apps.run(env, "apps.install", &req(&id, true)));
        assert_eq!(e.unwrap_err(), ActionError::Forbidden("self-service is disabled by policy".into()));
        let mut ss = policy.clone();
        ss["apps.allowSelfService"] = json!(true);
        let res = with_env(&host, ss, Some(&user), |env| Apps.run(env, "apps.install", &req(&id, true))).unwrap();
        assert_eq!(res.status, status::DRY_RUN);

        // Helpdesk may install allowed apps; custom remote.
        let res = with_env(&host, policy.clone(), Some(&helpdesk), |env| {
            Apps.run(env, "apps.install", &req(&[("id", FIREFOX), ("remote", "curated")], true))
        })
        .unwrap();
        assert_eq!(
            res.commands,
            vec![cmd(&["flatpak", "install", "-y", "--noninteractive", "--system", "curated", FIREFOX])]
        );
        let e = with_env(&host, policy, Some(&helpdesk), |env| {
            Apps.run(env, "apps.install", &req(&[("id", FIREFOX), ("remote", "--user")], true))
        });
        assert!(matches!(e, Err(ActionError::BadRequest(_))));
    }

    #[test]
    fn remove_repair_and_errors() {
        let r = root("ID=ubuntu\n");
        let host = Host::fake(&r, FakeRunner::new().on("flatpak repair --system", 0, "done\n"));
        let res = with_test_env(&host, |env| Apps.run(env, "apps.remove", &req(&[("id", FIREFOX)], true))).unwrap();
        assert_eq!(res.commands, vec![cmd(&["flatpak", "uninstall", "-y", "--noninteractive", "--system", FIREFOX])]);
        let res = with_test_env(&host, |env| Apps.run(env, "apps.repair", &req(&[], false))).unwrap();
        assert_eq!(res.status, status::OK);
        let e = with_test_env(&host, |env| Apps.run(env, "apps.remove", &req(&[], true)));
        assert!(matches!(e, Err(ActionError::BadRequest(_))));
        let e = with_test_env(&host, |env| Apps.run(env, "apps.repair", &req(&[("id", "bad")], true)));
        assert!(matches!(e, Err(ActionError::BadRequest(_))));
        let e = with_test_env(&host, |env| Apps.run(env, "apps.nope", &req(&[], true)));
        assert!(matches!(e, Err(ActionError::Unknown(_))));

        let host = Host::fake(&r, FakeRunner::new());
        let res = with_test_env(&host, |env| Apps.run(env, "apps.remove", &req(&[("id", FIREFOX)], true))).unwrap();
        assert_eq!(res.status, status::FAILED);
        assert_eq!(res.message, "flatpak is not installed");
    }

    #[test]
    fn specs_are_namespaced() {
        assert!(crate::provider::Registry::new(vec![new()]).is_ok());
    }
}
