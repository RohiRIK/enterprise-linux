//! `desktop`: logind sessions and the installed desktop environment.
//! Lockdown settings are stored and reported only; user notifications are
//! declared but not delivered yet.

use eld_api::{ActionRequest, ActionResult, ActionSpec, Object, ParamSpec, Role, SettingSpec, SettingType};
use serde_json::{json, Value};
use std::sync::Arc;

use crate::provider::{self, param, unknown, ActionError, Env, Provider};
use crate::sys::System;

/// Maximum notification title length, in characters.
pub const MAX_TITLE: usize = 200;
/// Maximum notification body length, in characters.
pub const MAX_BODY: usize = 1000;

/// The desktop provider.
pub struct Desktop;

/// Creates the provider.
pub fn new() -> Arc<dyn Provider> {
    Arc::new(Desktop)
}

impl Provider for Desktop {
    fn namespace(&self) -> &'static str {
        "desktop"
    }

    fn facts(&self, env: &Env) -> Result<Object, String> {
        let mut f = Object::new();
        f.insert("sessions".into(), sessions(env.sys));
        f.insert("environment".into(), Value::String(environment(env.sys).into()));
        Ok(f)
    }

    fn settings(&self) -> Vec<SettingSpec> {
        vec![
            SettingSpec::new("desktop.lock", SettingType::List, "Desktop keys locked against user changes"),
            SettingSpec::new("desktop.wallpaper", SettingType::String, "Default wallpaper path"),
            SettingSpec::new("desktop.favorites", SettingType::List, "Default dock favorites (desktop file ids)"),
            SettingSpec::new("desktop.extensionsAllowed", SettingType::List, "Shell extensions users may enable"),
        ]
    }

    fn actions(&self) -> Vec<ActionSpec> {
        vec![ActionSpec::new("desktop.send-notification", Role::Helpdesk, "Show a notification to logged-in users")
            .param(ParamSpec::new("title", "string", true, "Title, at most 200 characters"))
            .param(ParamSpec::new("body", "string", true, "Body, at most 1000 characters"))
            .not_implemented()]
    }

    fn run(&self, _env: &Env, name: &str, req: &ActionRequest) -> Result<ActionResult, ActionError> {
        match name {
            "desktop.send-notification" => {
                check_text("title", param(req, "title")?, MAX_TITLE)?;
                check_text("body", param(req, "body")?, MAX_BODY)?;
                Ok(provider::not_implemented(name, "per-session delivery through the IT desktop app is not built yet"))
            }
            _ => Err(ActionError::Unknown(name.to_string())),
        }
    }
}

/// Rejects over-long text or text with control characters.
fn check_text(name: &str, v: &str, max: usize) -> Result<(), ActionError> {
    if v.chars().count() > max {
        return Err(ActionError::BadRequest(format!("{name} longer than {max} characters")));
    }
    if v.chars().any(char::is_control) {
        return Err(ActionError::BadRequest(format!("{name} contains control characters")));
    }
    Ok(())
}

/// A logind session id: short and ASCII alphanumeric.
fn valid_session_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 32 && id.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// Sessions from `loginctl`, or "unknown".
fn sessions(sys: &dyn System) -> Value {
    if !sys.installed("loginctl") {
        return unknown();
    }
    let out = match sys.run("loginctl", &["list-sessions", "--no-legend"]) {
        Ok(o) if o.success() => o.stdout,
        _ => return unknown(),
    };
    let list: Vec<Value> = out
        .lines()
        .filter_map(|l| {
            let cols: Vec<&str> = l.split_whitespace().collect();
            let id = *cols.first()?;
            if !valid_session_id(id) {
                return None;
            }
            let (ty, class) = session_props(sys, id);
            Some(json!({
                "id": id,
                "user": cols.get(2).map(|u| Value::String((*u).into())).unwrap_or_else(unknown),
                "type": ty,
                "class": class,
            }))
        })
        .collect();
    Value::Array(list)
}

/// `Type` and `Class` of one session, "unknown" where unreadable.
fn session_props(sys: &dyn System, id: &str) -> (Value, Value) {
    let (mut ty, mut class) = (unknown(), unknown());
    if let Ok(o) = sys.run("loginctl", &["show-session", id, "-p", "Type", "-p", "Class"]) {
        if o.success() {
            for line in o.stdout.lines() {
                match line.trim().split_once('=') {
                    Some(("Type", v)) if !v.is_empty() => ty = Value::String(v.into()),
                    Some(("Class", v)) if !v.is_empty() => class = Value::String(v.into()),
                    _ => {}
                }
            }
        }
    }
    (ty, class)
}

/// Installed desktop environment.
fn environment(sys: &dyn System) -> &'static str {
    if sys.exists("/usr/bin/gnome-shell") {
        "gnome"
    } else if sys.exists("/usr/bin/plasmashell") {
        "kde"
    } else {
        "unknown"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::with_test_env;
    use crate::sys::{FakeRunner, Host};
    use eld_api::status;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static N: AtomicUsize = AtomicUsize::new(0);

    fn root() -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "eld-test-{}-desk-{}",
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

    const LIST: &str = "loginctl list-sessions --no-legend";

    #[test]
    fn debian_gnome_sessions() {
        let r = root();
        write(&r, "/etc/os-release", "ID=ubuntu\nID_LIKE=debian\n");
        write(&r, "/usr/bin/gnome-shell", "");
        let fr = FakeRunner::new()
            .on(LIST, 0, "     2 1000 alice seat0 tty2 active no -\n c3 0 root - pts/0 active no -\n../x 0 evil\n")
            .on("loginctl show-session 2 -p Type -p Class", 0, "Type=wayland\nClass=user\n")
            .on("loginctl show-session c3 -p Type -p Class", 0, "Type=tty\nClass=user\n");
        let host = Host::fake(&r, fr);
        let f = with_test_env(&host, |env| Desktop.facts(env)).unwrap();
        assert_eq!(f["environment"], "gnome");
        assert_eq!(
            f["sessions"],
            json!([
                {"id": "2", "user": "alice", "type": "wayland", "class": "user"},
                {"id": "c3", "user": "root", "type": "tty", "class": "user"},
            ])
        );
    }

    #[test]
    fn rhel_kde_x11_greeter() {
        let r = root();
        write(&r, "/etc/os-release", "ID=\"rhel\"\nID_LIKE=\"fedora\"\n");
        write(&r, "/usr/bin/plasmashell", "");
        let fr = FakeRunner::new().on(LIST, 0, "5 975 gdm seat0 tty1\n").on(
            "loginctl show-session 5 -p Type -p Class",
            0,
            "Type=x11\nClass=greeter\n",
        );
        let f = with_test_env(&Host::fake(&r, fr), |env| Desktop.facts(env)).unwrap();
        assert_eq!(f["environment"], "kde");
        assert_eq!(f["sessions"][0]["type"], "x11");
        assert_eq!(f["sessions"][0]["class"], "greeter");
    }

    #[test]
    fn missing_loginctl_is_unknown() {
        let f = with_test_env(&Host::fake(root(), FakeRunner::new()), |env| Desktop.facts(env)).unwrap();
        assert_eq!(f["sessions"], "unknown");
        assert_eq!(f["environment"], "unknown");
        // show-session failing degrades only that session's properties
        let fr = FakeRunner::new().on(LIST, 0, "7 1000 bob\n");
        let f = with_test_env(&Host::fake(root(), fr), |env| Desktop.facts(env)).unwrap();
        assert_eq!(f["sessions"][0]["type"], "unknown");
    }

    fn notify(title: &str, body: &str) -> Result<ActionResult, ActionError> {
        let mut req = ActionRequest { dry_run: true, ..Default::default() };
        req.params.insert("title".into(), title.into());
        req.params.insert("body".into(), body.into());
        with_test_env(&Host::fake(root(), FakeRunner::new()), |env| Desktop.run(env, "desktop.send-notification", &req))
    }

    #[test]
    fn notification_validation() {
        assert_eq!(notify("Reboot", "Please reboot today.").unwrap().status, status::NOT_IMPLEMENTED);
        assert!(matches!(notify("", "x"), Err(ActionError::BadRequest(_))));
        assert!(matches!(notify("x", ""), Err(ActionError::BadRequest(_))));
        assert!(matches!(notify(&"t".repeat(201), "x"), Err(ActionError::BadRequest(_))));
        assert!(notify(&"t".repeat(200), &"b".repeat(1000)).is_ok());
        assert!(matches!(notify("x", &"b".repeat(1001)), Err(ActionError::BadRequest(_))));
        assert!(matches!(notify("a\x1b[31m", "x"), Err(ActionError::BadRequest(_))));
        assert!(matches!(notify("x", "line\nbreak"), Err(ActionError::BadRequest(_))));
        let err = with_test_env(&Host::fake(root(), FakeRunner::new()), |env| {
            Desktop.run(env, "desktop.nope", &ActionRequest::default())
        });
        assert!(matches!(err, Err(ActionError::Unknown(_))));
    }
}
