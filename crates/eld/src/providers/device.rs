//! The `device` namespace: hardware identity, firmware, TPM, enrollment
//! state, and the lock / reboot / collect-logs / wipe actions.

use eld_api::{status, ActionRequest, ActionResult, ActionSpec, Object, ParamSpec, Role, SettingSpec, SettingType};
use serde_json::{json, Value};
use std::sync::Arc;

use crate::provider::{cmd, not_implemented, run_planned, unknown, ActionError, Env, Provider};
use crate::sys::System;

/// Where the MDM agent records enrollment state (`{"state", "mdm"}`).
pub const ENROLLMENT_FILE: &str = "/var/lib/eld/enrollment.json";

const DMI: &str = "/sys/class/dmi/id/";

/// Returns the device provider.
pub fn new() -> Arc<dyn Provider> {
    Arc::new(Device)
}

/// The device provider.
pub struct Device;

/// Counts how many facts could actually be read.
struct Reader<'a> {
    sys: &'a dyn System,
    read: usize,
}

impl Reader<'_> {
    /// Trimmed, non-empty file content or "unknown".
    fn text(&mut self, path: &str) -> Value {
        match self.sys.read_trimmed(path) {
            Ok(v) if !v.is_empty() => {
                self.read += 1;
                Value::String(v)
            }
            _ => unknown(),
        }
    }

    fn hostname(&mut self) -> Value {
        // /etc/hostname may carry comments; take the first real line.
        if let Ok(t) = self.sys.read_trimmed("/etc/hostname") {
            if let Some(h) = t.lines().map(str::trim).find(|l| !l.is_empty() && !l.starts_with('#')) {
                self.read += 1;
                return Value::String(h.to_string());
            }
        }
        self.text("/proc/sys/kernel/hostname")
    }

    fn uptime(&mut self) -> Value {
        let secs = self
            .sys
            .read_trimmed("/proc/uptime")
            .ok()
            .and_then(|t| t.split_whitespace().next().and_then(|f| f.parse::<f64>().ok()))
            .filter(|v| v.is_finite() && *v >= 0.0);
        match secs {
            Some(v) => {
                self.read += 1;
                json!(v as u64)
            }
            None => unknown(),
        }
    }
}

fn boot_mode(sys: &dyn System) -> Value {
    if sys.exists("/sys/firmware/efi") {
        json!("uefi")
    } else if sys.exists("/sys/firmware") {
        json!("bios")
    } else {
        unknown()
    }
}

fn tpm(sys: &dyn System) -> Value {
    if sys.exists("/sys/class/tpm/tpm0") {
        let version = match sys.read_trimmed("/sys/class/tpm/tpm0/tpm_version_major").as_deref() {
            Ok("2") => json!("2.0"),
            Ok("1") => json!("1.2"),
            _ => unknown(),
        };
        json!({"present": true, "version": version})
    } else if sys.exists("/sys/class") {
        json!({"present": false, "version": unknown()})
    } else {
        json!({"present": unknown(), "version": unknown()})
    }
}

/// Returns `(state, mdm)`. No file means not enrolled; an unreadable or
/// malformed file is "unknown". Only these two fields are ever reported.
fn enrollment(sys: &dyn System) -> (Value, Value) {
    let b = match sys.read_file(ENROLLMENT_FILE) {
        Ok(b) => b,
        Err(_) if sys.exists(ENROLLMENT_FILE) => return (unknown(), unknown()),
        Err(_) => return (json!("not-enrolled"), json!("none")),
    };
    let doc: Value = match serde_json::from_slice(&b) {
        Ok(v) => v,
        Err(_) => return (unknown(), unknown()),
    };
    let field = |k: &str| match doc.get(k).and_then(Value::as_str) {
        Some(s) if !s.is_empty() => json!(s),
        _ => unknown(),
    };
    (field("state"), field("mdm"))
}

/// Rejects any parameter not in `allowed`.
fn only_params(req: &ActionRequest, allowed: &[&str]) -> Result<(), ActionError> {
    match req.params.keys().find(|k| !allowed.contains(&k.as_str())) {
        Some(k) => Err(ActionError::BadRequest(format!("unknown parameter {k}"))),
        None => Ok(()),
    }
}

/// Reads the last day of the journal and returns only a line count: the
/// raw export is too large (and too sensitive) for an action result.
fn collect_logs(sys: &dyn System, name: &str, dry_run: bool) -> ActionResult {
    let c = cmd(&["journalctl", "--since", "-24h", "-o", "json", "--no-pager"]);
    if dry_run {
        return run_planned(sys, name, true, vec![c]);
    }
    let args: Vec<&str> = c[1..].iter().map(String::as_str).collect();
    let mut res = ActionResult { action: name.into(), commands: vec![c.clone()], ..Default::default() };
    match sys.run_long(&c[0], &args, std::time::Duration::from_secs(1800)) {
        Ok(o) if o.success() => {
            let lines = o.stdout.lines().filter(|l| !l.trim().is_empty()).count();
            res.status = status::OK.into();
            res.message = format!("collected {lines} journal entries from the last 24h");
            res.data.insert("lines".into(), json!(lines));
        }
        Ok(o) => {
            res.status = status::FAILED.into();
            res.message = format!("journalctl exited {}: {}", o.code, o.stderr.trim());
        }
        Err(e) => {
            res.status = status::FAILED.into();
            res.message = e.to_string();
        }
    }
    res
}

impl Provider for Device {
    fn namespace(&self) -> &'static str {
        "device"
    }

    fn facts(&self, env: &Env) -> Result<Object, String> {
        let sys = env.sys;
        let mut r = Reader { sys, read: 0 };
        let mut f = Object::new();
        f.insert("hostname".into(), r.hostname());
        f.insert("vendor".into(), r.text(&format!("{DMI}sys_vendor")));
        f.insert("model".into(), r.text(&format!("{DMI}product_name")));
        // product_serial is usually root-only; unreadable means "unknown".
        f.insert("serial".into(), r.text(&format!("{DMI}product_serial")));
        let firmware = json!({
            "vendor": r.text(&format!("{DMI}bios_vendor")),
            "version": r.text(&format!("{DMI}bios_version")),
            "date": r.text(&format!("{DMI}bios_date")),
        });
        f.insert("firmware".into(), firmware);
        f.insert("boot_mode".into(), boot_mode(sys));
        f.insert("tpm".into(), tpm(sys));
        f.insert("machine_id".into(), r.text("/etc/machine-id"));
        let (state, mdm) = enrollment(sys);
        f.insert("enrollment_state".into(), state);
        f.insert("enrollment_mdm".into(), mdm);
        f.insert("uptime_seconds".into(), r.uptime());
        if r.read == 0 {
            return Err("device: no device information readable".into());
        }
        Ok(f)
    }

    fn settings(&self) -> Vec<SettingSpec> {
        vec![
            SettingSpec::new("device.name", SettingType::String, "Friendly device name shown in inventory."),
            SettingSpec::new("device.ownerGroup", SettingType::String, "Group that owns the device."),
            SettingSpec::new("device.assetTag", SettingType::String, "Organisation asset tag."),
        ]
    }

    fn actions(&self) -> Vec<ActionSpec> {
        vec![
            ActionSpec::new("device.lock", Role::Helpdesk, "Lock all graphical sessions."),
            ActionSpec::new("device.reboot", Role::LocalAdmin, "Reboot the device.").param(ParamSpec::new(
                "when",
                "string",
                false,
                "When to reboot; only \"now\" is supported.",
            )),
            ActionSpec::new(
                "device.collect-logs",
                Role::Helpdesk,
                "Read the last 24h of the journal and return a line count.",
            ),
            ActionSpec::new(
                "device.wipe",
                Role::SvcMdm,
                "Wipe the device (requires an MDM-signed confirmation token).",
            )
            .destructive()
            .not_implemented(),
        ]
    }

    fn run(&self, env: &Env, name: &str, req: &ActionRequest) -> Result<ActionResult, ActionError> {
        match name {
            "device.lock" => {
                only_params(req, &[])?;
                Ok(run_planned(env.sys, name, req.dry_run, vec![cmd(&["loginctl", "lock-sessions"])]))
            }
            "device.reboot" => {
                only_params(req, &["when"])?;
                if let Some(w) = req.params.get("when") {
                    if w != "now" {
                        return Err(ActionError::BadRequest(format!(
                            "unsupported \"when\" value {w:?}; only \"now\" is supported"
                        )));
                    }
                }
                Ok(run_planned(env.sys, name, req.dry_run, vec![cmd(&["systemctl", "reboot"])]))
            }
            "device.collect-logs" => {
                only_params(req, &[])?;
                Ok(collect_logs(env.sys, name, req.dry_run))
            }
            "device.wipe" => {
                only_params(req, &[])?;
                if req.confirm_token.as_deref().unwrap_or("").is_empty() {
                    return Err(ActionError::Forbidden("device.wipe requires a confirmation token".into()));
                }
                Ok(not_implemented(
                    name,
                    "device.wipe needs MDM-signed confirmation token verification, which is not built yet",
                ))
            }
            _ => Err(ActionError::Unknown(name.to_string())),
        }
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
        let n = N.fetch_add(1, Ordering::SeqCst);
        let d = std::env::temp_dir().join(format!("eld-test-{}-device-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn write(root: &Path, path: &str, content: &str) {
        let p = root.join(path.trim_start_matches('/'));
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, content).unwrap();
    }

    fn full_root() -> PathBuf {
        let r = root();
        write(&r, "/etc/os-release", "ID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"24.04\"\n");
        write(&r, "/etc/hostname", "# comment\nlaptop-42\n");
        write(&r, "/proc/sys/kernel/hostname", "kernel-name\n");
        write(&r, "/sys/class/dmi/id/sys_vendor", "LENOVO\n");
        write(&r, "/sys/class/dmi/id/product_name", "21CB\n");
        write(&r, "/sys/class/dmi/id/bios_vendor", "LENOVO\n");
        write(&r, "/sys/class/dmi/id/bios_version", "N3AET75W\n");
        write(&r, "/sys/class/dmi/id/bios_date", "05/12/2024\n");
        std::fs::create_dir_all(r.join("sys/firmware/efi")).unwrap();
        write(&r, "/sys/class/tpm/tpm0/tpm_version_major", "2\n");
        write(&r, "/etc/machine-id", "0123456789abcdef0123456789abcdef\n");
        write(&r, "/proc/uptime", "12345.67 54321.00\n");
        r
    }

    #[test]
    fn facts_full() {
        let r = full_root();
        write(&r, ENROLLMENT_FILE, r#"{"state":"enrolled","mdm":"intune","token":"secret"}"#);
        let host = Host::fake(&r, FakeRunner::new());
        let f = with_test_env(&host, |env| Device.facts(env)).unwrap();
        assert_eq!(f["hostname"], "laptop-42");
        assert_eq!(f["vendor"], "LENOVO");
        assert_eq!(f["model"], "21CB");
        assert_eq!(f["serial"], "unknown");
        assert_eq!(f["firmware"], json!({"vendor": "LENOVO", "version": "N3AET75W", "date": "05/12/2024"}));
        assert_eq!(f["boot_mode"], "uefi");
        assert_eq!(f["tpm"], json!({"present": true, "version": "2.0"}));
        assert_eq!(f["machine_id"], "0123456789abcdef0123456789abcdef");
        assert_eq!(f["enrollment_state"], "enrolled");
        assert_eq!(f["enrollment_mdm"], "intune");
        assert_eq!(f["uptime_seconds"], 12345);
        assert!(!serde_json::to_string(&f).unwrap().contains("secret"));
    }

    #[test]
    fn facts_degrade() {
        let r = root();
        write(&r, "/etc/os-release", "ID=rocky\nID_LIKE=\"rhel centos fedora\"\n");
        write(&r, "/proc/sys/kernel/hostname", "rhel-box\n");
        std::fs::create_dir_all(r.join("sys/firmware")).unwrap();
        std::fs::create_dir_all(r.join("sys/class")).unwrap();
        write(&r, "/proc/uptime", "garbage\n");
        let host = Host::fake(&r, FakeRunner::new());
        let f = with_test_env(&host, |env| Device.facts(env)).unwrap();
        assert_eq!(f["hostname"], "rhel-box");
        assert_eq!(f["boot_mode"], "bios");
        assert_eq!(f["tpm"], json!({"present": false, "version": "unknown"}));
        assert_eq!(f["enrollment_state"], "not-enrolled");
        assert_eq!(f["vendor"], "unknown");
        assert_eq!(f["uptime_seconds"], "unknown");
    }

    #[test]
    fn facts_malformed_enrollment_and_empty_root() {
        let r = full_root();
        write(&r, ENROLLMENT_FILE, "not json");
        let host = Host::fake(&r, FakeRunner::new());
        let f = with_test_env(&host, |env| Device.facts(env)).unwrap();
        assert_eq!(f["enrollment_state"], "unknown");

        let host = Host::fake(root(), FakeRunner::new());
        assert!(with_test_env(&host, |env| Device.facts(env)).is_err());
    }

    #[test]
    fn lock_and_reboot() {
        let host = Host::fake(root(), FakeRunner::new().on("loginctl lock-sessions", 0, ""));
        let req = ActionRequest::default();
        let res = with_test_env(&host, |env| Device.run(env, "device.lock", &req)).unwrap();
        assert_eq!(res.status, status::OK);

        let dry = ActionRequest { dry_run: true, ..Default::default() };
        let res = with_test_env(&host, |env| Device.run(env, "device.reboot", &dry)).unwrap();
        assert_eq!(res.status, status::DRY_RUN);
        assert_eq!(res.commands, vec![cmd(&["systemctl", "reboot"])]);

        let mut bad = ActionRequest { dry_run: true, ..Default::default() };
        bad.params.insert("when".into(), "later".into());
        let e = with_test_env(&host, |env| Device.run(env, "device.reboot", &bad)).unwrap_err();
        assert!(matches!(e, ActionError::BadRequest(_)));

        let mut extra = ActionRequest::default();
        extra.params.insert("x".into(), "y".into());
        let e = with_test_env(&host, |env| Device.run(env, "device.lock", &extra)).unwrap_err();
        assert!(matches!(e, ActionError::BadRequest(_)));

        let e = with_test_env(&host, |env| Device.run(env, "device.nope", &req)).unwrap_err();
        assert!(matches!(e, ActionError::Unknown(_)));
    }

    #[test]
    fn collect_logs_counts_lines_only() {
        let out = "{\"MESSAGE\":\"a\"}\n{\"MESSAGE\":\"b\"}\n{\"MESSAGE\":\"c\"}\n";
        let host = Host::fake(root(), FakeRunner::new().on("journalctl --since -24h -o json --no-pager", 0, out));
        let req = ActionRequest::default();
        let res = with_test_env(&host, |env| Device.run(env, "device.collect-logs", &req)).unwrap();
        assert_eq!(res.status, status::OK);
        assert_eq!(res.data.len(), 1);
        assert_eq!(res.data["lines"], 3);

        let host = Host::fake(root(), FakeRunner::new());
        let res = with_test_env(&host, |env| Device.run(env, "device.collect-logs", &req)).unwrap();
        assert_eq!(res.status, status::FAILED);
        assert!(res.data.is_empty());
    }

    #[test]
    fn wipe_requires_token_and_is_not_implemented() {
        let host = Host::fake(root(), FakeRunner::new());
        let req = ActionRequest::default();
        let e = with_test_env(&host, |env| Device.run(env, "device.wipe", &req)).unwrap_err();
        assert!(matches!(e, ActionError::Forbidden(_)));
        let req = ActionRequest { confirm_token: Some("tok".into()), ..Default::default() };
        let res = with_test_env(&host, |env| Device.run(env, "device.wipe", &req)).unwrap();
        assert_eq!(res.status, status::NOT_IMPLEMENTED);
        assert!(res.commands.is_empty());
    }

    #[test]
    fn spec_shape() {
        let a = Device.actions();
        let wipe = a.iter().find(|a| a.name == "device.wipe").unwrap();
        assert!(wipe.destructive && !wipe.implemented);
        assert_eq!(Device.settings().len(), 3);
    }
}
