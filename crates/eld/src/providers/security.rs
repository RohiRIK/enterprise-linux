//! The `security` namespace: Secure Boot, mandatory access control,
//! firewall, SSH server, USBGuard, application allowlisting and auditd
//! state, the baseline / USB / firewall settings, and the SCAP compliance
//! scan. Fact keys here are read by the compliance provider; keep them
//! stable.

use eld_api::{status, ActionRequest, ActionResult, ActionSpec, Object, Role, SettingSpec, SettingType};
use serde_json::{json, Value};
use std::sync::Arc;

use crate::provider::{cmd, unknown, ActionError, Env, Provider};
use crate::sys::{Family, OsRelease, System};

/// EFI variable holding the Secure Boot state (4 attribute bytes, 1 value).
pub const SECURE_BOOT_VAR: &str = "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c";

/// Where the compliance scan writes its ARF report.
pub const SCAP_DIR: &str = "/var/lib/eld/scap";
const ARF: &str = "/var/lib/eld/scap/arf.xml";

/// Returns the security provider.
pub fn new() -> Arc<dyn Provider> {
    Arc::new(Security)
}

/// The security provider.
pub struct Security;

/// `systemctl is-active <unit>`: `None` when systemctl is missing or could
/// not run.
fn is_active(sys: &dyn System, unit: &str) -> Option<bool> {
    if !sys.installed("systemctl") {
        return None;
    }
    sys.run("systemctl", &["is-active", unit]).ok().map(|o| o.success())
}

fn tri(v: Option<bool>) -> Value {
    v.map(Value::Bool).unwrap_or_else(unknown)
}

/// True when a systemd unit file for `unit` is installed.
fn unit_file(sys: &dyn System, unit: &str) -> bool {
    ["/etc/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"]
        .iter()
        .any(|d| sys.exists(&format!("{d}/{unit}.service")))
}

fn secure_boot(sys: &dyn System) -> Value {
    if let Ok(b) = sys.read_file(SECURE_BOOT_VAR) {
        match b.get(4) {
            Some(1) => return json!(true),
            Some(0) => return json!(false),
            _ => {}
        }
    }
    if sys.installed("mokutil") {
        if let Ok(o) = sys.run("mokutil", &["--sb-state"]) {
            let text = format!("{}\n{}", o.stdout, o.stderr);
            if text.contains("SecureBoot enabled") {
                return json!(true);
            }
            if text.contains("SecureBoot disabled") {
                return json!(false);
            }
        }
    }
    // Legacy BIOS boot cannot have Secure Boot.
    if sys.exists("/sys/firmware") && !sys.exists("/sys/firmware/efi") {
        return json!(false);
    }
    unknown()
}

/// Mode from `aa-status --json`: enforcing when any profile enforces,
/// permissive when profiles exist but only complain.
fn apparmor_mode(sys: &dyn System) -> Value {
    if !sys.installed("aa-status") {
        return unknown();
    }
    let out = match sys.run("aa-status", &["--json"]) {
        Ok(o) if o.success() => o.stdout,
        _ => return unknown(),
    };
    let doc: Value = match serde_json::from_str(&out) {
        Ok(v) => v,
        Err(_) => return unknown(),
    };
    let Some(profiles) = doc.get("profiles").and_then(Value::as_object) else {
        return unknown();
    };
    let count = |mode: &str| profiles.values().filter(|v| v.as_str() == Some(mode)).count();
    if count("enforce") > 0 {
        json!("enforcing")
    } else if count("complain") > 0 {
        json!("permissive")
    } else {
        unknown()
    }
}

fn mac(sys: &dyn System) -> Value {
    if let Ok(v) = sys.read_trimmed("/sys/fs/selinux/enforce") {
        let mode = match v.as_str() {
            "1" => json!("enforcing"),
            "0" => json!("permissive"),
            _ => unknown(),
        };
        return json!({"type": "selinux", "mode": mode});
    }
    if sys.read_trimmed("/sys/module/apparmor/parameters/enabled").is_ok_and(|v| v == "Y") {
        return json!({"type": "apparmor", "mode": apparmor_mode(sys)});
    }
    if !sys.exists("/sys/fs") && !sys.exists("/sys/module") {
        return json!({"type": unknown(), "mode": unknown()});
    }
    json!({"type": "none", "mode": "disabled"})
}

/// ufw.service is "active" on Ubuntu even when ufw is disabled, so also
/// require `ENABLED=yes` when the config is readable.
fn ufw_enabled(sys: &dyn System) -> bool {
    match sys.read_file("/etc/ufw/ufw.conf") {
        Ok(b) => OsRelease::parse(&String::from_utf8_lossy(&b)).get("ENABLED") == "yes",
        Err(_) => true,
    }
}

fn firewall(sys: &dyn System) -> Value {
    if !sys.installed("systemctl") {
        return json!({"backend": unknown(), "active": unknown()});
    }
    let backends: [(&str, &[&str]); 3] =
        [("firewalld", &["firewall-cmd", "firewalld"]), ("ufw", &["ufw"]), ("nftables", &["nft"])];
    let mut failed = false;
    for (unit, _) in backends {
        match is_active(sys, unit) {
            Some(true) if unit != "ufw" || ufw_enabled(sys) => return json!({"backend": unit, "active": true}),
            Some(_) => {}
            None => failed = true,
        }
    }
    // Nothing active: report the first installed backend as inactive.
    for (unit, tools) in backends {
        if tools.iter().any(|t| sys.installed(t)) || unit_file(sys, unit) {
            let active = if failed { unknown() } else { json!(false) };
            return json!({"backend": unit, "active": active});
        }
    }
    if failed {
        return json!({"backend": unknown(), "active": unknown()});
    }
    json!({"backend": "none", "active": false})
}

fn ssh_server(sys: &dyn System) -> Value {
    // Ubuntu 24.04+ starts sshd through ssh.socket.
    let mut seen = Some(false);
    for unit in ["ssh", "sshd", "ssh.socket"] {
        match is_active(sys, unit) {
            Some(true) => return json!({"active": true}),
            Some(false) => {}
            None => seen = None,
        }
    }
    json!({"active": tri(seen)})
}

fn usbguard(sys: &dyn System) -> Value {
    let installed = sys.installed("usbguard") || unit_file(sys, "usbguard");
    let active = if installed { tri(is_active(sys, "usbguard")) } else { json!(false) };
    json!({"installed": installed, "active": active})
}

fn allowlisting(sys: &dyn System) -> Value {
    if sys.installed("fapolicyd") || unit_file(sys, "fapolicyd") {
        json!({"backend": "fapolicyd", "active": tri(is_active(sys, "fapolicyd"))})
    } else {
        json!({"backend": "none", "active": false})
    }
}

/// Maps the `security.baseline` setting to an SSG XCCDF profile id.
fn scap_profile(baseline: Option<&str>) -> Result<&'static str, ActionError> {
    match baseline {
        Some("cis-l1-workstation") => Ok("xccdf_org.ssgproject.content_profile_cis_level1_workstation"),
        Some("cis-l2-workstation") => Ok("xccdf_org.ssgproject.content_profile_cis_level2_workstation"),
        Some("stig") => Ok("xccdf_org.ssgproject.content_profile_stig"),
        None | Some("none") => Err(ActionError::BadRequest("set security.baseline first".into())),
        Some(other) => Err(ActionError::BadRequest(format!("unsupported security.baseline {other:?}"))),
    }
}

/// SSG datastream for this substrate, e.g. `ssg-ubuntu2404-ds.xml` or
/// `ssg-rhel9-ds.xml`.
fn scap_datastream(o: &OsRelease) -> Result<String, String> {
    let version = o.get("VERSION_ID");
    if version.is_empty() || !version.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return Err(format!("cannot map VERSION_ID {version:?} to a SCAP datastream"));
    }
    let name = match o.family() {
        Family::Debian if o.get("ID") == "ubuntu" => format!("ubuntu{}", version.replace('.', "")),
        Family::Rhel => {
            let major = version.split('.').next().unwrap_or("");
            if major.is_empty() {
                return Err(format!("cannot map VERSION_ID {version:?} to a SCAP datastream"));
            }
            format!("rhel{major}")
        }
        f => return Err(format!("no SCAP datastream mapping for {} family", f.as_str())),
    };
    Ok(format!("/usr/share/xml/scap/ssg/content/ssg-{name}-ds.xml"))
}

fn failed(name: &str, message: String, commands: Vec<Vec<String>>) -> ActionResult {
    ActionResult { action: name.into(), status: status::FAILED.into(), message, commands, ..Default::default() }
}

fn compliance_scan(env: &Env, name: &str, req: &ActionRequest) -> Result<ActionResult, ActionError> {
    if let Some(k) = req.params.keys().next() {
        return Err(ActionError::BadRequest(format!("unknown parameter {k}")));
    }
    let sys = env.sys;
    let baseline = (env.setting)("security.baseline");
    let profile = scap_profile(baseline.as_ref().and_then(Value::as_str))?;
    if !sys.installed("oscap") {
        return Ok(failed(name, "oscap is not installed; install OpenSCAP to run compliance scans".into(), vec![]));
    }
    let datastream = match OsRelease::read(sys) {
        Ok(o) => scap_datastream(&o),
        Err(e) => Err(format!("cannot read os-release: {e}")),
    };
    let datastream = match datastream {
        Ok(d) => d,
        Err(m) => return Ok(failed(name, m, vec![])),
    };
    let cmds = vec![
        cmd(&["mkdir", "-p", "-m", "0700", SCAP_DIR]),
        cmd(&["oscap", "xccdf", "eval", "--profile", profile, "--results-arf", ARF, &datastream]),
    ];
    if !sys.exists(&datastream) {
        return Ok(failed(name, format!("SCAP content {datastream} is missing; install scap-security-guide"), cmds));
    }
    if req.dry_run {
        return Ok(ActionResult {
            action: name.into(),
            status: status::DRY_RUN.into(),
            commands: cmds,
            ..Default::default()
        });
    }
    for (i, c) in cmds.iter().enumerate() {
        let args: Vec<&str> = c[1..].iter().map(String::as_str).collect();
        let o = match sys.run_long(&c[0], &args, std::time::Duration::from_secs(1800)) {
            Ok(o) => o,
            Err(e) => return Ok(failed(name, e.to_string(), cmds.clone())),
        };
        let last = i == cmds.len() - 1;
        // oscap exits 2 when some rules failed: the scan itself completed.
        let result = match o.code {
            0 => "pass",
            2 if last => "failures",
            code => {
                let m = format!("{} exited {code}: {}", c[0], o.stderr.trim());
                return Ok(failed(name, m, cmds.clone()));
            }
        };
        if last {
            let mut res = ActionResult {
                action: name.into(),
                status: status::OK.into(),
                message: format!("compliance scan completed ({result})"),
                commands: cmds.clone(),
                ..Default::default()
            };
            res.data.insert("result".into(), json!(result));
            res.data.insert("profile".into(), json!(profile));
            res.data.insert("arf".into(), json!(ARF));
            return Ok(res);
        }
    }
    unreachable!("cmds is non-empty")
}

impl Provider for Security {
    fn namespace(&self) -> &'static str {
        "security"
    }

    fn facts(&self, env: &Env) -> Result<Object, String> {
        let sys = env.sys;
        let mut f = Object::new();
        f.insert("secure_boot".into(), secure_boot(sys));
        f.insert("mac".into(), mac(sys));
        f.insert("firewall".into(), firewall(sys));
        f.insert("ssh_server".into(), ssh_server(sys));
        f.insert("usbguard".into(), usbguard(sys));
        f.insert("allowlisting".into(), allowlisting(sys));
        f.insert("auditd".into(), json!({"active": tri(is_active(sys, "auditd"))}));
        Ok(f)
    }

    fn settings(&self) -> Vec<SettingSpec> {
        vec![
            SettingSpec::enumeration(
                "security.baseline",
                &["cis-l1-workstation", "cis-l2-workstation", "stig", "none"],
                "Hardening baseline the device is scanned and evaluated against.",
            ),
            SettingSpec::enumeration(
                "security.usb.storage",
                &["allow", "block", "read-only"],
                "Policy for USB mass-storage devices.",
            ),
            SettingSpec::new(
                "security.usb.allow",
                SettingType::List,
                "USB devices allowed regardless of policy, e.g. \"vendor:046d\".",
            ),
            SettingSpec::enumeration(
                "security.firewall.defaultInbound",
                &["deny", "allow"],
                "Default action for inbound connections.",
            )
            .with_default(json!("deny")),
        ]
    }

    fn actions(&self) -> Vec<ActionSpec> {
        vec![ActionSpec::new(
            "security.run-compliance-scan",
            Role::Helpdesk,
            "Run an OpenSCAP scan against the profile selected by security.baseline.",
        )]
    }

    fn run(&self, env: &Env, name: &str, req: &ActionRequest) -> Result<ActionResult, ActionError> {
        match name {
            "security.run-compliance-scan" => compliance_scan(env, name, req),
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
        let d = std::env::temp_dir().join(format!("eld-test-{}-security-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn write(root: &Path, path: &str, content: &[u8]) {
        let p = root.join(path.trim_start_matches('/'));
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, content).unwrap();
    }

    fn facts(host: &Host) -> Object {
        with_test_env(host, |env| Security.facts(env)).unwrap()
    }

    /// Runs the scan with `security.baseline` set to `baseline`.
    fn scan(host: &Host, baseline: Option<&str>, dry_run: bool) -> Result<ActionResult, ActionError> {
        let b = baseline.map(|s| json!(s));
        let setting = move |k: &str| {
            if k == "security.baseline" {
                b.clone()
            } else {
                None
            }
        };
        let emit = |_: &str, _: &str, _: Object| {};
        let facts = |ns: &str| Err(format!("no namespace {ns}"));
        let env = Env { sys: host, setting: &setting, emit: &emit, caller: None, facts: &facts, now: 0 };
        let req = ActionRequest { dry_run, ..Default::default() };
        Security.run(&env, "security.run-compliance-scan", &req)
    }

    #[test]
    fn ubuntu_apparmor_ufw() {
        let r = root();
        write(&r, "/etc/os-release", b"ID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"24.04\"\n");
        write(&r, SECURE_BOOT_VAR, &[6, 0, 0, 0, 1]);
        write(&r, "/sys/module/apparmor/parameters/enabled", b"Y\n");
        write(&r, "/etc/ufw/ufw.conf", b"ENABLED=yes\nLOGLEVEL=low\n");
        let aa = r#"{"version":"1","profiles":{"/usr/bin/man":"enforce","foo":"complain"},"processes":{}}"#;
        let runner = FakeRunner::new()
            .on("aa-status --json", 0, aa)
            .on("systemctl is-active firewalld", 4, "inactive\n")
            .on("systemctl is-active ufw", 0, "active\n")
            .on("systemctl is-active ssh", 3, "inactive\n")
            .on("systemctl is-active sshd", 4, "inactive\n")
            .on("systemctl is-active ssh.socket", 0, "active\n")
            .on("systemctl is-active auditd", 3, "inactive\n")
            .with_installed(&["aa-status", "systemctl", "ufw"]);
        let f = facts(&Host::fake(&r, runner));
        assert_eq!(f["secure_boot"], true);
        assert_eq!(f["mac"], json!({"type": "apparmor", "mode": "enforcing"}));
        assert_eq!(f["firewall"], json!({"backend": "ufw", "active": true}));
        assert_eq!(f["ssh_server"], json!({"active": true}));
        assert_eq!(f["usbguard"], json!({"installed": false, "active": false}));
        assert_eq!(f["allowlisting"], json!({"backend": "none", "active": false}));
        assert_eq!(f["auditd"], json!({"active": false}));
    }

    #[test]
    fn ufw_service_active_but_disabled() {
        let r = root();
        write(&r, "/etc/ufw/ufw.conf", b"ENABLED=no\n");
        let runner = FakeRunner::new()
            .on("systemctl is-active firewalld", 4, "")
            .on("systemctl is-active ufw", 0, "active\n")
            .on("systemctl is-active nftables", 3, "")
            .with_installed(&["systemctl", "ufw"]);
        let f = facts(&Host::fake(&r, runner));
        assert_eq!(f["firewall"], json!({"backend": "ufw", "active": false}));
    }

    #[test]
    fn rhel_selinux_firewalld_fapolicyd() {
        let r = root();
        write(&r, "/etc/os-release", b"ID=\"rhel\"\nID_LIKE=\"fedora\"\nVERSION_ID=\"9.4\"\n");
        write(&r, SECURE_BOOT_VAR, &[6, 0, 0, 0, 0]);
        write(&r, "/sys/fs/selinux/enforce", b"1");
        write(&r, "/usr/lib/systemd/system/usbguard.service", b"");
        let runner = FakeRunner::new()
            .on("systemctl is-active firewalld", 0, "active\n")
            .on("systemctl is-active ssh", 4, "")
            .on("systemctl is-active sshd", 0, "active\n")
            .on("systemctl is-active usbguard", 0, "active\n")
            .on("systemctl is-active fapolicyd", 0, "active\n")
            .on("systemctl is-active auditd", 0, "active\n")
            .with_installed(&["systemctl", "fapolicyd", "firewall-cmd"]);
        let f = facts(&Host::fake(&r, runner));
        assert_eq!(f["secure_boot"], false);
        assert_eq!(f["mac"], json!({"type": "selinux", "mode": "enforcing"}));
        assert_eq!(f["firewall"], json!({"backend": "firewalld", "active": true}));
        assert_eq!(f["ssh_server"], json!({"active": true}));
        assert_eq!(f["usbguard"], json!({"installed": true, "active": true}));
        assert_eq!(f["allowlisting"], json!({"backend": "fapolicyd", "active": true}));
        assert_eq!(f["auditd"], json!({"active": true}));
    }

    #[test]
    fn missing_tools_are_unknown() {
        let r = root();
        std::fs::create_dir_all(r.join("sys/fs")).unwrap();
        write(&r, "/sys/module/apparmor/parameters/enabled", b"Y\n");
        std::fs::create_dir_all(r.join("sys/firmware/efi")).unwrap();
        let f = facts(&Host::fake(&r, FakeRunner::new()));
        assert_eq!(f["secure_boot"], "unknown");
        assert_eq!(f["mac"], json!({"type": "apparmor", "mode": "unknown"}));
        assert_eq!(f["firewall"], json!({"backend": "unknown", "active": "unknown"}));
        assert_eq!(f["ssh_server"], json!({"active": "unknown"}));
        assert_eq!(f["auditd"], json!({"active": "unknown"}));
    }

    #[test]
    fn mokutil_fallback_and_no_mac() {
        let r = root();
        std::fs::create_dir_all(r.join("sys/fs")).unwrap();
        let runner = FakeRunner::new()
            .on("mokutil --sb-state", 0, "SecureBoot disabled\n")
            .on("systemctl is-active firewalld", 4, "")
            .on("systemctl is-active ufw", 4, "")
            .on("systemctl is-active nftables", 4, "")
            .with_installed(&["mokutil", "systemctl"]);
        let f = facts(&Host::fake(&r, runner));
        assert_eq!(f["secure_boot"], false);
        assert_eq!(f["mac"], json!({"type": "none", "mode": "disabled"}));
        assert_eq!(f["firewall"], json!({"backend": "none", "active": false}));
    }

    fn scan_root(os_release: &str, ds: &str) -> PathBuf {
        let r = root();
        write(&r, "/etc/os-release", os_release.as_bytes());
        write(&r, &format!("/usr/share/xml/scap/ssg/content/{ds}"), b"<ds/>");
        r
    }

    #[test]
    fn scan_dry_run_ubuntu() {
        let r = scan_root("ID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"24.04\"\n", "ssg-ubuntu2404-ds.xml");
        let host = Host::fake(&r, FakeRunner::new().with_installed(&["oscap"]));
        let res = scan(&host, Some("cis-l1-workstation"), true).unwrap();
        assert_eq!(res.status, status::DRY_RUN);
        assert_eq!(
            res.commands[1],
            cmd(&[
                "oscap",
                "xccdf",
                "eval",
                "--profile",
                "xccdf_org.ssgproject.content_profile_cis_level1_workstation",
                "--results-arf",
                ARF,
                "/usr/share/xml/scap/ssg/content/ssg-ubuntu2404-ds.xml",
            ])
        );
    }

    #[test]
    fn scan_rhel_failures_is_ok() {
        let r = scan_root("ID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\nVERSION_ID=\"9.4\"\n", "ssg-rhel9-ds.xml");
        let oscap = format!(
            "oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_stig --results-arf {ARF} \
             /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml"
        );
        let runner =
            FakeRunner::new().on(&format!("mkdir -p -m 0700 {SCAP_DIR}"), 0, "").on(&oscap, 2, "lots of output");
        let host = Host::fake(&r, runner);
        let res = scan(&host, Some("stig"), false).unwrap();
        assert_eq!(res.status, status::OK);
        assert_eq!(res.data["result"], "failures");
        assert!(res.data.get("output").is_none());
    }

    #[test]
    fn scan_errors() {
        let r = scan_root("ID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"24.04\"\n", "ssg-ubuntu2404-ds.xml");
        let host = Host::fake(&r, FakeRunner::new().with_installed(&["oscap"]));
        assert!(matches!(scan(&host, None, true), Err(ActionError::BadRequest(_))));
        assert!(matches!(scan(&host, Some("none"), true), Err(ActionError::BadRequest(_))));

        let host = Host::fake(&r, FakeRunner::new());
        let res = scan(&host, Some("stig"), false).unwrap();
        assert_eq!(res.status, status::FAILED);
        assert!(res.message.contains("oscap is not installed"));

        let r = root();
        write(&r, "/etc/os-release", b"ID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"26.04\"\n");
        let host = Host::fake(&r, FakeRunner::new().with_installed(&["oscap"]));
        let res = scan(&host, Some("stig"), true).unwrap();
        assert_eq!(res.status, status::FAILED);
        assert!(res.message.contains("ssg-ubuntu2604-ds.xml"));

        let req = ActionRequest::default();
        let e = with_test_env(&host, |env| Security.run(env, "security.nope", &req)).unwrap_err();
        assert!(matches!(e, ActionError::Unknown(_)));
    }

    #[test]
    fn datastream_mapping() {
        let ds = |t: &str| scap_datastream(&OsRelease::parse(t));
        assert!(ds("ID=almalinux\nID_LIKE=\"rhel centos fedora\"\nVERSION_ID=10.0")
            .unwrap()
            .ends_with("ssg-rhel10-ds.xml"));
        assert!(ds("ID=debian\nVERSION_ID=12").is_err());
        assert!(ds("ID=ubuntu\nVERSION_ID=\"24.04/../x\"").is_err());
    }
}
