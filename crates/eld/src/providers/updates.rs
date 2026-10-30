//! `updates`: pending package updates, reboot state and the update ring.
//! Reads the native package manager of the substrate family (apt, dnf,
//! zypper); install and refresh actions run the same tools.

use eld_api::{status, ActionRequest, ActionResult, ActionSpec, Object, Role, SettingSpec, SettingType};
use serde_json::{json, Value};
use std::sync::Arc;

use crate::provider::{cmd, not_implemented, run_planned, unknown, ActionError, Env, Provider};
use crate::sys::{family, Family, System};

/// Marker file eld's update job writes after a successful run.
const LAST_SUCCESS: &str = "/var/lib/eld/updates/last-success";

/// The `updates` provider.
pub struct Updates;

/// Creates the provider.
pub fn new() -> Arc<dyn Provider> {
    Arc::new(Updates)
}

/// Pending update counts; `None` means unknown.
#[derive(Debug, Default, PartialEq)]
struct Pending {
    all: Option<u64>,
    security: Option<u64>,
}

fn opt_int(v: Option<u64>) -> Value {
    v.map(Value::from).unwrap_or_else(unknown)
}

fn opt_bool(v: Option<bool>) -> Value {
    v.map(Value::Bool).unwrap_or_else(unknown)
}

/// Stdout of a tool if it is installed and exits with one of `codes`.
fn run_ok(sys: &dyn System, tool: &str, args: &[&str], codes: &[i32]) -> Option<(i32, String)> {
    if !sys.installed(tool) {
        return None;
    }
    match sys.run(tool, args) {
        Ok(o) if codes.contains(&o.code) => Some((o.code, o.stdout)),
        _ => None,
    }
}

/// Counts `Inst ` lines of an apt-get simulation; security ones come from a
/// `-security` pocket.
fn parse_apt(out: &str) -> Pending {
    let inst: Vec<&str> = out.lines().filter(|l| l.starts_with("Inst ")).collect();
    let security = inst.iter().filter(|l| l.contains("-security")).count() as u64;
    Pending { all: Some(inst.len() as u64), security: Some(security) }
}

/// Counts package lines of `dnf -q check-update`, stopping at the
/// "Obsoleting Packages" block.
fn parse_dnf_check(out: &str) -> u64 {
    let mut n = 0;
    for l in out.lines() {
        if l.starts_with("Obsoleting") {
            break;
        }
        if !l.trim().is_empty() {
            n += 1;
        }
    }
    n
}

fn count_nonempty(out: &str) -> u64 {
    out.lines().filter(|l| !l.trim().is_empty()).count() as u64
}

fn pending_debian(sys: &dyn System) -> Pending {
    match run_ok(sys, "apt-get", &["-s", "-o", "Debug::NoLocking=true", "upgrade"], &[0]) {
        Some((_, out)) => parse_apt(&out),
        None => Pending::default(),
    }
}

fn pending_rhel(sys: &dyn System) -> Pending {
    let all = match run_ok(sys, "dnf", &["-q", "check-update"], &[0, 100]) {
        Some((100, out)) => Some(parse_dnf_check(&out)),
        Some(_) => Some(0),
        None => None,
    };
    let security =
        run_ok(sys, "dnf", &["-q", "updateinfo", "list", "--security"], &[0]).map(|(_, o)| count_nonempty(&o));
    Pending { all, security }
}

fn pending_suse(sys: &dyn System) -> Pending {
    let all = run_ok(sys, "zypper", &["--non-interactive", "--quiet", "list-updates"], &[0])
        .map(|(_, o)| o.lines().filter(|l| l.starts_with("v |")).count() as u64);
    Pending { all, security: None }
}

fn reboot_required(sys: &dyn System, fam: Family) -> Option<bool> {
    match fam {
        Family::Debian => Some(sys.exists("/var/run/reboot-required") || sys.exists("/run/reboot-required")),
        Family::Rhel => match run_ok(sys, "needs-restarting", &["-r"], &[0, 1]) {
            Some((1, _)) => Some(true),
            Some(_) => Some(false),
            None => None,
        },
        // zypper creates this flag; its absence is not proof of "no reboot".
        Family::Suse => (sys.exists("/run/reboot-needed") || sys.exists("/var/run/reboot-needed")).then_some(true),
        Family::Unknown => None,
    }
}

fn package_manager(fam: Family) -> &'static str {
    match fam {
        Family::Debian => "apt",
        Family::Rhel => "dnf",
        Family::Suse => "zypper",
        Family::Unknown => "unknown",
    }
}

/// Commands of a mutating action for a family, `None` if unsupported.
fn plan(name: &str, fam: Family) -> Option<Vec<Vec<String>>> {
    let c = match (name, fam) {
        ("updates.check", Family::Debian) => cmd(&["apt-get", "update"]),
        ("updates.check", Family::Rhel) => cmd(&["dnf", "-q", "makecache"]),
        ("updates.check", Family::Suse) => cmd(&["zypper", "--non-interactive", "refresh"]),
        ("updates.install-now", Family::Debian) => {
            cmd(&["apt-get", "-y", "-o", "Dpkg::Options::=--force-confold", "upgrade"])
        }
        ("updates.install-now", Family::Rhel) => cmd(&["dnf", "-y", "upgrade"]),
        ("updates.install-now", Family::Suse) => cmd(&["zypper", "--non-interactive", "update"]),
        _ => return None,
    };
    Some(vec![c])
}

impl Provider for Updates {
    fn namespace(&self) -> &'static str {
        "updates"
    }

    fn facts(&self, env: &Env) -> Result<Object, String> {
        let fam = family(env.sys);
        let pending = match fam {
            Family::Debian => pending_debian(env.sys),
            Family::Rhel => pending_rhel(env.sys),
            Family::Suse => pending_suse(env.sys),
            Family::Unknown => Pending::default(),
        };
        let last_success = env
            .sys
            .read_trimmed(LAST_SUCCESS)
            .ok()
            .filter(|s| !s.is_empty())
            .map(Value::String)
            .unwrap_or_else(unknown);
        let ring = match (env.setting)("updates.ring") {
            Some(Value::String(s)) if !s.is_empty() => Value::String(s),
            _ => unknown(),
        };
        let mut o = Object::new();
        o.insert("package_manager".into(), json!(package_manager(fam)));
        o.insert("pending".into(), opt_int(pending.all));
        o.insert("security_pending".into(), opt_int(pending.security));
        o.insert("reboot_required".into(), opt_bool(reboot_required(env.sys, fam)));
        o.insert("last_success".into(), last_success);
        o.insert("ring".into(), ring);
        Ok(o)
    }

    fn settings(&self) -> Vec<SettingSpec> {
        vec![
            SettingSpec::enumeration(
                "updates.ring",
                &["canary", "pilot", "broad"],
                "Rollout ring this device belongs to.",
            )
            .with_default(json!("broad")),
            SettingSpec::new("updates.window", SettingType::String, "Maintenance window for installing updates."),
            SettingSpec::new("updates.maxDeferralDays", SettingType::Int, "Days a user may defer pending updates.")
                .with_default(json!(7)),
            SettingSpec::new(
                "updates.autoReboot",
                SettingType::Bool,
                "Reboot automatically after updates when required.",
            )
            .with_default(json!(false)),
        ]
    }

    fn actions(&self) -> Vec<ActionSpec> {
        vec![
            ActionSpec::new("updates.check", Role::User, "Refresh package metadata."),
            ActionSpec::new("updates.install-now", Role::Helpdesk, "Install all pending updates now."),
            ActionSpec::new("updates.rollback", Role::LocalAdmin, "Roll back the last update.").not_implemented(),
        ]
    }

    fn run(&self, env: &Env, name: &str, req: &ActionRequest) -> Result<ActionResult, ActionError> {
        match name {
            "updates.check" | "updates.install-now" => {
                let fam = family(env.sys);
                match plan(name, fam) {
                    Some(cmds) => Ok(run_planned(env.sys, name, req.dry_run, cmds)),
                    None => Ok(ActionResult {
                        action: name.into(),
                        status: status::FAILED.into(),
                        message: "unsupported substrate".into(),
                        ..Default::default()
                    }),
                }
            }
            "updates.rollback" => Ok(not_implemented(
                name,
                "rollback needs an image-based (bootc/ostree) or snapshot substrate, see docs/HARDENING.md §4",
            )),
            _ => Err(ActionError::Unknown(name.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::with_test_env;
    use crate::sys::{FakeRunner, Host};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static N: AtomicUsize = AtomicUsize::new(0);

    fn root(os_release: &str, files: &[(&str, &str)]) -> std::path::PathBuf {
        let n = N.fetch_add(1, Ordering::SeqCst);
        let d = std::env::temp_dir().join(format!("eld-test-{}-updates-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("etc")).unwrap();
        std::fs::write(d.join("etc/os-release"), os_release).unwrap();
        for (p, c) in files {
            let f = d.join(p.trim_start_matches('/'));
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(f, c).unwrap();
        }
        d
    }

    const UBUNTU: &str = "ID=ubuntu\nID_LIKE=debian\n";
    const ROCKY: &str = "ID=rocky\nID_LIKE=\"rhel centos fedora\"\n";

    const APT_SIM: &str = "Reading package lists...\n\
Inst libssl3 [3.0.13-0ubuntu3.1] (3.0.13-0ubuntu3.4 Ubuntu:24.04/noble-security [amd64])\n\
Inst curl [8.5.0-2ubuntu10.1] (8.5.0-2ubuntu10.6 Ubuntu:24.04/noble-updates [amd64])\n\
Conf libssl3 (3.0.13-0ubuntu3.4 Ubuntu:24.04/noble-security [amd64])\n";

    #[test]
    fn debian_facts() {
        let r = root(UBUNTU, &[("/var/run/reboot-required", ""), (LAST_SUCCESS, "2026-10-28T03:00:00Z\n")]);
        let host = Host::fake(&r, FakeRunner::new().on("apt-get -s -o Debug::NoLocking=true upgrade", 0, APT_SIM));
        let f = with_test_env(&host, |env| Updates.facts(env)).unwrap();
        assert_eq!(f["package_manager"], "apt");
        assert_eq!(f["pending"], 2);
        assert_eq!(f["security_pending"], 1);
        assert_eq!(f["reboot_required"], true);
        assert_eq!(f["last_success"], "2026-10-28T03:00:00Z");
        assert_eq!(f["ring"], "unknown");
    }

    #[test]
    fn debian_missing_apt_is_unknown() {
        let r = root(UBUNTU, &[]);
        let host = Host::fake(&r, FakeRunner::new());
        let f = with_test_env(&host, |env| Updates.facts(env)).unwrap();
        assert_eq!(f["pending"], "unknown");
        assert_eq!(f["security_pending"], "unknown");
        assert_eq!(f["reboot_required"], false);
        assert_eq!(f["last_success"], "unknown");
    }

    #[test]
    fn rhel_facts() {
        let r = root(ROCKY, &[]);
        let check = "\nkernel.x86_64   5.14.0-503.el9   baseos\nopenssl.x86_64  1:3.2.2-6.el9   baseos\n\
Obsoleting Packages\nfoo.x86_64  1.0  appstream\n";
        let host = Host::fake(
            &r,
            FakeRunner::new()
                .on("dnf -q check-update", 100, check)
                .on("dnf -q updateinfo list --security", 0, "RLSA-2026:1 Important/Sec. openssl-1:3.2.2-6.el9.x86_64\n")
                .on("needs-restarting -r", 1, "Reboot is required\n"),
        );
        let f = with_test_env(&host, |env| Updates.facts(env)).unwrap();
        assert_eq!(f["package_manager"], "dnf");
        assert_eq!(f["pending"], 2);
        assert_eq!(f["security_pending"], 1);
        assert_eq!(f["reboot_required"], true);
    }

    #[test]
    fn rhel_no_updates_and_missing_needs_restarting() {
        let r = root(ROCKY, &[]);
        let host = Host::fake(
            &r,
            FakeRunner::new().on("dnf -q check-update", 0, "").on("dnf -q updateinfo list --security", 0, ""),
        );
        let f = with_test_env(&host, |env| Updates.facts(env)).unwrap();
        assert_eq!(f["pending"], 0);
        assert_eq!(f["security_pending"], 0);
        assert_eq!(f["reboot_required"], "unknown");
    }

    #[test]
    fn rhel_dnf_error_is_unknown() {
        let r = root(ROCKY, &[]);
        let host = Host::fake(&r, FakeRunner::new().on("dnf -q check-update", 1, ""));
        let f = with_test_env(&host, |env| Updates.facts(env)).unwrap();
        assert_eq!(f["pending"], "unknown");
    }

    #[test]
    fn suse_and_unknown_family() {
        let r = root("ID=opensuse-leap\nID_LIKE=\"suse opensuse\"\n", &[]);
        let out = "S | Repository | Name | Current | Available | Arch\nv | repo-oss   | vim  | 9.0     | 9.1       | x86_64\n";
        let host = Host::fake(&r, FakeRunner::new().on("zypper --non-interactive --quiet list-updates", 0, out));
        let f = with_test_env(&host, |env| Updates.facts(env)).unwrap();
        assert_eq!(f["package_manager"], "zypper");
        assert_eq!(f["pending"], 1);
        assert_eq!(f["security_pending"], "unknown");

        let r = root("ID=arch\n", &[]);
        let host = Host::fake(&r, FakeRunner::new());
        let f = with_test_env(&host, |env| Updates.facts(env)).unwrap();
        assert_eq!(f["package_manager"], "unknown");
        assert_eq!(f["reboot_required"], "unknown");
        let res = with_test_env(&host, |env| Updates.run(env, "updates.check", &ActionRequest::default())).unwrap();
        assert_eq!(res.status, status::FAILED);
        assert_eq!(res.message, "unsupported substrate");
    }

    #[test]
    fn ring_from_setting() {
        let r = root(UBUNTU, &[]);
        let host = Host::fake(&r, FakeRunner::new());
        let setting = |k: &str| (k == "updates.ring").then(|| json!("pilot"));
        let emit = |_: &str, _: &str, _: Object| {};
        let facts = |_: &str| Err(String::new());
        let env = Env { sys: &host, setting: &setting, emit: &emit, caller: None, facts: &facts, now: 0 };
        assert_eq!(Updates.facts(&env).unwrap()["ring"], "pilot");
    }

    #[test]
    fn actions_dry_run_and_run() {
        let r = root(UBUNTU, &[]);
        let host = Host::fake(&r, FakeRunner::new().on("apt-get update", 0, "ok\n"));
        let dry = ActionRequest { dry_run: true, ..Default::default() };
        let res = with_test_env(&host, |env| Updates.run(env, "updates.install-now", &dry)).unwrap();
        assert_eq!(res.status, status::DRY_RUN);
        assert_eq!(res.commands, vec![cmd(&["apt-get", "-y", "-o", "Dpkg::Options::=--force-confold", "upgrade"])]);
        let res = with_test_env(&host, |env| Updates.run(env, "updates.check", &ActionRequest::default())).unwrap();
        assert_eq!(res.status, status::OK);

        let r = root(ROCKY, &[]);
        let host = Host::fake(&r, FakeRunner::new());
        let res = with_test_env(&host, |env| Updates.run(env, "updates.install-now", &dry)).unwrap();
        assert_eq!(res.commands, vec![cmd(&["dnf", "-y", "upgrade"])]);
        let res = with_test_env(&host, |env| Updates.run(env, "updates.rollback", &dry)).unwrap();
        assert_eq!(res.status, status::NOT_IMPLEMENTED);
        let err = with_test_env(&host, |env| Updates.run(env, "updates.nope", &dry)).unwrap_err();
        assert_eq!(err, ActionError::Unknown("updates.nope".into()));
    }

    #[test]
    fn specs_are_namespaced() {
        let p = new();
        assert!(crate::provider::Registry::new(vec![p]).is_ok());
    }
}
