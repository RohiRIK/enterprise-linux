//! The `os` namespace: distro identity from os-release, the
//! enterprise-linux image and build, and the running kernel. Read-only.

use eld_api::Object;
use serde_json::{json, Value};
use std::sync::Arc;

use crate::provider::{unknown, Env, Provider};
use crate::sys::OsRelease;

/// Build metadata written by the image build (`KEY=VALUE` lines).
pub const BUILD_INFO: &str = "/usr/lib/enterprise-linux/build-info";

/// Returns the os provider.
pub fn new() -> Arc<dyn Provider> {
    Arc::new(OsInfo)
}

/// The os provider.
pub struct OsInfo;

/// A non-empty field or "unknown".
fn field(o: &OsRelease, k: &str) -> Value {
    match o.get(k) {
        "" => unknown(),
        v => json!(v),
    }
}

/// The bracketed (active) mode of `/sys/kernel/security/lockdown`, e.g.
/// `none [integrity] confidentiality` -> `integrity`.
fn lockdown_mode(text: &str) -> Option<&str> {
    text.split_whitespace()
        .find_map(|t| t.strip_prefix('[').and_then(|t| t.strip_suffix(']')))
        .filter(|t| !t.is_empty())
}

impl Provider for OsInfo {
    fn namespace(&self) -> &'static str {
        "os"
    }

    fn facts(&self, env: &Env) -> Result<Object, String> {
        let sys = env.sys;
        let rel = OsRelease::read(sys).ok();
        let empty = OsRelease::default();
        let o = rel.as_ref().unwrap_or(&empty);

        let mut f = Object::new();
        for (key, name) in [
            ("id", "ID"),
            ("id_like", "ID_LIKE"),
            ("name", "NAME"),
            ("version_id", "VERSION_ID"),
            ("pretty_name", "PRETTY_NAME"),
        ] {
            f.insert(key.into(), field(o, name));
        }
        let family = if rel.is_some() { json!(o.family().as_str()) } else { unknown() };
        f.insert("family".into(), family);
        f.insert("image".into(), json!({"id": field(o, "IMAGE_ID"), "version": field(o, "IMAGE_VERSION")}));

        // build-info uses the same KEY=VALUE syntax as os-release.
        let build =
            sys.read_file(BUILD_INFO).map(|b| OsRelease::parse(&String::from_utf8_lossy(&b))).unwrap_or_default();
        f.insert("build_hash".into(), field(&build, "BUILD_HASH"));

        let release = sys.read_trimmed("/proc/sys/kernel/osrelease").ok().filter(|r| !r.is_empty());
        let lockdown = sys
            .read_trimmed("/sys/kernel/security/lockdown")
            .ok()
            .and_then(|t| lockdown_mode(&t).map(|m| json!(m)))
            .unwrap_or_else(unknown);
        if rel.is_none() && release.is_none() {
            return Err("os: neither os-release nor the kernel release is readable".into());
        }
        f.insert(
            "kernel".into(),
            json!({"release": release.map(Value::String).unwrap_or_else(unknown), "lockdown": lockdown}),
        );
        f.insert("arch".into(), json!(std::env::consts::ARCH));
        Ok(f)
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
        let d = std::env::temp_dir().join(format!("eld-test-{}-osinfo-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn write(root: &Path, path: &str, content: &str) {
        let p = root.join(path.trim_start_matches('/'));
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, content).unwrap();
    }

    #[test]
    fn debian_family_with_image() {
        let r = root();
        write(
            &r,
            "/etc/os-release",
            "NAME=\"Ubuntu\"\nID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"24.04\"\n\
             PRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\nIMAGE_ID=el-workstation\nIMAGE_VERSION=2026.10.3\n",
        );
        write(&r, BUILD_INFO, "# build\nBUILD_HASH=\"abc123\"\nBUILD_DATE=2026-10-28\n");
        write(&r, "/proc/sys/kernel/osrelease", "6.8.0-45-generic\n");
        write(&r, "/sys/kernel/security/lockdown", "none [integrity] confidentiality\n");
        let host = Host::fake(&r, FakeRunner::new());
        let f = with_test_env(&host, |env| OsInfo.facts(env)).unwrap();
        assert_eq!(f["id"], "ubuntu");
        assert_eq!(f["id_like"], "debian");
        assert_eq!(f["name"], "Ubuntu");
        assert_eq!(f["version_id"], "24.04");
        assert_eq!(f["pretty_name"], "Ubuntu 24.04.1 LTS");
        assert_eq!(f["family"], "debian");
        assert_eq!(f["image"], json!({"id": "el-workstation", "version": "2026.10.3"}));
        assert_eq!(f["build_hash"], "abc123");
        assert_eq!(f["kernel"], json!({"release": "6.8.0-45-generic", "lockdown": "integrity"}));
        assert_eq!(f["arch"], std::env::consts::ARCH);
    }

    #[test]
    fn rhel_family_missing_extras() {
        let r = root();
        write(&r, "/usr/lib/os-release", "ID=\"rhel\"\nID_LIKE=\"fedora\"\nVERSION_ID=\"9.4\"\n");
        let host = Host::fake(&r, FakeRunner::new());
        let f = with_test_env(&host, |env| OsInfo.facts(env)).unwrap();
        assert_eq!(f["family"], "rhel");
        assert_eq!(f["name"], "unknown");
        assert_eq!(f["image"], json!({"id": "unknown", "version": "unknown"}));
        assert_eq!(f["build_hash"], "unknown");
        assert_eq!(f["kernel"], json!({"release": "unknown", "lockdown": "unknown"}));
    }

    #[test]
    fn kernel_only_and_nothing() {
        let r = root();
        write(&r, "/proc/sys/kernel/osrelease", "5.14.0\n");
        let host = Host::fake(&r, FakeRunner::new());
        let f = with_test_env(&host, |env| OsInfo.facts(env)).unwrap();
        assert_eq!(f["family"], "unknown");
        assert_eq!(f["id"], "unknown");

        let host = Host::fake(root(), FakeRunner::new());
        assert!(with_test_env(&host, |env| OsInfo.facts(env)).is_err());
    }

    #[test]
    fn lockdown_parse() {
        assert_eq!(lockdown_mode("[none] integrity confidentiality"), Some("none"));
        assert_eq!(lockdown_mode("none integrity [confidentiality]"), Some("confidentiality"));
        assert_eq!(lockdown_mode("none integrity"), None);
    }
}
