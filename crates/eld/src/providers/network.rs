//! `network`: interfaces, VPN state, DNS servers and EDR isolation state.
//! Settings are stored and reported only; the isolation response actions
//! are declared but not built yet.

use eld_api::{ActionRequest, ActionResult, ActionSpec, Object, Role, SettingSpec, SettingType};
use serde_json::{json, Value};
use std::sync::Arc;

use crate::provider::{self, unknown, ActionError, Env, Provider};
use crate::sys::System;

/// Marker file present while the device is network-isolated by an EDR.
pub const ISOLATED_MARKER: &str = "/var/lib/eld/network/isolated";

/// Linux ARPHRD types from `/sys/class/net/<if>/type`.
const ARPHRD_ETHER: &str = "1";
const ARPHRD_LOOPBACK: &str = "772";

const ISOLATION_WHY: &str = "isolation firewall rule set (allow only MDM/EDR endpoints) not built yet";

/// The network provider.
pub struct Network;

/// Creates the provider.
pub fn new() -> Arc<dyn Provider> {
    Arc::new(Network)
}

impl Provider for Network {
    fn namespace(&self) -> &'static str {
        "network"
    }

    fn facts(&self, env: &Env) -> Result<Object, String> {
        let mut f = Object::new();
        f.insert("interfaces".into(), interfaces(env.sys));
        f.insert("vpn".into(), json!({ "active": vpn_active(env.sys) }));
        f.insert("dns".into(), nameservers(env.sys));
        f.insert("isolated".into(), Value::Bool(env.sys.exists(ISOLATED_MARKER)));
        Ok(f)
    }

    fn settings(&self) -> Vec<SettingSpec> {
        vec![
            SettingSpec::new("network.proxy", SettingType::String, "System proxy URL, empty for none"),
            SettingSpec::new("network.dns", SettingType::List, "DNS servers to use instead of DHCP-provided ones"),
            SettingSpec::new("network.vpn.alwaysOn", SettingType::Bool, "Require the corporate VPN to be connected"),
        ]
    }

    fn actions(&self) -> Vec<ActionSpec> {
        vec![
            ActionSpec::new(
                "network.isolate",
                Role::SvcEdr,
                "EDR response: block all traffic except to MDM/EDR endpoints",
            )
            .not_implemented(),
            ActionSpec::new("network.release-isolation", Role::SvcEdr, "EDR response: lift network isolation")
                .not_implemented(),
        ]
    }

    fn run(&self, _env: &Env, name: &str, _req: &ActionRequest) -> Result<ActionResult, ActionError> {
        match name {
            "network.isolate" | "network.release-isolation" => Ok(provider::not_implemented(name, ISOLATION_WHY)),
            _ => Err(ActionError::Unknown(name.to_string())),
        }
    }
}

/// Lists non-loopback interfaces from sysfs, or "unknown".
fn interfaces(sys: &dyn System) -> Value {
    let Ok(names) = sys.read_dir("/sys/class/net") else {
        return unknown();
    };
    let list: Vec<Value> = names
        .iter()
        .filter(|n| n.as_str() != "lo")
        .map(|n| {
            let base = format!("/sys/class/net/{n}");
            let read = |leaf: &str| {
                sys.read_trimmed(&format!("{base}/{leaf}")).map(Value::String).unwrap_or_else(|_| unknown())
            };
            json!({
                "name": n,
                "mac": read("address"),
                "operstate": read("operstate"),
                "kind": kind(sys, n),
            })
        })
        .collect();
    Value::Array(list)
}

/// Classifies an interface: wireless, virtual, loopback, ethernet or other.
fn kind(sys: &dyn System, name: &str) -> &'static str {
    if sys.exists(&format!("/sys/class/net/{name}/wireless")) {
        return "wireless";
    }
    if sys.exists(&format!("/sys/devices/virtual/net/{name}")) {
        return "virtual";
    }
    match sys.read_trimmed(&format!("/sys/class/net/{name}/type")).as_deref() {
        Ok(ARPHRD_LOOPBACK) => "loopback",
        Ok(ARPHRD_ETHER) => "ethernet",
        _ => "other",
    }
}

/// Whether a VPN or WireGuard connection is active per NetworkManager.
fn vpn_active(sys: &dyn System) -> Value {
    if !sys.installed("nmcli") {
        return unknown();
    }
    match sys.run("nmcli", &["-t", "-f", "TYPE,STATE", "connection", "show", "--active"]) {
        Ok(o) if o.success() => Value::Bool(o.stdout.lines().any(|l| {
            let l = l.trim();
            (l.starts_with("vpn:") || l.starts_with("wireguard:")) && l.contains("activated")
        })),
        _ => unknown(),
    }
}

/// `nameserver` entries from `/etc/resolv.conf`, or "unknown".
fn nameservers(sys: &dyn System) -> Value {
    let Ok(text) = sys.read_file("/etc/resolv.conf") else {
        return unknown();
    };
    let list: Vec<Value> = String::from_utf8_lossy(&text)
        .lines()
        .filter_map(|l| {
            let mut parts = l.split_whitespace();
            match (parts.next(), parts.next()) {
                (Some("nameserver"), Some(addr)) => Some(Value::String(addr.to_string())),
                _ => None,
            }
        })
        .collect();
    Value::Array(list)
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
            "eld-test-{}-net-{}",
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

    fn iface(root: &Path, name: &str, mac: &str, ty: &str) {
        write(root, &format!("/sys/class/net/{name}/address"), &format!("{mac}\n"));
        write(root, &format!("/sys/class/net/{name}/operstate"), "up\n");
        write(root, &format!("/sys/class/net/{name}/type"), &format!("{ty}\n"));
    }

    const NMCLI: &str = "nmcli -t -f TYPE,STATE connection show --active";

    #[test]
    fn facts_debian_with_vpn() {
        let r = root();
        write(&r, "/etc/os-release", "ID=ubuntu\nID_LIKE=debian\n");
        iface(&r, "lo", "00:00:00:00:00:00", "772");
        iface(&r, "enp0s1", "52:54:00:12:34:56", "1");
        iface(&r, "wlp2s0", "aa:bb:cc:dd:ee:ff", "1");
        std::fs::create_dir_all(r.join("sys/class/net/wlp2s0/wireless")).unwrap();
        iface(&r, "docker0", "02:42:00:00:00:01", "1");
        std::fs::create_dir_all(r.join("sys/devices/virtual/net/docker0")).unwrap();
        write(&r, "/etc/resolv.conf", "# generated\nnameserver 127.0.0.53\noptions edns0\nnameserver 10.0.0.1\n");
        let host = Host::fake(&r, FakeRunner::new().on(NMCLI, 0, "802-11-wireless:activated\nvpn:activated\n"));
        let f = with_test_env(&host, |env| Network.facts(env)).unwrap();
        let ifs = f["interfaces"].as_array().unwrap();
        assert_eq!(ifs.len(), 3);
        let by = |n: &str| ifs.iter().find(|i| i["name"] == n).unwrap().clone();
        assert_eq!(by("enp0s1")["kind"], "ethernet");
        assert_eq!(by("enp0s1")["mac"], "52:54:00:12:34:56");
        assert_eq!(by("enp0s1")["operstate"], "up");
        assert_eq!(by("wlp2s0")["kind"], "wireless");
        assert_eq!(by("docker0")["kind"], "virtual");
        assert_eq!(f["vpn"]["active"], true);
        assert_eq!(f["dns"], json!(["127.0.0.53", "10.0.0.1"]));
        assert_eq!(f["isolated"], false);
    }

    #[test]
    fn facts_rhel_wireguard_inactive_and_isolated() {
        let r = root();
        write(&r, "/etc/os-release", "ID=\"rhel\"\nID_LIKE=\"fedora\"\n");
        iface(&r, "eth0", "52:54:00:aa:bb:cc", "1");
        write(&r, ISOLATED_MARKER, "");
        let host = Host::fake(&r, FakeRunner::new().on(NMCLI, 0, "wireguard:activating\n802-3-ethernet:activated\n"));
        let f = with_test_env(&host, |env| Network.facts(env)).unwrap();
        assert_eq!(f["vpn"]["active"], false);
        assert_eq!(f["isolated"], true);
        assert_eq!(f["interfaces"][0]["kind"], "ethernet");
    }

    #[test]
    fn missing_tools_and_files_are_unknown() {
        let r = root();
        let host = Host::fake(&r, FakeRunner::new());
        let f = with_test_env(&host, |env| Network.facts(env)).unwrap();
        assert_eq!(f["interfaces"], "unknown");
        assert_eq!(f["vpn"]["active"], "unknown");
        assert_eq!(f["dns"], "unknown");
        // nmcli present but failing
        let host = Host::fake(&r, FakeRunner::new().on(NMCLI, 8, ""));
        let f = with_test_env(&host, |env| Network.facts(env)).unwrap();
        assert_eq!(f["vpn"]["active"], "unknown");
    }

    #[test]
    fn isolation_actions_not_implemented() {
        let host = Host::fake(root(), FakeRunner::new());
        let req = ActionRequest { dry_run: true, ..Default::default() };
        for a in Network.actions() {
            assert!(!a.implemented);
            assert_eq!(a.min_role, Role::SvcEdr);
            let res = with_test_env(&host, |env| Network.run(env, &a.name, &req)).unwrap();
            assert_eq!(res.status, status::NOT_IMPLEMENTED);
            assert!(res.commands.is_empty());
        }
        let err = with_test_env(&host, |env| Network.run(env, "network.nope", &req)).unwrap_err();
        assert!(matches!(err, ActionError::Unknown(_)));
    }
}
