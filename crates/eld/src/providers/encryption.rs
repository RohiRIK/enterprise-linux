//! `encryption`: whether the root filesystem sits on LUKS, how it unlocks,
//! mounted volumes, and recovery-key escrow metadata. Key material is never
//! read or returned (docs/ENCRYPTION.md §5).

use eld_api::{ActionRequest, ActionResult, ActionSpec, Object, Role, SettingSpec, SettingType};
use serde_json::{json, Value};
use std::sync::Arc;

use crate::provider::{not_implemented, unknown, ActionError, Env, Provider, UNKNOWN};
use crate::sys::System;

/// Escrow metadata written by eld's escrow job; only metadata fields are read.
const ESCROW_FILE: &str = "/var/lib/eld/encryption/escrow.json";

const NOT_BUILT: &str = "escrow target not chosen (docs/ENCRYPTION.md §6, open question 2); \
key material is never returned by the API";

/// The `encryption` provider.
pub struct Encryption;

/// Creates the provider.
pub fn new() -> Arc<dyn Provider> {
    Arc::new(Encryption)
}

/// One lsblk node, flattened, with the index of its parent.
#[derive(Debug, Clone)]
struct Dev {
    name: String,
    path: String,
    kind: String,
    fstype: String,
    mountpoints: Vec<String>,
    parent: Option<usize>,
}

fn s(v: &Value, k: &str) -> String {
    v.get(k).and_then(Value::as_str).unwrap_or("").to_string()
}

/// Flattens `lsblk -J` output; children keep a link to their parent.
fn parse_lsblk(json_text: &str) -> Option<Vec<Dev>> {
    let v: Value = serde_json::from_str(json_text).ok()?;
    let mut out = Vec::new();
    fn walk(v: &Value, parent: Option<usize>, out: &mut Vec<Dev>) {
        let mut mountpoints: Vec<String> = match v.get("mountpoints") {
            Some(Value::Array(a)) => a.iter().filter_map(|m| m.as_str().map(String::from)).collect(),
            _ => vec![],
        };
        // Older lsblk only has the singular column.
        if let Some(m) = v.get("mountpoint").and_then(Value::as_str) {
            mountpoints.push(m.to_string());
        }
        out.push(Dev {
            name: s(v, "name"),
            path: s(v, "path"),
            kind: s(v, "type"),
            fstype: s(v, "fstype"),
            mountpoints,
            parent,
        });
        let me = out.len() - 1;
        if let Some(Value::Array(children)) = v.get("children") {
            for c in children {
                walk(c, Some(me), out);
            }
        }
    }
    for d in v.get("blockdevices")?.as_array()? {
        walk(d, None, &mut out);
    }
    Some(out)
}

/// The LUKS container below device `i`: the parent of the nearest `crypt`
/// ancestor (or `i` itself) when that parent is `crypto_LUKS`.
fn luks_container(devs: &[Dev], i: usize) -> Option<usize> {
    let mut cur = Some(i);
    while let Some(c) = cur {
        if devs[c].kind == "crypt" {
            if let Some(p) = devs[c].parent {
                if devs[p].fstype == "crypto_LUKS" {
                    return Some(p);
                }
            }
        }
        cur = devs[c].parent;
    }
    None
}

/// LUKS version and unlock method from `cryptsetup luksDump`. Only the
/// version line and token types are read.
fn parse_luks_dump(out: &str) -> (&'static str, &'static str) {
    let mut version = UNKNOWN;
    let (mut tpm2, mut tpm2_pin, mut fido2) = (false, false, false);
    let mut in_tokens = false;
    for line in out.lines() {
        let t = line.trim();
        if !line.starts_with(char::is_whitespace) && !t.is_empty() {
            in_tokens = t == "Tokens:";
        }
        if let Some(v) = t.strip_prefix("Version:") {
            version = match v.trim() {
                "1" => "luks1",
                "2" => "luks2",
                _ => UNKNOWN,
            };
        }
        if !in_tokens {
            continue;
        }
        if let Some((k, v)) = t.split_once(':') {
            let (k, v) = (k.trim(), v.trim());
            if k.chars().all(|c| c.is_ascii_digit()) && !k.is_empty() {
                match v {
                    "systemd-tpm2" => tpm2 = true,
                    "systemd-fido2" => fido2 = true,
                    _ => {}
                }
            } else if k == "tpm2-pin" && v == "true" {
                tpm2_pin = true;
            }
        }
    }
    let unlock = if tpm2 && tpm2_pin {
        "tpm2+pin"
    } else if tpm2 {
        "tpm2"
    } else if fido2 {
        "fido2"
    } else if version == UNKNOWN {
        UNKNOWN
    } else {
        "passphrase"
    };
    (version, unlock)
}

fn luks_info(sys: &dyn System, path: &str) -> (Value, Value) {
    if path.is_empty() || !path.starts_with('/') || !sys.installed("cryptsetup") {
        return (unknown(), unknown());
    }
    match sys.run("cryptsetup", &["luksDump", path]) {
        Ok(o) if o.success() => {
            let (t, u) = parse_luks_dump(&o.stdout);
            (json!(t), json!(u))
        }
        _ => (unknown(), unknown()),
    }
}

fn str_or_unknown(s: &str) -> Value {
    if s.is_empty() {
        unknown()
    } else {
        json!(s)
    }
}

/// `root` and `volumes` facts.
fn block_facts(sys: &dyn System) -> (Value, Value) {
    let unknown_root = json!({"status": UNKNOWN, "device": UNKNOWN, "type": UNKNOWN, "unlock": UNKNOWN});
    if !sys.installed("lsblk") {
        return (unknown_root, unknown());
    }
    let devs = match sys.run("lsblk", &["-J", "-o", "NAME,PATH,TYPE,FSTYPE,MOUNTPOINTS"]) {
        Ok(o) if o.success() => parse_lsblk(&o.stdout),
        _ => None,
    };
    let Some(devs) = devs else {
        return (unknown_root, unknown());
    };
    let volumes: Vec<Value> = devs
        .iter()
        .enumerate()
        .filter(|(_, d)| !d.mountpoints.is_empty())
        .map(|(i, d)| {
            let st = if luks_container(&devs, i).is_some() { "encrypted" } else { "unencrypted" };
            json!({
                "name": d.name, "path": d.path, "type": d.kind, "fstype": d.fstype,
                "mountpoints": d.mountpoints, "status": st,
            })
        })
        .collect();
    let root = match devs.iter().position(|d| d.mountpoints.iter().any(|m| m == "/")) {
        None => unknown_root,
        Some(i) => match luks_container(&devs, i) {
            Some(p) => {
                let (t, u) = luks_info(sys, &devs[p].path);
                json!({"status": "encrypted", "device": str_or_unknown(&devs[p].path), "type": t, "unlock": u})
            }
            None => {
                json!({"status": "unencrypted", "device": str_or_unknown(&devs[i].path), "type": UNKNOWN, "unlock": UNKNOWN})
            }
        },
    };
    (root, Value::Array(volumes))
}

/// Escrow metadata. Any field other than the three below is ignored so a
/// misplaced key in the file can never reach the API.
fn recovery_facts(sys: &dyn System) -> Value {
    let meta: Option<Value> = sys.read_file(ESCROW_FILE).ok().and_then(|b| serde_json::from_slice(&b).ok());
    let meta = meta.unwrap_or(Value::Null);
    let escrowed = meta.get("escrowed").and_then(Value::as_bool).map(Value::Bool).unwrap_or_else(unknown);
    let text = |k: &str| {
        meta.get(k).and_then(Value::as_str).filter(|v| !v.is_empty()).map(|v| json!(v)).unwrap_or_else(unknown)
    };
    json!({"escrowed": escrowed, "escrow_target": text("escrow_target"), "last_rotated": text("last_rotated")})
}

impl Provider for Encryption {
    fn namespace(&self) -> &'static str {
        "encryption"
    }

    fn facts(&self, env: &Env) -> Result<Object, String> {
        let (root, volumes) = block_facts(env.sys);
        let mut o = Object::new();
        o.insert("root".into(), root);
        o.insert("volumes".into(), volumes);
        o.insert("recovery".into(), recovery_facts(env.sys));
        Ok(o)
    }

    fn settings(&self) -> Vec<SettingSpec> {
        vec![
            SettingSpec::new(
                "encryption.required",
                SettingType::Bool,
                "Require full-disk encryption of the root volume.",
            )
            .with_default(json!(true)),
            SettingSpec::enumeration(
                "encryption.unlock",
                &["tpm2", "tpm2+pin", "tpm2+network", "passphrase"],
                "Required unlock method for the root volume.",
            ),
            SettingSpec::enumeration(
                "encryption.escrow",
                &["mdm", "entra", "vault", "none"],
                "Where the recovery key is escrowed.",
            ),
        ]
    }

    fn actions(&self) -> Vec<ActionSpec> {
        vec![
            ActionSpec::new(
                "encryption.rotate-recovery-key",
                Role::LocalAdmin,
                "Rotate the LUKS recovery key and escrow it.",
            )
            .not_implemented(),
            ActionSpec::new("encryption.escrow-now", Role::LocalAdmin, "Escrow the current recovery key now.")
                .not_implemented(),
        ]
    }

    fn run(&self, _env: &Env, name: &str, _req: &ActionRequest) -> Result<ActionResult, ActionError> {
        match name {
            "encryption.rotate-recovery-key" | "encryption.escrow-now" => Ok(not_implemented(name, NOT_BUILT)),
            _ => Err(ActionError::Unknown(name.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::with_test_env;
    use crate::sys::{FakeRunner, Host};
    use eld_api::status;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static N: AtomicUsize = AtomicUsize::new(0);

    fn root(files: &[(&str, &str)]) -> std::path::PathBuf {
        let n = N.fetch_add(1, Ordering::SeqCst);
        let d = std::env::temp_dir().join(format!("eld-test-{}-encryption-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("etc")).unwrap();
        std::fs::write(d.join("etc/os-release"), "ID=ubuntu\nID_LIKE=debian\n").unwrap();
        for (p, c) in files {
            let f = d.join(p.trim_start_matches('/'));
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(f, c).unwrap();
        }
        d
    }

    const LSBLK_ARGS: &str = "lsblk -J -o NAME,PATH,TYPE,FSTYPE,MOUNTPOINTS";

    /// Ubuntu-style: nvme0n1p3 (LUKS) -> crypt -> LVM root and swap.
    const LSBLK_LUKS: &str = r#"{"blockdevices": [
      {"name":"nvme0n1","path":"/dev/nvme0n1","type":"disk","fstype":null,"mountpoints":[null],"children":[
        {"name":"nvme0n1p1","path":"/dev/nvme0n1p1","type":"part","fstype":"vfat","mountpoints":["/boot/efi"]},
        {"name":"nvme0n1p2","path":"/dev/nvme0n1p2","type":"part","fstype":"ext4","mountpoints":["/boot"]},
        {"name":"nvme0n1p3","path":"/dev/nvme0n1p3","type":"part","fstype":"crypto_LUKS","mountpoints":[null],"children":[
          {"name":"dm_crypt-0","path":"/dev/mapper/dm_crypt-0","type":"crypt","fstype":"LVM2_member","mountpoints":[null],"children":[
            {"name":"vg-root","path":"/dev/mapper/vg-root","type":"lvm","fstype":"ext4","mountpoints":["/"]},
            {"name":"vg-swap","path":"/dev/mapper/vg-swap","type":"lvm","fstype":"swap","mountpoints":["[SWAP]"]}
          ]}
        ]}
      ]}
    ]}"#;

    const LSBLK_PLAIN: &str = r#"{"blockdevices": [
      {"name":"sda","path":"/dev/sda","type":"disk","fstype":null,"mountpoints":[null],"children":[
        {"name":"sda1","path":"/dev/sda1","type":"part","fstype":"xfs","mountpoints":["/", "/var/snap"]}
      ]}
    ]}"#;

    const DUMP_TPM2_PIN: &str = "LUKS header information\nVersion:       \t2\nEpoch:         \t9\n\
Keyslots:\n  0: luks2\n\tKey:        512 bits\n  1: luks2\n\tKey:        512 bits\n\
Tokens:\n  0: systemd-tpm2\n\ttpm2-hash-pcrs:   7\n\ttpm2-pcr-bank:    sha256\n\ttpm2-pin:         true\n\tKeyslot:    1\n\
Digests:\n  0: pbkdf2\n\tHash:       sha256\n";

    fn facts(host: &Host) -> Object {
        with_test_env(host, |env| Encryption.facts(env)).unwrap()
    }

    #[test]
    fn luks_root_with_tpm2_pin() {
        let r = root(&[]);
        let host = Host::fake(
            &r,
            FakeRunner::new().on(LSBLK_ARGS, 0, LSBLK_LUKS).on("cryptsetup luksDump /dev/nvme0n1p3", 0, DUMP_TPM2_PIN),
        );
        let f = facts(&host);
        assert_eq!(
            f["root"],
            json!({"status": "encrypted", "device": "/dev/nvme0n1p3", "type": "luks2", "unlock": "tpm2+pin"})
        );
        let vols = f["volumes"].as_array().unwrap();
        assert_eq!(vols.len(), 4);
        assert_eq!(vols[0]["mountpoints"], json!(["/boot/efi"]));
        assert_eq!(vols[0]["status"], "unencrypted");
        assert_eq!(vols[2]["name"], "vg-root");
        assert_eq!(vols[2]["status"], "encrypted");
        assert_eq!(vols[3]["mountpoints"], json!(["[SWAP]"]));
    }

    #[test]
    fn luks_dump_variants() {
        assert_eq!(parse_luks_dump("Version: 1\nKey Slot 0: ENABLED\n"), ("luks1", "passphrase"));
        assert_eq!(parse_luks_dump("Version: 2\nTokens:\nDigests:\n"), ("luks2", "passphrase"));
        let tpm = "Version: 2\nTokens:\n  0: systemd-tpm2\n\ttpm2-pin:  false\nDigests:\n";
        assert_eq!(parse_luks_dump(tpm), ("luks2", "tpm2"));
        let fido = "Version: 2\nTokens:\n  0: systemd-fido2\n\tfido2-uv-required: false\nDigests:\n";
        assert_eq!(parse_luks_dump(fido), ("luks2", "fido2"));
        // A "tpm2-pin" key outside the tokens section is ignored.
        let other = "Version: 2\nConfig:\n\ttpm2-pin: true\nTokens:\n  0: systemd-recovery\nDigests:\n";
        assert_eq!(parse_luks_dump(other), ("luks2", "passphrase"));
    }

    #[test]
    fn missing_cryptsetup_degrades_type_and_unlock() {
        let r = root(&[]);
        let host = Host::fake(&r, FakeRunner::new().on(LSBLK_ARGS, 0, LSBLK_LUKS));
        let f = facts(&host);
        assert_eq!(f["root"]["status"], "encrypted");
        assert_eq!(f["root"]["type"], "unknown");
        assert_eq!(f["root"]["unlock"], "unknown");
    }

    #[test]
    fn unencrypted_root() {
        let r = root(&[]);
        let host = Host::fake(&r, FakeRunner::new().on(LSBLK_ARGS, 0, LSBLK_PLAIN));
        let f = facts(&host);
        assert_eq!(f["root"]["status"], "unencrypted");
        assert_eq!(f["root"]["device"], "/dev/sda1");
        assert_eq!(f["volumes"][0]["mountpoints"], json!(["/", "/var/snap"]));
    }

    #[test]
    fn missing_lsblk_is_unknown() {
        let r = root(&[]);
        let host = Host::fake(&r, FakeRunner::new());
        let f = facts(&host);
        assert_eq!(f["root"]["status"], "unknown");
        assert_eq!(f["volumes"], "unknown");
        assert_eq!(f["recovery"]["escrowed"], "unknown");
    }

    #[test]
    fn recovery_metadata_only() {
        let r = root(&[(
            ESCROW_FILE,
            r#"{"escrowed": true, "escrow_target": "vault", "last_rotated": "2026-10-01T00:00:00Z",
                "recovery_key": "SECRET-123456"}"#,
        )]);
        let host = Host::fake(&r, FakeRunner::new());
        let f = facts(&host);
        assert_eq!(
            f["recovery"],
            json!({"escrowed": true, "escrow_target": "vault", "last_rotated": "2026-10-01T00:00:00Z"})
        );
        assert!(!serde_json::to_string(&f).unwrap().contains("SECRET"));
    }

    #[test]
    fn actions_not_implemented() {
        let r = root(&[]);
        let host = Host::fake(&r, FakeRunner::new());
        let dry = ActionRequest { dry_run: true, ..Default::default() };
        for a in ["encryption.rotate-recovery-key", "encryption.escrow-now"] {
            let res = with_test_env(&host, |env| Encryption.run(env, a, &dry)).unwrap();
            assert_eq!(res.status, status::NOT_IMPLEMENTED);
        }
        assert!(with_test_env(&host, |env| Encryption.run(env, "encryption.x", &dry)).is_err());
        assert!(crate::provider::Registry::new(vec![new()]).is_ok());
    }
}
