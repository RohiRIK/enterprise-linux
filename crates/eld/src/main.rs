//! `eld` entry point: load config, open state, bind the socket, serve.

use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use eld::audit::Auditor;
use eld::config::Config;
use eld::events::Bus;
use eld::server::Daemon;
use eld::store::Store;
use eld::sys::Host;

const USAGE: &str = "usage: eld [--config PATH] [--socket PATH] [--state-dir DIR] [--audit-log PATH] [--no-journald]

The enterprise-linux control daemon. Serves the control API on a Unix socket
(default /run/eld/api.sock). Normally started by systemd (eld.service).";

fn main() {
    if let Err(e) = run() {
        eprintln!("eld: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let mut config_path = "/etc/eld/eld.json".to_string();
    let mut overrides: Vec<(String, String)> = vec![];
    let mut no_journald = false;
    while let Some(a) = args.next() {
        match a.as_str() {
            "-h" | "--help" => {
                println!("{USAGE}");
                return Ok(());
            }
            "--version" => {
                println!("eld {}", env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            "--no-journald" => no_journald = true,
            "--config" | "--socket" | "--state-dir" | "--audit-log" => {
                let v = args.next().ok_or_else(|| format!("{a} needs a value\n{USAGE}"))?;
                if a == "--config" {
                    config_path = v;
                } else {
                    overrides.push((a, v));
                }
            }
            _ => return Err(format!("unknown argument {a}\n{USAGE}")),
        }
    }
    let mut cfg = Config::load(Path::new(&config_path))?;
    for (k, v) in overrides {
        match k.as_str() {
            "--socket" => cfg.socket = v,
            "--state-dir" => cfg.state_dir = v,
            _ => cfg.audit_log = v,
        }
    }
    if no_journald {
        cfg.journald = false;
    }

    let store = Arc::new(Store::open(&cfg.state_dir)?);
    let audit = Arc::new(Auditor::open(&cfg.audit_log, cfg.journald)?);
    let reg = eld::registry(Arc::clone(&store), Arc::clone(&audit), &cfg)?;
    let listener = bind(&cfg.socket)?;
    eprintln!("eld {} listening on {}", env!("CARGO_PKG_VERSION"), cfg.socket);

    let daemon = Arc::new(Daemon::new(reg, store, audit, Arc::new(Bus::default()), cfg, Box::new(Host::new())));
    daemon.emit("daemon.started", eld_api::severity::INFO, None, Default::default());
    let d = Arc::clone(&daemon);
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(30));
        d.expire_grants();
    });
    daemon.serve(listener);
    Ok(())
}

/// Binds the socket, replacing a stale one. Every local user may connect:
/// authorization is per request from peer credentials.
fn bind(path: &str) -> Result<UnixListener, String> {
    let p = Path::new(path);
    if let Some(dir) = p.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    match std::fs::symlink_metadata(p) {
        Ok(m) if m.file_type().is_socket() => std::fs::remove_file(p).map_err(|e| format!("{path}: {e}"))?,
        Ok(_) => return Err(format!("{path} exists and is not a socket")),
        Err(_) => {}
    }
    let l = UnixListener::bind(p).map_err(|e| format!("{path}: {e}"))?;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o666)).map_err(|e| format!("{path}: {e}"))?;
    Ok(l)
}
