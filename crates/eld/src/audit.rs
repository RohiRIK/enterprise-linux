//! Structured audit records: who, which client process, what, old -> new,
//! result. Written as JSON lines to a file and, when enabled, to journald
//! with a stable `MESSAGE_ID` (`docs/CONTROL-API.md` §5).

use eld_api::{time, Caller, Object};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::fs::File;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixDatagram;
use std::sync::Mutex;

/// journald `MESSAGE_ID` of every eld audit record.
pub const MESSAGE_ID: &str = "3f1c5a2e8b7d4e0c9a6b1d2e3f4a5b6c";

/// Records kept in memory for `audit.export`.
const RECENT: usize = 1000;

/// The audit sink.
pub struct Auditor {
    file: Mutex<Option<File>>,
    journald: Option<UnixDatagram>,
    recent: Mutex<VecDeque<Value>>,
}

impl Auditor {
    /// Opens the configured sinks. An empty path disables the file sink.
    pub fn open(path: &str, journald: bool) -> Result<Auditor, String> {
        let file = if path.is_empty() {
            None
        } else {
            if let Some(dir) = std::path::Path::new(path).parent() {
                std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
            }
            Some(
                std::fs::OpenOptions::new()
                    .append(true)
                    .create(true)
                    .mode(0o600)
                    .open(path)
                    .map_err(|e| format!("{path}: {e}"))?,
            )
        };
        let journald = journald
            .then(|| UnixDatagram::unbound().ok())
            .flatten()
            .filter(|s| s.connect("/run/systemd/journal/socket").is_ok());
        Ok(Auditor { file: Mutex::new(file), journald, recent: Mutex::new(VecDeque::new()) })
    }

    /// A sink that only keeps records in memory (tests).
    pub fn memory() -> Auditor {
        Auditor { file: Mutex::new(None), journald: None, recent: Mutex::new(VecDeque::new()) }
    }

    /// Writes one record. `op` is e.g. `settings.write`, `action.run`.
    pub fn record(&self, caller: Option<&Caller>, op: &str, target: &str, outcome: &str, detail: Object) {
        let rec = json!({
            "time": time::now_rfc3339(),
            "op": op,
            "target": target,
            "polkitAction": crate::authz::polkit_action(op, target),
            "outcome": outcome,
            "caller": caller,
            "detail": detail,
        });
        self.write(rec, if outcome == "denied" { 4 } else { 6 });
    }

    fn write(&self, rec: Value, priority: u8) {
        let line = rec.to_string();
        if let Some(f) = self.file.lock().unwrap().as_mut() {
            let _ = writeln!(f, "{line}");
        }
        if let Some(sock) = &self.journald {
            // Native protocol: newline-separated KEY=value fields. The JSON
            // line contains no raw newlines.
            let msg = format!(
                "MESSAGE_ID={MESSAGE_ID}\nSYSLOG_IDENTIFIER=eld\nPRIORITY={priority}\nMESSAGE=eld audit {} {}\nELD_AUDIT={line}\n",
                rec["op"].as_str().unwrap_or(""),
                rec["target"].as_str().unwrap_or("")
            );
            let _ = sock.send(msg.as_bytes());
        }
        let mut recent = self.recent.lock().unwrap();
        if recent.len() == RECENT {
            recent.pop_front();
        }
        recent.push_back(rec);
    }

    /// The most recent `n` records, oldest first.
    pub fn recent(&self, n: usize) -> Vec<Value> {
        let r = self.recent.lock().unwrap();
        r.iter().skip(r.len().saturating_sub(n)).cloned().collect()
    }
}
