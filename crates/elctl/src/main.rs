//! `elctl`: the command-line client of the enterprise-linux control API.
//! Human output by default, `--json` / `--yaml` for machines, stable exit
//! codes (see [`exit`]).

mod format;

use eld_api::client::{Client, Response};
use eld_api::{result, status, ActionRequest};
use serde_json::{json, Value};
use std::io::Read;

/// Stable exit codes.
mod exit {
    pub const OK: i32 = 0;
    pub const ERROR: i32 = 1;
    pub const USAGE: i32 = 2;
    pub const FORBIDDEN: i32 = 3;
    /// Validation failed, a key was rejected, or an action failed.
    pub const REJECTED: i32 = 4;
    pub const UNREACHABLE: i32 = 5;
    pub const NOT_IMPLEMENTED: i32 = 6;
    pub const NOT_FOUND: i32 = 7;
    /// The settings changed since the given ETag.
    pub const STALE: i32 = 8;
}

const USAGE: &str = "usage: elctl [--json|--yaml] [--socket PATH] <command>

Facts
  facts get [NAMESPACE]              all namespaces, or one (--all is the default)
Settings (desired state)
  settings get [KEY]                 stored values, or one key
  settings set KEY VALUE             VALUE is JSON if it parses, else a string
  settings unset KEY
  settings apply -f FILE [--if-match ETAG]   apply a DevicePolicy (JSON; - for stdin)
  settings diff -f FILE              dry run of apply
Actions
  action list
  action run NAME [--PARAM VALUE ...] [--dry-run] [--confirm-token TOKEN]
Events
  events list [--since ID]
  events follow [--since ID]         stream, for EDR/SIEM
Other
  schema                             machine-readable settings and actions
  whoami                             your identity and roles as eld sees them

Exit codes: 0 ok, 1 error, 2 usage, 3 forbidden, 4 rejected/failed,
5 daemon unreachable, 6 not implemented, 7 not found, 8 stale ETag.";

/// Output format.
#[derive(Clone, Copy, PartialEq)]
pub enum Fmt {
    Human,
    Json,
    Yaml,
}

struct Ctx {
    client: Client,
    fmt: Fmt,
}

fn main() {
    std::process::exit(run(std::env::args().skip(1).collect()));
}

fn usage(msg: &str) -> i32 {
    eprintln!("elctl: {msg}\n\n{USAGE}");
    exit::USAGE
}

fn run(argv: Vec<String>) -> i32 {
    let mut fmt = Fmt::Human;
    let mut socket = std::env::var("ELD_SOCKET").unwrap_or_else(|_| eld_api::DEFAULT_SOCKET.into());
    let mut rest = vec![];
    let mut it = argv.into_iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--json" => fmt = Fmt::Json,
            "--yaml" => fmt = Fmt::Yaml,
            "--socket" => match it.next() {
                Some(s) => socket = s,
                None => return usage("--socket needs a path"),
            },
            "-h" | "--help" | "help" => {
                println!("{USAGE}");
                return exit::OK;
            }
            "--version" => {
                println!("elctl {}", env!("CARGO_PKG_VERSION"));
                return exit::OK;
            }
            _ => rest.push(a),
        }
    }
    let ctx = Ctx { client: Client::new(&socket), fmt };
    let words: Vec<&str> = rest.iter().map(String::as_str).collect();
    match words.as_slice() {
        ["facts", "get"] | ["facts", "get", "--all"] | ["facts"] => ctx.get("/v1/facts", format::facts),
        ["facts", "get", ns] => ctx.get(&format!("/v1/facts/{ns}"), format::facts),
        ["settings", "get"] | ["settings"] => ctx.get("/v1/settings", format::settings),
        ["settings", "get", key] => ctx.get(&format!("/v1/settings/{key}"), format::value),
        ["settings", "set", key, value] => {
            let v = serde_json::from_str(value).unwrap_or_else(|_| Value::String(value.to_string()));
            let body = json!({"settings": {*key: v}});
            ctx.send("PATCH", "/v1/settings", &[], Some(body), format::apply)
        }
        ["settings", "unset", key] => ctx.send("DELETE", &format!("/v1/settings/{key}"), &[], None, format::value),
        ["settings", verb @ ("apply" | "diff"), args @ ..] => ctx.apply(verb, args),
        ["action", "list"] | ["actions"] => ctx.get("/v1/actions", format::actions),
        ["action", "run", name, args @ ..] => ctx.action(name, args),
        ["events", "list", args @ ..] => match since(args) {
            Ok(s) => ctx.get(&format!("/v1/events?since={s}"), format::events),
            Err(e) => usage(&e),
        },
        ["events", "follow", args @ ..] => match since(args) {
            Ok(s) => ctx.follow(s),
            Err(e) => usage(&e),
        },
        ["schema"] => ctx.get("/v1/schema", format::value),
        ["whoami"] => ctx.get("/v1/whoami", format::whoami),
        [] => usage("missing command"),
        _ => usage(&format!("unknown command: {}", words.join(" "))),
    }
}

fn since(args: &[&str]) -> Result<u64, String> {
    match args {
        [] => Ok(0),
        ["--since", n] => n.parse().map_err(|_| format!("--since wants an event id, got {n}")),
        _ => Err(format!("unexpected arguments: {}", args.join(" "))),
    }
}

impl Ctx {
    fn get(&self, path: &str, human: fn(&Value) -> String) -> i32 {
        self.send("GET", path, &[], None, human)
    }

    fn send(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<Value>,
        human: fn(&Value) -> String,
    ) -> i32 {
        let bytes = body.map(|b| b.to_string().into_bytes());
        let resp = match self.client.request(method, path, headers, bytes.as_deref()) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("elctl: cannot reach eld at {}: {e}", self.client.socket.display());
                return exit::UNREACHABLE;
            }
        };
        self.print(resp, human)
    }

    fn print(&self, resp: Response, human: fn(&Value) -> String) -> i32 {
        let v: Value = serde_json::from_slice(&resp.body)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&resp.body).into()));
        if resp.status != 200 {
            let msg = v.get("message").and_then(Value::as_str).unwrap_or("request failed");
            match self.fmt {
                Fmt::Human => eprintln!("elctl: {msg}"),
                _ => self.emit(&v, human),
            }
            return match resp.status {
                400 => exit::REJECTED,
                403 => exit::FORBIDDEN,
                404 => exit::NOT_FOUND,
                412 => exit::STALE,
                _ => exit::ERROR,
            };
        }
        self.emit(&v, human);
        outcome(&v)
    }

    fn emit(&self, v: &Value, human: fn(&Value) -> String) {
        match self.fmt {
            Fmt::Json => println!("{}", serde_json::to_string_pretty(v).unwrap_or_default()),
            Fmt::Yaml => print!("{}", format::yaml(v)),
            Fmt::Human => print!("{}", human(v)),
        }
    }

    fn apply(&self, verb: &str, args: &[&str]) -> i32 {
        let mut file = None;
        let mut if_match = None;
        let mut i = 0;
        while i < args.len() {
            match (args[i], args.get(i + 1)) {
                ("-f" | "--file", Some(f)) => file = Some(*f),
                ("--if-match", Some(e)) => if_match = Some(*e),
                _ => return usage(&format!("unexpected argument {}", args[i])),
            }
            i += 2;
        }
        let Some(file) = file else { return usage("settings apply/diff need -f FILE") };
        let text = if file == "-" {
            let mut s = String::new();
            if let Err(e) = std::io::stdin().read_to_string(&mut s) {
                eprintln!("elctl: stdin: {e}");
                return exit::ERROR;
            }
            s
        } else {
            match std::fs::read_to_string(file) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("elctl: {file}: {e}");
                    return exit::ERROR;
                }
            }
        };
        let doc: Value = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("elctl: {file}: not valid JSON ({e}); YAML policy files are not supported yet");
                return exit::REJECTED;
            }
        };
        let headers: Vec<(&str, &str)> = if_match.map(|e| vec![("If-Match", e)]).unwrap_or_default();
        if verb == "diff" {
            self.send("POST", "/v1/settings/diff", &headers, Some(doc), format::apply)
        } else {
            self.send("PUT", "/v1/settings", &headers, Some(doc), format::apply)
        }
    }

    fn action(&self, name: &str, args: &[&str]) -> i32 {
        let mut req = ActionRequest::default();
        let mut i = 0;
        while i < args.len() {
            let a = args[i];
            match a {
                "--dry-run" => {
                    req.dry_run = true;
                    i += 1;
                    continue;
                }
                "--confirm-token" => match args.get(i + 1) {
                    Some(t) => req.confirm_token = Some(t.to_string()),
                    None => return usage("--confirm-token needs a value"),
                },
                _ => {
                    let Some(key) = a.strip_prefix("--") else { return usage(&format!("unexpected argument {a}")) };
                    // --key=value or --key value
                    if let Some((k, v)) = key.split_once('=') {
                        req.params.insert(k.into(), v.into());
                        i += 1;
                        continue;
                    }
                    match args.get(i + 1) {
                        Some(v) => {
                            req.params.insert(key.into(), v.to_string());
                        }
                        None => return usage(&format!("--{key} needs a value")),
                    }
                }
            }
            i += 2;
        }
        let body = serde_json::to_value(&req).unwrap_or_default();
        self.send("POST", &format!("/v1/actions/{name}"), &[], Some(body), format::action)
    }

    fn follow(&self, since: u64) -> i32 {
        let fmt = self.fmt;
        let res = self.client.stream(&format!("/v1/events?follow=true&since={since}"), |data| {
            match fmt {
                Fmt::Human => {
                    if let Ok(v) = serde_json::from_str::<Value>(data) {
                        print!("{}", format::events(&Value::Array(vec![v])));
                    }
                }
                // One JSON object per line for machine consumers.
                _ => println!("{data}"),
            }
            true
        });
        match res {
            Ok(200) => exit::OK,
            Ok(403) => {
                eprintln!("elctl: reading events requires role helpdesk or higher");
                exit::FORBIDDEN
            }
            Ok(s) => {
                eprintln!("elctl: unexpected status {s}");
                exit::ERROR
            }
            Err(e) => {
                eprintln!("elctl: cannot reach eld at {}: {e}", self.client.socket.display());
                exit::UNREACHABLE
            }
        }
    }
}

/// Exit code for a 200 response body.
fn outcome(v: &Value) -> i32 {
    if let Some(st) = v.get("status").and_then(Value::as_str) {
        if v.get("action").is_some() {
            return match st {
                status::OK | status::DRY_RUN => exit::OK,
                status::NOT_IMPLEMENTED => exit::NOT_IMPLEMENTED,
                _ => exit::REJECTED,
            };
        }
    }
    if let Some(rs) = v.get("results").and_then(Value::as_array) {
        if rs.iter().any(|r| r.get("result").and_then(Value::as_str) == Some(result::REJECTED)) {
            return exit::REJECTED;
        }
    }
    exit::OK
}
