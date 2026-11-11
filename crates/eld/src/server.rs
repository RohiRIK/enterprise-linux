//! Request routing and the socket loop. [`Daemon::handle`] is independent
//! of the transport so it can be tested without a socket.

use eld_api::{
    code, result, severity, status, ActionRequest, ApplyResponse, Caller, DevicePolicy, Event, Object, Role,
};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io::{BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use crate::audit::Auditor;
use crate::authz::{allowed, PeerCred, Resolver};
use crate::config::Config;
use crate::events::Bus;
use crate::http::{read_request, write_response, write_sse_head, Request, Response};
use crate::provider::{ActionError, Env, Registry};
use crate::settings::{flatten, plan, validate_policy};
use crate::store::{AppliedPolicy, CommitError, Store};
use crate::sys::System;

/// Namespaces whose fact reads are audited (recovery-key metadata).
const AUDITED_READS: &[&str] = &["encryption"];

/// Role needed to write settings.
const WRITE_ROLE: Role = Role::LocalAdmin;
/// Role needed to read the event stream.
const EVENTS_ROLE: Role = Role::Helpdesk;

/// Connection limits (review finding M1: one local user must not be able to
/// lock everyone else, the MDM agent and admins out of the API).
#[derive(Debug, Clone)]
pub struct Limits {
    /// Concurrent connections served in total; more get 503. Root is
    /// bounded by this alone.
    pub max_connections: usize,
    /// Slots kept back from ordinary users. Service principals (MDM/EDR
    /// agents, matched by uid) share these and can never hold more, so a
    /// compromised agent cannot starve root or users.
    pub reserved: usize,
    /// Concurrent connections per ordinary uid.
    pub per_uid: usize,
    /// Total time from accept to a fully read request (line, headers and
    /// body), not per read, so a client dripping bytes is cut off.
    pub request_deadline: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Limits { max_connections: 64, reserved: 8, per_uid: 8, request_deadline: Duration::from_secs(10) }
    }
}

/// Who a connection counts against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnClass {
    /// uid 0: only the total limit applies.
    Root,
    /// A service principal's uid: shares the reserved slots.
    Service,
    /// Everyone else: the unreserved slots, `per_uid` each.
    User,
}

/// Admission control for [`Limits`].
#[derive(Debug, Default)]
pub struct Slots {
    st: Mutex<SlotState>,
}

#[derive(Debug, Default)]
struct SlotState {
    total: usize,
    service: usize,
    users: usize,
    per_uid: HashMap<u32, usize>,
}

impl Slots {
    /// Takes a slot for `uid`, or says why not.
    pub fn acquire(&self, l: &Limits, uid: u32, class: ConnClass) -> Result<(), &'static str> {
        let mut s = self.st.lock().unwrap();
        if s.total >= l.max_connections {
            return Err("too many connections");
        }
        match class {
            ConnClass::Root => {}
            ConnClass::Service => {
                if s.service >= l.reserved {
                    return Err("too many connections from service principals");
                }
                s.service += 1;
            }
            ConnClass::User => {
                if s.users >= l.max_connections.saturating_sub(l.reserved) {
                    return Err("too many connections");
                }
                if s.per_uid.get(&uid).copied().unwrap_or(0) >= l.per_uid {
                    return Err("too many connections from this user");
                }
                s.users += 1;
                *s.per_uid.entry(uid).or_default() += 1;
            }
        }
        s.total += 1;
        Ok(())
    }

    /// Returns a slot taken by [`Slots::acquire`].
    pub fn release(&self, uid: u32, class: ConnClass) {
        let mut s = self.st.lock().unwrap();
        s.total = s.total.saturating_sub(1);
        match class {
            ConnClass::Root => {}
            ConnClass::Service => s.service = s.service.saturating_sub(1),
            ConnClass::User => {
                s.users = s.users.saturating_sub(1);
                if let Some(n) = s.per_uid.get_mut(&uid) {
                    *n -= 1;
                    if *n == 0 {
                        s.per_uid.remove(&uid);
                    }
                }
            }
        }
    }
}

/// Reads from the socket until an absolute deadline, re-arming the socket
/// timeout with the time left before every read.
struct DeadlineReader<'a> {
    s: &'a UnixStream,
    until: Instant,
}

impl Read for DeadlineReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let left = self.until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "request deadline exceeded"));
        }
        self.s.set_read_timeout(Some(left))?;
        let mut s = self.s;
        s.read(buf)
    }
}

/// What a handler produces.
pub enum Reply {
    Full(Response),
    /// Server-Sent Events: backlog, then live events.
    Stream(Vec<Event>, Receiver<Event>),
}

/// The daemon: registry, state and sinks.
pub struct Daemon {
    pub reg: Registry,
    pub store: Arc<Store>,
    pub audit: Arc<Auditor>,
    pub bus: Arc<Bus>,
    pub config: Config,
    pub sys: Box<dyn System>,
    pub limits: Limits,
    slots: Slots,
    destructive: Mutex<VecDeque<u64>>,
}

fn now() -> u64 {
    eld_api::time::unix(SystemTime::now())
}

fn forbidden(what: &str, need: Role) -> Response {
    Response::error(403, code::FORBIDDEN, format!("{what} requires role {need} or higher"))
}

impl Daemon {
    pub fn new(
        reg: Registry,
        store: Arc<Store>,
        audit: Arc<Auditor>,
        bus: Arc<Bus>,
        config: Config,
        sys: Box<dyn System>,
    ) -> Daemon {
        let mut config = config;
        // Pin service principals to local system uids (Sam M3).
        let read = |p: &str| sys.read_file(p).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default();
        let max = crate::config::sys_uid_max(&read("/etc/login.defs"));
        for w in config.pin_service_principals(&read("/etc/passwd"), max) {
            eprintln!("eld: {w}");
        }
        for w in crate::authz::unmatched_ref_warnings(&store) {
            eprintln!("eld: {w}");
        }
        Daemon {
            reg,
            store,
            audit,
            bus,
            config,
            sys,
            limits: Limits::default(),
            slots: Slots::default(),
            destructive: Mutex::new(VecDeque::new()),
        }
    }

    /// Resolves accept-time peer credentials into a caller.
    pub fn caller(&self, peer: &PeerCred) -> Caller {
        Resolver { sys: self.sys.as_ref(), config: &self.config, store: &self.store, now: now() }.resolve(peer)
    }

    /// Publishes an event and writes it to the audit log.
    pub fn emit(&self, kind: &str, sev: &str, actor: Option<&Caller>, data: Object) {
        self.audit.record(actor, "event", kind, "ok", data.clone());
        self.bus.publish(kind, sev, actor, data);
    }

    fn with_env<R>(&self, caller: Option<&Caller>, f: impl FnOnce(&Env) -> R) -> R {
        let setting = |k: &str| self.store.get(k).map(|v| v.value);
        let emit = |kind: &str, sev: &str, data: Object| self.emit(kind, sev, caller, data);
        // compliance reads other namespaces; it may not read itself.
        let facts = |ns: &str| if ns == "compliance" { Err("recursive read".to_string()) } else { self.facts(ns) };
        let env = Env { sys: self.sys.as_ref(), setting: &setting, emit: &emit, caller, facts: &facts, now: now() };
        f(&env)
    }

    /// Facts of one namespace.
    pub fn facts(&self, ns: &str) -> Result<Object, String> {
        let p = self.reg.provider(ns).ok_or_else(|| format!("unknown namespace {ns}"))?;
        self.with_env(None, |env| p.facts(env))
    }

    /// Routes one request.
    pub fn handle(&self, req: &Request, caller: &Caller) -> Reply {
        let path = req.path.trim_end_matches('/');
        let Some(rest) = path.strip_prefix("/v1") else {
            return Reply::Full(Response::error(404, code::NOT_FOUND, "unknown path; the API lives under /v1"));
        };
        let segs: Vec<&str> = rest.split('/').filter(|s| !s.is_empty()).collect();
        let m = req.method.as_str();
        Reply::Full(match (m, segs.as_slice()) {
            ("GET", ["whoami"]) => Response::json(200, caller),
            ("GET", ["schema"]) => self.schema(),
            ("GET", ["facts"]) => self.all_facts(caller),
            ("GET", ["facts", ns]) => self.ns_facts(ns, caller),
            ("GET", ["settings"]) => self.get_settings(),
            ("GET", ["settings", key]) => self.get_setting(key),
            ("PUT", ["settings"]) => self.put_policy(req, caller, req.flag("dryRun")),
            ("POST", ["settings", "diff"]) => self.put_policy(req, caller, true),
            ("PATCH", ["settings"]) => self.patch_settings(req, caller),
            ("DELETE", ["settings", key]) => self.delete_setting(key, req, caller),
            ("GET", ["actions"]) => Response::json(200, &self.reg.actions().collect::<Vec<_>>()),
            ("POST", ["actions", name]) => self.run_action(name, req, caller),
            ("GET", ["events"]) => {
                if !allowed(&caller.roles, EVENTS_ROLE) {
                    return Reply::Full(forbidden("reading events", EVENTS_ROLE));
                }
                let since = req.query.get("since").and_then(|s| s.parse().ok()).unwrap_or(0);
                if req.flag("follow") {
                    let (backlog, rx) = self.bus.subscribe(since);
                    return Reply::Stream(backlog, rx);
                }
                Response::json(200, &self.bus.since(since))
            }
            (_, ["whoami" | "schema" | "facts" | "settings" | "actions" | "events", ..]) => {
                Response::error(405, code::BAD_REQUEST, format!("{m} not allowed on {path}"))
            }
            _ => Response::error(404, code::NOT_FOUND, format!("no route for {m} {path}")),
        })
    }

    fn schema(&self) -> Response {
        Response::json(
            200,
            &json!({
                "apiVersion": eld_api::VERSION,
                "namespaces": self.reg.namespaces(),
                "settings": self.reg.settings().collect::<Vec<_>>(),
                "actions": self.reg.actions().collect::<Vec<_>>(),
                "policy": {"apiVersion": "enterprise-linux/v1", "kind": "DevicePolicy"},
                "endpoints": [
                    "GET /v1/whoami", "GET /v1/schema", "GET /v1/facts", "GET /v1/facts/{namespace}",
                    "GET /v1/settings", "GET /v1/settings/{key}", "PUT /v1/settings", "POST /v1/settings/diff",
                    "PATCH /v1/settings", "DELETE /v1/settings/{key}", "GET /v1/actions",
                    "POST /v1/actions/{name}", "GET /v1/events?since=&follow="
                ],
            }),
        )
    }

    fn all_facts(&self, caller: &Caller) -> Response {
        let nss = self.reg.namespaces();
        let results: Vec<(&str, Value)> = std::thread::scope(|s| {
            let handles: Vec<_> = nss
                .iter()
                .map(|ns| {
                    s.spawn(move || {
                        (
                            *ns,
                            match self.facts(ns) {
                                Ok(f) => Value::Object(f),
                                Err(e) => json!({"error": e}),
                            },
                        )
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().expect("fact provider panicked")).collect()
        });
        for ns in AUDITED_READS {
            if nss.contains(ns) {
                self.audit.record(Some(caller), "facts.read", ns, "ok", Object::new());
            }
        }
        Response::json(200, &results.into_iter().map(|(k, v)| (k.to_string(), v)).collect::<Object>())
    }

    fn ns_facts(&self, ns: &str, caller: &Caller) -> Response {
        if self.reg.provider(ns).is_none() {
            return Response::error(404, code::NOT_FOUND, format!("unknown namespace {ns}"));
        }
        if AUDITED_READS.contains(&ns) {
            self.audit.record(Some(caller), "facts.read", ns, "ok", Object::new());
        }
        match self.facts(ns) {
            Ok(f) => Response::json(200, &f),
            Err(e) => Response::error(500, code::INTERNAL, e),
        }
    }

    fn get_settings(&self) -> Response {
        let etag = self.store.etag();
        Response::json(
            200,
            &json!({
                "etag": etag,
                "policy": self.store.policy(),
                "values": self.store.all(),
            }),
        )
        .with_header("ETag", &etag)
    }

    fn get_setting(&self, key: &str) -> Response {
        let Some(spec) = self.reg.setting(key) else {
            return Response::error(404, code::NOT_FOUND, format!("unknown setting {key}"));
        };
        match self.store.get(key) {
            Some(v) => Response::json(200, &v),
            None => Response::json(200, &json!({"key": key, "value": spec.default, "source": "default"})),
        }
    }

    fn write_allowed(&self, caller: &Caller, target: &str) -> Option<Response> {
        if allowed(&caller.roles, WRITE_ROLE) {
            return None;
        }
        self.audit.record(Some(caller), "settings.write", target, "denied", Object::new());
        Some(forbidden("changing settings", WRITE_ROLE))
    }

    fn put_policy(&self, req: &Request, caller: &Caller, dry_run: bool) -> Response {
        if let Some(r) = self.write_allowed(caller, "policy") {
            return r;
        }
        let doc: DevicePolicy = match serde_json::from_slice(&req.body) {
            Ok(d) => d,
            Err(e) => return Response::error(400, code::BAD_REQUEST, format!("policy document: {e}")),
        };
        if let Err(e) = validate_policy(&doc) {
            return Response::error(400, code::BAD_REQUEST, e);
        }
        let values = flatten(&doc.spec);
        let policy = (!dry_run).then(|| doc.metadata.clone());
        self.write(req, caller, &values, true, dry_run, policy, &doc.metadata.name)
    }

    fn patch_settings(&self, req: &Request, caller: &Caller) -> Response {
        if let Some(r) = self.write_allowed(caller, "settings") {
            return r;
        }
        let body: Value = match serde_json::from_slice(&req.body) {
            Ok(v) => v,
            Err(e) => return Response::error(400, code::BAD_REQUEST, format!("body: {e}")),
        };
        let Some(map) = body.get("settings").and_then(Value::as_object) else {
            return Response::error(400, code::BAD_REQUEST, r#"body must be {"settings": {"key": value}}"#);
        };
        let values: BTreeMap<String, Value> = map.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        self.write(req, caller, &values, false, req.flag("dryRun"), None, "settings")
    }

    fn delete_setting(&self, key: &str, req: &Request, caller: &Caller) -> Response {
        if let Some(r) = self.write_allowed(caller, key) {
            return r;
        }
        let Some(cur) = self.store.get(key) else {
            return Response::error(404, code::NOT_FOUND, format!("{key} is not set"));
        };
        if cur.source.rank() > caller.source.rank() {
            return Response::error(409, code::CONFLICT, format!("{key} is set by {}", cur.source.as_str()));
        }
        let change = crate::store::Change { key: key.into(), value: None, source: caller.source, set_by: caller.who() };
        match self.store.commit(req.header("If-Match"), &[change], None) {
            Ok(etag) => {
                self.audit.record(
                    Some(caller),
                    "settings.write",
                    key,
                    "ok",
                    eld_api::Object::from_iter([("old".into(), cur.value)]),
                );
                Response::json(200, &json!({"key": key, "result": result::REMOVED, "etag": etag}))
                    .with_header("ETag", &etag)
            }
            Err(e) => commit_error(e),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn write(
        &self,
        req: &Request,
        caller: &Caller,
        values: &BTreeMap<String, Value>,
        full: bool,
        dry_run: bool,
        policy: Option<eld_api::PolicyMetadata>,
        target: &str,
    ) -> Response {
        let (results, changes) = plan(&self.reg, &self.store, caller, values, full);
        let rejected = results.iter().filter(|r| r.result == result::REJECTED).count();
        let mut etag = self.store.etag();
        if !dry_run {
            let applied = policy.as_ref().map(|meta| AppliedPolicy {
                meta: meta.clone(),
                source: caller.source,
                applied_at: eld_api::time::now_rfc3339(),
                status: if rejected == 0 { "applied" } else { "partial" }.into(),
            });
            match self.store.commit(req.header("If-Match"), &changes, applied) {
                Ok(e) => etag = e,
                Err(e) => return commit_error(e),
            }
            if changes.iter().any(|c| c.key.starts_with("roles.")) {
                for w in crate::authz::unmatched_ref_warnings(&self.store) {
                    eprintln!("eld: {w}");
                }
            }
            let detail = json!({"results": results, "dryRun": false});
            self.audit.record(Some(caller), "settings.write", target, "ok", crate::provider::obj(detail));
            for r in results.iter().filter(|r| r.result == result::REJECTED && r.reason.starts_with("set by")) {
                self.emit(
                    "settings.conflict",
                    severity::WARNING,
                    Some(caller),
                    crate::provider::obj(json!({"key": r.key, "reason": r.reason})),
                );
            }
            if let Some(meta) = &policy {
                self.emit(
                    "policy.applied",
                    severity::INFO,
                    Some(caller),
                    crate::provider::obj(json!({"name": meta.name, "version": meta.version, "rejected": rejected})),
                );
            } else if !changes.is_empty() {
                self.emit(
                    "settings.changed",
                    severity::INFO,
                    Some(caller),
                    crate::provider::obj(json!({"keys": changes.iter().map(|c| &c.key).collect::<Vec<_>>()})),
                );
            }
        }
        Response::json(200, &ApplyResponse { dry_run, policy, results, etag: etag.clone() }).with_header("ETag", &etag)
    }

    fn rate_limited(&self) -> bool {
        let now = now();
        let mut q = self.destructive.lock().unwrap();
        while q.front().is_some_and(|t| now - *t >= 60) {
            q.pop_front();
        }
        if q.len() >= self.config.destructive_per_minute as usize {
            return true;
        }
        q.push_back(now);
        false
    }

    fn run_action(&self, name: &str, req: &Request, caller: &Caller) -> Response {
        let Some((spec, provider)) = self.reg.action(name) else {
            return Response::error(404, code::NOT_FOUND, format!("unknown action {name}"));
        };
        if !allowed(&caller.roles, spec.min_role) {
            self.audit.record(Some(caller), "action.run", name, "denied", Object::new());
            return forbidden(name, spec.min_role);
        }
        let areq: ActionRequest = if req.body.iter().all(u8::is_ascii_whitespace) {
            ActionRequest::default()
        } else {
            match serde_json::from_slice(&req.body) {
                Ok(r) => r,
                Err(e) => return Response::error(400, code::BAD_REQUEST, format!("body: {e}")),
            }
        };
        if spec.destructive && !areq.dry_run && self.rate_limited() {
            return Response::error(429, code::TOO_MANY, "too many destructive actions; try again in a minute");
        }
        let out = self.with_env(Some(caller), |env| provider.run(env, name, &areq));
        let detail = crate::provider::obj(json!({"params": areq.params, "dryRun": areq.dry_run}));
        match out {
            Ok(res) => {
                self.audit.record(Some(caller), "action.run", name, &res.status, detail);
                if !areq.dry_run && res.status != status::NOT_IMPLEMENTED {
                    self.emit(
                        "action.completed",
                        severity::INFO,
                        Some(caller),
                        crate::provider::obj(json!({"action": name, "status": res.status})),
                    );
                }
                Response::json(200, &res)
            }
            Err(e) => {
                let (st, c, msg) = match e {
                    ActionError::BadRequest(m) => (400, code::BAD_REQUEST, m),
                    ActionError::Forbidden(m) => (403, code::FORBIDDEN, m),
                    ActionError::Unknown(m) => (404, code::NOT_FOUND, format!("unknown action {m}")),
                };
                self.audit.record(Some(caller), "action.run", name, if st == 403 { "denied" } else { "error" }, detail);
                Response::error(st, c, msg)
            }
        }
    }

    /// Drops expired JIT grants and announces them.
    pub fn expire_grants(&self) {
        match self.store.expire_grants(now()) {
            Ok(gs) => {
                for g in gs {
                    self.emit(
                        "roles.expired",
                        severity::INFO,
                        None,
                        crate::provider::obj(json!({"user": g.user, "role": g.role})),
                    );
                }
            }
            Err(e) => eprintln!("eld: expiring grants: {e}"),
        }
    }

    /// Which connection limits apply to `uid`.
    pub fn conn_class(&self, uid: u32) -> ConnClass {
        if uid == 0 {
            ConnClass::Root
        } else if self.config.service_principals.iter().any(|sp| sp.uid == Some(uid)) {
            ConnClass::Service
        } else {
            ConnClass::User
        }
    }

    /// Serves one connection: authenticate, read, route, reply.
    pub fn serve_conn(&self, stream: UnixStream) {
        let until = Instant::now() + self.limits.request_deadline;
        let Some(peer) = peer_cred(&stream) else { return };
        self.serve_peer(stream, &peer, until);
    }

    fn serve_peer(&self, stream: UnixStream, peer: &PeerCred, until: Instant) {
        // Resolve roles now, from the credentials the kernel recorded at
        // connect(), before the client sends a single byte (Sam H1).
        let caller = self.caller(peer);
        let mut w = match stream.try_clone() {
            Ok(w) => w,
            Err(_) => return,
        };
        let _ = w.set_write_timeout(Some(Duration::from_secs(30)));
        let req = match read_request(&mut BufReader::new(DeadlineReader { s: &stream, until })) {
            Ok(r) => r,
            Err(resp) => {
                let _ = write_response(&mut w, &resp);
                return;
            }
        };
        match self.handle(&req, &caller) {
            Reply::Full(resp) => {
                let _ = write_response(&mut w, &resp);
            }
            Reply::Stream(backlog, rx) => {
                if write_sse_head(&mut w).is_err() {
                    return;
                }
                let send = |w: &mut UnixStream, e: &Event| {
                    let data = serde_json::to_string(e).unwrap_or_default();
                    write!(w, "id: {}\nevent: {}\ndata: {data}\n\n", e.id, e.kind).and_then(|_| w.flush())
                };
                for e in &backlog {
                    if send(&mut w, e).is_err() {
                        return;
                    }
                }
                loop {
                    match rx.recv_timeout(Duration::from_secs(15)) {
                        Ok(e) => {
                            if send(&mut w, &e).is_err() {
                                return;
                            }
                        }
                        // Keepalive comment; also detects closed clients.
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                            if w.write_all(b": keepalive\n\n").and_then(|_| w.flush()).is_err() {
                                return;
                            }
                        }
                        Err(_) => return,
                    }
                }
            }
        }
    }

    /// Accept loop: one thread per connection, bounded in total and per
    /// uid, with slots reserved for root and service principals.
    pub fn serve(self: Arc<Self>, listener: UnixListener) {
        for conn in listener.incoming() {
            let Ok(stream) = conn else { continue };
            let until = Instant::now() + self.limits.request_deadline;
            let Some(peer) = peer_cred(&stream) else { continue };
            let class = self.conn_class(peer.uid);
            if let Err(why) = self.slots.acquire(&self.limits, peer.uid, class) {
                let mut s = stream;
                let _ = s.set_write_timeout(Some(Duration::from_secs(1)));
                let _ = write_response(&mut s, &Response::error(503, code::INTERNAL, why));
                continue;
            }
            let d = Arc::clone(&self);
            std::thread::spawn(move || {
                d.serve_peer(stream, &peer, until);
                d.slots.release(peer.uid, class);
            });
        }
    }
}

fn commit_error(e: CommitError) -> Response {
    match e {
        CommitError::Stale { current } => {
            Response::error(412, code::PRECONDITION, format!("settings changed; current ETag is {current}"))
                .with_header("ETag", &current)
        }
        CommitError::Io(m) => Response::error(500, code::INTERNAL, m),
    }
}

// asm-generic values (x86_64, aarch64, riscv64, ...); libc does not export
// them for every target.
const SO_PEERSEC: libc::c_int = 31;
const SO_PEERGROUPS: libc::c_int = 59;

/// Peer credentials of a connected Unix socket, as the kernel recorded them
/// at `connect()`: `SO_PEERCRED` (uid, gid, pid), `SO_PEERGROUPS`
/// (supplementary groups, Linux >= 4.13) and `SO_PEERSEC` (LSM label).
/// If the groups cannot be read the caller gets its primary gid only, which
/// fails closed.
pub fn peer_cred(s: &UnixStream) -> Option<PeerCred> {
    use std::os::fd::AsRawFd;
    let fd = s.as_raw_fd();
    let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: cred and len are valid for writes and sized for SO_PEERCRED.
    let rc = unsafe {
        libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_PEERCRED, (&mut cred as *mut libc::ucred).cast(), &mut len)
    };
    if rc != 0 {
        return None;
    }
    Some(PeerCred {
        uid: cred.uid,
        gid: cred.gid,
        pid: cred.pid,
        groups: peer_groups(fd).unwrap_or_default(),
        label: peer_label(fd),
    })
}

fn peer_groups(fd: std::os::fd::RawFd) -> Option<Vec<u32>> {
    const GID: usize = std::mem::size_of::<libc::gid_t>();
    let mut n = 64usize;
    loop {
        let mut buf: Vec<libc::gid_t> = vec![0; n];
        let mut len = (n * GID) as libc::socklen_t;
        // SAFETY: buf holds n gid_t values and len is its size in bytes.
        let rc = unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, SO_PEERGROUPS, buf.as_mut_ptr().cast(), &mut len) };
        if rc == 0 {
            buf.truncate(len as usize / GID);
            return Some(buf);
        }
        // ERANGE: len now holds the size needed (NGROUPS_MAX is 65536).
        let need = len as usize / GID;
        if std::io::Error::last_os_error().raw_os_error() == Some(libc::ERANGE) && need > n && need <= 65536 {
            n = need;
            continue;
        }
        return None;
    }
}

fn peer_label(fd: std::os::fd::RawFd) -> String {
    let mut buf = vec![0u8; 4096];
    let mut len = buf.len() as libc::socklen_t;
    // SAFETY: buf is valid for len bytes.
    let rc = unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, SO_PEERSEC, buf.as_mut_ptr().cast(), &mut len) };
    if rc != 0 {
        return String::new();
    }
    buf.truncate(len as usize);
    String::from_utf8_lossy(&buf).trim_end_matches(['\0', '\n']).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::{FakeRunner, Host};
    use eld_api::Source;

    fn daemon() -> Daemon {
        let store = Arc::new(Store::memory());
        let audit = Arc::new(Auditor::memory());
        let cfg = Config { destructive_per_minute: 1, ..Config::default() };
        let reg = crate::registry(Arc::clone(&store), Arc::clone(&audit), &cfg).unwrap();
        let root = std::env::temp_dir().join("eld-server-test-empty-root");
        let sys = Box::new(Host::fake(root, FakeRunner::new()));
        Daemon::new(reg, store, audit, Arc::new(Bus::default()), cfg, sys)
    }

    fn caller(user: &str, roles: &[Role], source: Source) -> Caller {
        Caller {
            uid: 1000,
            gid: 1000,
            pid: 1,
            user: user.into(),
            label: String::new(),
            roles: roles.to_vec(),
            source,
            principal: String::new(),
        }
    }

    fn req(method: &str, path: &str, body: Value) -> Request {
        let (path, qs) = path.split_once('?').unwrap_or((path, ""));
        let mut r = Request { method: method.into(), path: path.into(), ..Default::default() };
        for p in qs.split('&').filter(|p| !p.is_empty()) {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            r.query.insert(k.into(), v.into());
        }
        if !body.is_null() {
            r.body = body.to_string().into_bytes();
        }
        r
    }

    fn call(d: &Daemon, r: Request, c: &Caller) -> (u16, Value) {
        match d.handle(&r, c) {
            Reply::Full(resp) => (resp.status, serde_json::from_slice(&resp.body).unwrap()),
            Reply::Stream(..) => panic!("unexpected stream"),
        }
    }

    fn policy(ring: &str) -> Value {
        json!({
            "apiVersion": "enterprise-linux/v1",
            "kind": "DevicePolicy",
            "metadata": {"name": "p", "version": "1"},
            "spec": {"updates": {"ring": ring}}
        })
    }

    /// Sam H1: groups are captured from the socket itself at accept.
    #[test]
    fn peer_cred_captures_groups_at_accept() {
        let (a, _b) = UnixStream::pair().unwrap();
        let p = peer_cred(&a).unwrap();
        // SAFETY: plain libc getters with valid buffers.
        let (uid, gid, mut want) = unsafe {
            let n = libc::getgroups(0, std::ptr::null_mut());
            let mut g: Vec<libc::gid_t> = vec![0; n.max(0) as usize];
            let n = libc::getgroups(n, g.as_mut_ptr());
            g.truncate(n.max(0) as usize);
            (libc::getuid(), libc::getgid(), g)
        };
        assert_eq!((p.uid, p.gid, p.pid), (uid, gid, std::process::id() as i32));
        let mut got = p.groups.clone();
        got.sort_unstable();
        want.sort_unstable();
        assert_eq!(got, want);
    }

    /// Sam M1: one uid's connections cannot starve another uid, and the
    /// reserved slots stay open for root and the MDM uid.
    #[test]
    fn one_uid_cannot_starve_others() {
        use ConnClass::*;
        let l = Limits::default();
        let s = Slots::default();
        for _ in 0..l.per_uid {
            s.acquire(&l, 1000, User).unwrap();
        }
        assert_eq!(s.acquire(&l, 1000, User), Err("too many connections from this user"));
        s.acquire(&l, 1001, User).unwrap();
        // Many attacker uids fill every unreserved slot...
        let mut uid = 2000;
        while s.acquire(&l, uid, User).is_ok() {
            uid += 1;
        }
        assert_eq!(s.acquire(&l, 5000, User), Err("too many connections"));
        // ...but root and the MDM agent still get in.
        s.acquire(&l, 0, Root).unwrap();
        s.acquire(&l, 990, Service).unwrap();
        s.release(1000, User);
        s.acquire(&l, 1000, User).unwrap();
    }

    /// Service principals share the reserved slots and cannot exceed them,
    /// so a compromised agent cannot starve root; root is bounded only by
    /// the total.
    #[test]
    fn service_principals_capped_root_is_not() {
        use ConnClass::*;
        let l = Limits::default();
        let s = Slots::default();
        for i in 0..l.reserved {
            s.acquire(&l, 990 + (i as u32 % 2), Service).unwrap();
        }
        assert_eq!(s.acquire(&l, 990, Service), Err("too many connections from service principals"));
        assert_eq!(s.acquire(&l, 991, Service), Err("too many connections from service principals"));
        // Root fills everything that is left, past any per-uid or reserved cap.
        for _ in l.reserved..l.max_connections {
            s.acquire(&l, 0, Root).unwrap();
        }
        assert_eq!(s.acquire(&l, 0, Root), Err("too many connections"));
        s.release(990, Service);
        s.acquire(&l, 990, Service).unwrap();
    }

    #[test]
    fn connection_classes() {
        let mut d = daemon();
        d.config.service_principals.push(crate::config::ServicePrincipal {
            name: "mdm".into(),
            user: String::new(),
            uid: Some(990),
            role: Role::SvcMdm,
        });
        assert_eq!(d.conn_class(0), ConnClass::Root);
        assert_eq!(d.conn_class(990), ConnClass::Service);
        assert_eq!(d.conn_class(1000), ConnClass::User);
    }

    #[test]
    fn users_cannot_write_settings() {
        let d = daemon();
        let u = caller("alice", &[Role::User], Source::User);
        let (st, _) = call(&d, req("PUT", "/v1/settings", policy("pilot")), &u);
        assert_eq!(st, 403);
        let (st, _) = call(&d, req("PATCH", "/v1/settings", json!({"settings": {"updates.ring": "pilot"}})), &u);
        assert_eq!(st, 403);
        assert!(d.audit.recent(10).iter().any(|r| r["outcome"] == "denied"));
    }

    #[test]
    fn mdm_takes_precedence_over_local_admin() {
        let d = daemon();
        let mdm = Caller { principal: "intune".into(), ..caller("mdm", &[Role::SvcMdm], Source::Mdm) };
        let admin = caller("root", &[Role::LocalAdmin], Source::LocalAdmin);
        let (st, v) = call(&d, req("PUT", "/v1/settings", policy("pilot")), &mdm);
        assert_eq!(st, 200);
        assert_eq!(v["results"][0]["result"], "applied");
        let (_, v) = call(&d, req("PATCH", "/v1/settings", json!({"settings": {"updates.ring": "canary"}})), &admin);
        assert_eq!(v["results"][0]["result"], "rejected");
        assert!(d.bus.since(0).iter().any(|e| e.kind == "settings.conflict"));
        let (st, _) = call(&d, req("DELETE", "/v1/settings/updates.ring", Value::Null), &admin);
        assert_eq!(st, 409);
        let (_, v) = call(&d, req("GET", "/v1/facts/policy", Value::Null), &admin);
        assert_eq!(v["name"], "p");
        assert_eq!(v["source"], "mdm");
    }

    #[test]
    fn dry_run_and_stale_etag() {
        let d = daemon();
        let admin = caller("root", &[Role::LocalAdmin], Source::LocalAdmin);
        let (_, v) = call(&d, req("POST", "/v1/settings/diff", policy("pilot")), &admin);
        assert_eq!(v["dryRun"], true);
        assert!(d.store.get("updates.ring").is_none());
        let mut r = req("PUT", "/v1/settings", policy("pilot"));
        r.headers.push(("If-Match".into(), "\"r99\"".into()));
        assert_eq!(call(&d, r, &admin).0, 412);
        let (st, _) = call(&d, req("PUT", "/v1/settings", json!({"kind": "Nope"})), &admin);
        assert_eq!(st, 400);
    }

    #[test]
    fn action_authorization() {
        let d = daemon();
        let u = caller("alice", &[Role::User], Source::User);
        let hd = caller("bob", &[Role::User, Role::Helpdesk], Source::User);
        assert_eq!(call(&d, req("POST", "/v1/actions/device.reboot", json!({"dryRun": true})), &u).0, 403);
        assert_eq!(call(&d, req("POST", "/v1/actions/nope.nope", Value::Null), &hd).0, 404);
        let (st, v) = call(&d, req("POST", "/v1/actions/device.lock", json!({"dryRun": true})), &hd);
        assert_eq!(st, 200);
        assert_eq!(v["status"], "dry-run");
    }

    /// Sam M2: helpdesk never grants roles on its own initiative; it can
    /// only approve another user's pending request.
    #[test]
    fn helpdesk_cannot_grant_only_approve() {
        let d = daemon();
        let alice = caller("alice", &[Role::User], Source::User);
        let hd = Caller { uid: 1001, ..caller("bob", &[Role::User, Role::Helpdesk], Source::User) };
        let hd2 = Caller { uid: 1002, ..caller("carol", &[Role::User, Role::Helpdesk], Source::User) };
        let admin = Caller { uid: 0, ..caller("root", &[Role::LocalAdmin], Source::LocalAdmin) };
        let run = |name: &str, body: Value, c: &Caller| call(&d, req("POST", &format!("/v1/actions/{name}"), body), c);
        let grant = |user: &str, role: &str| json!({"params": {"user": user, "role": role, "for": "30m"}});

        // Direct grants: refused for helpdesk, for any role and any target.
        for role in ["local-admin", "helpdesk", "power-user"] {
            assert_eq!(run("roles.grant-temporary", grant("alice", role), &hd).0, 403);
            assert_eq!(run("roles.grant-temporary", grant("carol", role), &hd).0, 403);
        }
        assert!(d.store.active_grants(now()).is_empty());

        // Approving something nobody asked for does nothing.
        let approve = |user: &str, role: &str| json!({"params": {"user": user, "role": role}});
        assert_eq!(run("roles.approve", approve("carol", "local-admin"), &hd).0, 400);
        assert!(d.store.active_grants(now()).is_empty());

        // A user asks; helpdesk approves; the grant carries the request.
        let ask = json!({"params": {"role": "local-admin", "for": "30m", "ticket": "INC-1"}});
        assert_eq!(run("roles.request-temporary", ask.clone(), &alice).0, 200);
        assert_eq!(run("roles.approve", approve("alice", "local-admin"), &hd).0, 200);
        let gs = d.store.active_grants(now());
        assert_eq!((gs.len(), gs[0].user.as_str(), gs[0].ticket.as_str()), (1, "alice", "INC-1"));
        // The request is consumed.
        assert_eq!(run("roles.approve", approve("alice", "local-admin"), &hd2).0, 400);

        // Nobody approves their own request.
        assert_eq!(run("roles.request-temporary", ask, &hd2).0, 200);
        assert_eq!(run("roles.approve", approve("carol", "local-admin"), &hd2).0, 403);

        // Local admins may still grant directly, never to themselves; limits hold.
        assert_eq!(run("roles.grant-temporary", grant("dave", "helpdesk"), &admin).0, 200);
        assert_eq!(run("roles.grant-temporary", grant("root", "helpdesk"), &admin).0, 403);
        let long = json!({"params": {"user": "alice", "role": "local-admin", "for": "48h"}});
        assert_eq!(run("roles.grant-temporary", long, &admin).0, 400);
        let big = json!({"params": {"role": "helpdesk", "for": "5m", "reason": "x".repeat(300)}});
        assert_eq!(run("roles.request-temporary", big, &alice).0, 400);
    }

    #[test]
    fn destructive_actions_are_rate_limited() {
        let d = daemon();
        let mdm = caller("mdm", &[Role::SvcMdm], Source::Mdm);
        let body = json!({"confirmToken": "t"});
        let (st, v) = call(&d, req("POST", "/v1/actions/device.wipe", body.clone()), &mdm);
        assert_eq!(st, 200);
        assert_eq!(v["status"], "not-implemented");
        assert_eq!(call(&d, req("POST", "/v1/actions/device.wipe", body), &mdm).0, 429);
    }

    #[test]
    fn events_need_helpdesk() {
        let d = daemon();
        let u = caller("alice", &[Role::User], Source::User);
        let hd = caller("bob", &[Role::Helpdesk], Source::User);
        assert_eq!(call(&d, req("GET", "/v1/events", Value::Null), &u).0, 403);
        assert_eq!(call(&d, req("GET", "/v1/events", Value::Null), &hd).0, 200);
        assert!(matches!(d.handle(&req("GET", "/v1/events?follow=true", Value::Null), &hd), Reply::Stream(..)));
    }

    #[test]
    fn routes_and_schema() {
        let d = daemon();
        let u = caller("alice", &[Role::User], Source::User);
        let (st, v) = call(&d, req("GET", "/v1/schema", Value::Null), &u);
        assert_eq!(st, 200);
        assert!(v["namespaces"].as_array().unwrap().len() >= 13);
        assert_eq!(call(&d, req("GET", "/v1/facts", Value::Null), &u).0, 200);
        assert_eq!(call(&d, req("GET", "/v1/facts/nope", Value::Null), &u).0, 404);
        assert_eq!(call(&d, req("DELETE", "/v1/facts", Value::Null), &u).0, 405);
        assert_eq!(call(&d, req("GET", "/v2/facts", Value::Null), &u).0, 404);
        let (_, v) = call(&d, req("GET", "/v1/settings/updates.ring", Value::Null), &u);
        assert_eq!(v["source"], "default");
    }

    #[test]
    fn example_policy_applies_cleanly() {
        let d = daemon();
        let mdm = caller("mdm", &[Role::SvcMdm], Source::Mdm);
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/policy.json");
        let doc: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let (st, v) = call(&d, req("PUT", "/v1/settings", doc), &mdm);
        assert_eq!(st, 200);
        let rejected: Vec<_> = v["results"].as_array().unwrap().iter().filter(|r| r["result"] != "applied").collect();
        assert!(rejected.is_empty(), "{rejected:?}");
    }
}
