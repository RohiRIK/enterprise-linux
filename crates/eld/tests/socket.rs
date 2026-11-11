//! End to end over a real Unix socket: peer credentials, routing, SSE.

use eld::audit::Auditor;
use eld::config::Config;
use eld::events::Bus;
use eld::server::Daemon;
use eld::store::Store;
use eld::sys::{FakeRunner, Host};
use eld_api::client::Client;
use serde_json::Value;
use std::os::unix::net::UnixListener;
use std::sync::Arc;

#[test]
fn serves_over_unix_socket() {
    let dir = std::env::temp_dir().join(format!("eld-socket-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("api.sock");
    let store = Arc::new(Store::memory());
    let audit = Arc::new(Auditor::memory());
    let cfg = Config::default();
    let reg = eld::registry(Arc::clone(&store), Arc::clone(&audit), &cfg).unwrap();
    let sys = Box::new(Host::fake(&dir, FakeRunner::new()));
    let d = Arc::new(Daemon::new(reg, store, audit, Arc::new(Bus::default()), cfg, sys));
    let listener = UnixListener::bind(&sock).unwrap();
    let d2 = Arc::clone(&d);
    std::thread::spawn(move || d2.serve(listener));

    let c = Client::new(&sock);
    let r = c.request("GET", "/v1/whoami", &[], None).unwrap();
    assert_eq!(r.status, 200);
    let who: Value = serde_json::from_slice(&r.body).unwrap();
    // SAFETY: getuid has no preconditions.
    let uid = unsafe { libc::getuid() };
    assert_eq!(who["uid"], uid);
    assert_eq!(who["pid"], std::process::id());

    let r = c.request("GET", "/v1/nope", &[], None).unwrap();
    assert_eq!(r.status, 404);

    if uid == 0 {
        d.emit("test.event", "info", None, Default::default());
        let mut got = vec![];
        c.stream("/v1/events?follow=true", |data| {
            got.push(data.to_string());
            !data.contains("test.event")
        })
        .unwrap();
        assert!(got.last().unwrap().contains("test.event"));
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Sam M1: the request deadline covers the whole request, so a client that
/// drips one byte at a time (each read well inside any per-read timeout)
/// is still cut off; and one uid cannot hold more than its share.
#[test]
fn slow_clients_are_cut_off_and_capped_per_uid() {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::time::{Duration, Instant};

    let dir = std::env::temp_dir().join(format!("eld-socket-slow-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("api.sock");
    let store = Arc::new(Store::memory());
    let audit = Arc::new(Auditor::memory());
    let cfg = Config::default();
    let reg = eld::registry(Arc::clone(&store), Arc::clone(&audit), &cfg).unwrap();
    let sys = Box::new(Host::fake(&dir, FakeRunner::new()));
    let mut d = Daemon::new(reg, store, audit, Arc::new(Bus::default()), cfg, sys);
    d.limits.request_deadline = Duration::from_millis(800);
    d.limits.per_uid = 2;
    // SAFETY: getuid has no preconditions.
    let uid = unsafe { libc::getuid() };
    if uid == 0 {
        // root has no per-uid cap: one reserved slot plus the general pool.
        d.limits.max_connections = 2;
        d.limits.reserved = 0;
        d.limits.root_reserved = 1;
    }
    let d = Arc::new(d);
    let listener = UnixListener::bind(&sock).unwrap();
    std::thread::spawn(move || d.serve(listener));

    // Two slow connections from this uid fill its share.
    let start = Instant::now();
    let mut slow: Vec<UnixStream> = (0..2).map(|_| UnixStream::connect(&sock).unwrap()).collect();
    for s in &mut slow {
        s.write_all(b"GET /v1/who").unwrap();
    }
    std::thread::sleep(Duration::from_millis(100));
    let mut third = UnixStream::connect(&sock).unwrap();
    third.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut buf = String::new();
    third.read_to_string(&mut buf).unwrap();
    assert!(buf.starts_with("HTTP/1.1 503"), "{buf}");

    // Keep dripping a byte every 200 ms; the deadline still ends it.
    let mut s = slow.remove(0);
    s.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
    let mut got = Vec::new();
    while start.elapsed() < Duration::from_secs(5) {
        let _ = s.write_all(b"a");
        let mut b = [0u8; 512];
        match s.read(&mut b) {
            Ok(0) => break,
            Ok(n) => got.extend_from_slice(&b[..n]),
            Err(_) => std::thread::sleep(Duration::from_millis(150)),
        }
    }
    let elapsed = start.elapsed();
    assert!(elapsed < Duration::from_secs(3), "slow client held a slot for {elapsed:?}");
    let got = String::from_utf8_lossy(&got);
    assert!(got.is_empty() || got.starts_with("HTTP/1.1 400"), "{got}");
    let _ = std::fs::remove_dir_all(&dir);
}
