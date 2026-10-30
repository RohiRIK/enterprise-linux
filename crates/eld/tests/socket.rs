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
