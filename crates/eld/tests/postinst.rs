//! Runs the el-eld postinst sandbox test (packaging/deb/tests) so the
//! el-agent account checks (review M3, L-12c) are gated by `cargo test`.

use std::path::Path;
use std::process::Command;

#[test]
fn postinst_el_agent_checks() {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packaging/deb/tests/postinst-el-agent.sh");
    let out = Command::new("sh").arg(&script).output().expect("run sh");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{text}{}", String::from_utf8_lossy(&out.stderr));
    assert!(!text.contains("FAIL"), "{text}");
    assert!(text.matches("ok ").count() >= 10, "{text}");
}
