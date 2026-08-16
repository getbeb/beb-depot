use std::process::Command;

/// The end-to-end suite is a shell script, because what it tests is a
/// program's behaviour at its edges: streams, exit codes, and files.
#[test]
fn e2e() {
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/e2e.sh");
    let bin = env!("CARGO_BIN_EXE_beb-depot");
    let out = Command::new("bash")
        .arg(script)
        .env("BEB_DEPOT_BIN", bin)
        .output()
        .expect("run e2e.sh");
    print!("{}", String::from_utf8_lossy(&out.stdout));
    eprint!("{}", String::from_utf8_lossy(&out.stderr));
    assert!(out.status.success(), "e2e.sh failed");
}
