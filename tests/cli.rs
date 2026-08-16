use std::path::PathBuf;
use std::process::Command;

/// Both suites are shell scripts, because what they test is a program's
/// behaviour at its edges: streams, exit codes, and files.
fn run(script: &str, beb: Option<PathBuf>) {
    let path = format!("{}/tests/{script}", env!("CARGO_MANIFEST_DIR"));
    let mut cmd = Command::new("bash");
    cmd.arg(&path).env("BEB_DEPOT_BIN", env!("CARGO_BIN_EXE_beb-depot"));
    if let Some(beb) = beb {
        cmd.env("BEB_BIN", beb);
    }
    let out = cmd.output().unwrap_or_else(|e| panic!("run {script}: {e}"));
    print!("{}", String::from_utf8_lossy(&out.stdout));
    eprint!("{}", String::from_utf8_lossy(&out.stderr));
    assert!(out.status.success(), "{script} failed");
}

#[test]
fn e2e() {
    run("e2e.sh", None);
}

/// The joint with beb, which neither repository's own suite covers. It
/// needs a beb to test against; a sibling checkout is where it lives
/// during development, and the script skips if there is none anywhere.
/// The depot behind a real sshd. Skips where none can be started; the
/// environment a forced command gets is not something a stub can model,
/// and this is the suite that found it.
#[test]
fn sshd() {
    run("sshd.sh", None);
}

#[test]
fn roundtrip() {
    let sibling = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(|p| p.join("beb/target/release/beb"))
        .filter(|p| p.is_file());
    run("roundtrip.sh", sibling);
}
