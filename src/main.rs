//! beb-depot: a place beb mail waits when two machines cannot reach
//! each other.
//!
//! It runs no beb, parses no frame, and verifies no signature. sshd
//! decides who is calling; this decides where the bytes go.

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, ErrorKind, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{ExitCode, Stdio};
use std::time::Duration;

const DIR_MODE: u32 = 0o700;
const FILE_MODE: u32 = 0o600;

/// A frame larger than this is refused before a byte of it is stored.
/// Not a knob: any connecting courier may drop for any allowed
/// recipient, so disk has to be bounded by policy rather than by trust.
/// beb bodies are uncapped by design, which is a promise beb can make
/// about its own disk and this cannot make about somebody else's.
const FRAME_MAX: u64 = 64 * 1024 * 1024;

/// What one recipient may keep waiting, and for how long.
///
/// The frame ceiling bounds a single mistake. These bound a persistent
/// one, which is the case a depot left running unattended actually
/// meets: a courier that never comes back, or a sender in a loop. Two
/// caps rather than one because the two ways to fill a disk are not the
/// same shape -- many small frames exhaust a directory, and an
/// operator's patience, long before they exhaust the space.
///
/// Not knobs, for the same reason FRAME_MAX is not one. A depot cannot
/// tell a mistake from an attack, so this is the one place it is allowed
/// an opinion, and an opinion every deployment states differently is not
/// an opinion.
const HOLD_MAX_ITEMS: usize = 10_000;
const HOLD_MAX_BYTES: u64 = 1024 * 1024 * 1024;

/// After this, nobody is coming back for it.
///
/// Expiry runs on traffic rather than on a timer, because a depot has no
/// process of its own: every connection is one sshd child that exits. So
/// a drop, a pickup, and `held` each sweep what they touch. A queue
/// nothing ever touches is the case this misses, and it is also the case
/// where those frames are the only thing there.
const HOLD_MAX_AGE: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// How often a blocked `pickup` looks again.
///
/// A poll, and deliberately. The two intents run in different processes
/// -- sshd spawns one per connection -- so the only thing a drop and a
/// waiting pickup share is this filesystem, and something has to notice.
/// A kernel watch would notice instantly; this notices within a quarter
/// second, on a directory that is normally empty.
///
/// It is cheap because the expensive thing is already paid for. The
/// alternative is the client reconnecting to ask, and one ssh handshake
/// to this depot measured 1250ms against 0.02ms for the directory read.
/// Polling inside a held connection and polling by reconnecting are the
/// same word for two things five orders of magnitude apart.
const POLL: Duration = Duration::from_millis(250);

struct Fail {
    code: u8,
    msg: String,
}

fn refused(msg: impl Into<String>) -> Fail {
    Fail { code: 3, msg: msg.into() }
}

impl From<String> for Fail {
    fn from(msg: String) -> Fail {
        Fail { code: 1, msg }
    }
}

impl From<&str> for Fail {
    fn from(msg: &str) -> Fail {
        Fail { code: 1, msg: msg.to_string() }
    }
}

const USAGE: &str = "\
beb-depot {version} holds beb mail for keys that read somewhere else.

  beb-depot authorize KEYFILE [RECIPIENT...]
      let that courier in, and let it collect for those recipients
  beb-depot serve [--root PATH] FINGERPRINT
      answer one connection; sshd runs this as a forced command
  beb-depot allow FINGERPRINT RECIPIENT
      one more recipient for a courier already let in
  beb-depot held
      what is waiting, and for whom
  beb-depot status
      whether the lines sshd reads still describe this depot

  beb-depot --help
  beb-depot --version

A RECIPIENT is a queue name, 64 lowercase hex, or the path to a beb
identity's public key file, which this converts to one. A KEYFILE is a
courier's public key, or \"-\" for stdin; its fingerprint is derived,
never typed. If it is what beb-courier whoami printed, it names its own
recipients and you need give none.

Exit: 0 did it, 1 change the command, 2 nothing to do, 3 refused.

It holds at most 64 MiB per frame, and per recipient 10000 frames or
1 GiB, whichever comes first. Anything that has waited more than 30
days is dropped, swept by whatever touches the queue next.

BEB_DEPOT_ROOT names where it keeps things. It defaults to
~/.local/share/beb-depot, and holds:

  allowed                    one \"FINGERPRINT RECIPIENT\" line each
  inbox/<recipient>/<id>     one whole frame per file

BEB_DEPOT_AUTHORIZED_KEYS names the file authorize writes. It defaults
to ~/.ssh/authorized_keys, and gains one line per courier:

  command=\"'/path/to/beb-depot' serve --root '/path' SHA256:...\",restrict ssh-...

That fingerprint is the depot's whole notion of who is calling, which
is why authorize derives it from the key file rather than asking.";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let r = match args.first().map(String::as_str) {
        Some("serve") => cmd_serve(&args[1..]),
        Some("authorize") => cmd_authorize(&args[1..]),
        Some("allow") => cmd_allow(&args[1..]),
        Some("held") => cmd_held(&args[1..]),
        Some("status") => cmd_status(&args[1..]),
        Some("--help") | Some("-h") | None => {
            println!("{}", USAGE.replace("{version}", env!("CARGO_PKG_VERSION")));
            return ExitCode::SUCCESS;
        }
        Some("--version") => {
            println!("beb-depot {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        Some(other) => Err(format!("no such command \"{other}\"; beb-depot --help lists them").into()),
    };
    match r {
        Ok(()) => ExitCode::SUCCESS,
        Err(f) => {
            note(&f.msg);
            ExitCode::from(f.code)
        }
    }
}

/// Everything said about a result, never the result itself: prose on
/// stderr with a prefix, so a client reading stdout gets frames and
/// nothing else.
fn note(msg: &str) {
    let _ = io::stdout().flush();
    let mut err = io::stderr().lock();
    for line in msg.lines() {
        let _ = writeln!(err, "beb-depot: {line}");
    }
}

fn root() -> Result<PathBuf, String> {
    if let Some(r) = std::env::var_os("BEB_DEPOT_ROOT").filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(r));
    }
    let home = std::env::var_os("HOME")
        .filter(|v| !v.is_empty())
        .ok_or("no HOME and no BEB_DEPOT_ROOT; one of them has to say where to keep things")?;
    Ok(PathBuf::from(home).join(".local/share/beb-depot"))
}

fn private_dir_all(p: &Path) -> io::Result<()> {
    fs::create_dir_all(p)?;
    fs::set_permissions(p, fs::Permissions::from_mode(DIR_MODE))
}

fn private_file(p: &Path) -> io::Result<File> {
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(FILE_MODE)
        .open(p)
}

fn fsync_dir(d: &Path) -> io::Result<()> {
    File::open(d)?.sync_all()
}

/// A recipient is a beb mailbox name: the 32 raw ed25519 key bytes in
/// hex. On a connection the depot never derives it, the courier passes
/// it, and this checks the shape because it becomes a directory name.
/// An operator may hand `authorize` the key file instead and have it
/// derived, which is a convenience at the desk and never on the wire.
fn valid_recipient(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn valid_fingerprint(s: &str) -> bool {
    s.starts_with("SHA256:")
        && s.len() > 8
        && !s.contains(char::is_whitespace)
        && !s.contains('\n')
}

// ---- what a courier may collect for ------------------------------------

/// The allow list, one `FINGERPRINT RECIPIENT` line each.
///
/// A flat file on purpose: an operator adds a courier to `authorized_keys`
/// by hand already, and this is the same act at the same moment. It is
/// also greppable, which a directory of encoded names would not be --
/// a fingerprint holds `/` and `+` and cannot be a filename as it stands.
fn allowed_path(root: &Path) -> PathBuf {
    root.join("allowed")
}

fn allowed_for(root: &Path, fp: &str) -> Vec<String> {
    let text = fs::read_to_string(allowed_path(root)).unwrap_or_default();
    text.lines()
        .filter_map(|l| {
            let mut f = l.split_whitespace();
            let (who, what) = (f.next()?, f.next()?);
            (who == fp && valid_recipient(what)).then(|| what.to_string())
        })
        .collect()
}

fn cmd_allow(args: &[String]) -> Result<(), Fail> {
    let (fp, to) = match args {
        [fp, to] => (fp.as_str(), to.as_str()),
        _ => {
            return Err("allow takes a fingerprint and a recipient: \
                        beb-depot allow FINGERPRINT RECIPIENT"
                .into())
        }
    };
    if !valid_fingerprint(fp) {
        return Err(format!("\"{fp}\" is not a fingerprint; ssh-keygen -lf prints one as SHA256:...").into());
    }
    let to = &as_recipient(to)?;
    let root = root()?;
    if !grant(&root, fp, to)? {
        return Err(Fail { code: 2, msg: format!("{fp} could already collect for {to}") });
    }
    note(&format!("{fp} may now collect for {to}"));
    Ok(())
}

/// Write one grant. `false` means it was already there, which is the
/// only reason two verbs can write this file: adding a line that exists
/// is not an event, so `authorize` can re-run over a courier that has
/// gained one recipient without arguing about the others.
fn grant(root: &Path, fp: &str, to: &str) -> Result<bool, String> {
    private_dir_all(root).map_err(|e| format!("cannot create {}: {e}", root.display()))?;
    if allowed_for(root, fp).iter().any(|r| r == to) {
        return Ok(false);
    }
    let path = allowed_path(root);
    let mut text = fs::read_to_string(&path).unwrap_or_default();
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
    text.push_str(&format!("{fp} {to}\n"));
    let tmp = path.with_extension("tmp");
    private_file(&tmp)
        .and_then(|mut f| f.write_all(text.as_bytes()).and_then(|_| f.sync_all()))
        .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    fs::rename(&tmp, &path).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    fsync_dir(root).map_err(|e| format!("cannot sync {}: {e}", root.display()))?;
    Ok(true)
}

// ---- letting a courier in ----------------------------------------------

/// Where sshd looks. Overridable because a depot is sometimes not the
/// account you are logged in as, and because a test must never write to
/// the real one.
fn authorized_keys_path() -> Result<PathBuf, String> {
    if let Some(p) = std::env::var_os("BEB_DEPOT_AUTHORIZED_KEYS").filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(p));
    }
    let home = std::env::var_os("HOME")
        .filter(|v| !v.is_empty())
        .ok_or_else(|| "HOME is not set, so there is no ~/.ssh/authorized_keys to write".to_string())?;
    Ok(PathBuf::from(home).join(".ssh/authorized_keys"))
}

/// The one line sshd needs, written rather than dictated.
///
/// The fingerprint in that line is the depot's entire notion of who is
/// calling, and until now an operator typed it twice: once here and
/// once into `allowed`. Two hand-copies of the same 43 base64
/// characters, in two files, that must agree -- and when they disagree
/// nothing detects it, because from the depot's side the fingerprint is
/// the truth. One courier silently collects another's mail.
///
/// gitolite solved this by never letting an operator write the line at
/// all: it generates authorized_keys from a directory where the
/// filename is the user. Same idea, smaller: derive the fingerprint
/// from the key file, write both places in one act, and the operator
/// never transcribes it. What is left for a human is the decision --
/// this key, these recipients -- which is the part a human should have.
fn cmd_authorize(args: &[String]) -> Result<(), Fail> {
    let (keyfile, given) = match args {
        [k, rest @ ..] => (Path::new(k.as_str()), rest),
        _ => {
            return Err("authorize takes a courier's key file, and the recipients it \
                        collects for: beb-depot authorize KEYFILE [RECIPIENT...]"
                .into())
        }
    };
    // A handover file carries both: beb-courier whoami prints the key
    // first and the queue names after it, so that the two facts travel
    // together to a machine the courier was built to be unable to reach.
    // Naming recipients on the command line still works, and adds to
    // whatever the file already said.
    let handover = read_handover(keyfile)?;
    let carried = handover.recipients;
    if given.is_empty() && carried.is_empty() {
        return Err(refused(format!(
            "{} names no recipients, and none were given\n\
             beb-courier whoami prints a file that carries them, or name them here",
            keyfile.display()
        )));
    }
    let recipients: Vec<String> = given.to_vec();
    // Everything is resolved before anything is written: a half-authorized
    // courier is a key that can connect and collect nothing, which looks
    // like a depot fault rather than a typo.
    let mut recipients: Vec<String> = recipients
        .iter()
        .map(|r| as_recipient(r))
        .collect::<Result<_, _>>()?;
    for c in carried {
        if !recipients.contains(&c) {
            recipients.push(c);
        }
    }
    let key = handover.key;
    let fp = fingerprint_of(keyfile, &key)?;
    let exe = shell_word(&forced_command_binary()?)?;
    // Resolved now, absolute, and written into the line: whatever root
    // this operator is granting in is the root the connection will serve
    // from, whether or not anything is set in the environment then.
    let root = root()?;
    private_dir_all(&root).map_err(|e| format!("cannot create {}: {e}", root.display()))?;
    let abs = fs::canonicalize(&root)
        .map_err(|e| Fail::from(format!("cannot resolve {}: {e}", root.display())))?;
    let rootword = shell_word(&abs.to_string_lossy())?;
    let line = format!("command=\"{exe} serve --root {rootword} {fp}\",restrict {key}");

    let ak = authorized_keys_path()?;
    let existing = fs::read_to_string(&ak).unwrap_or_default();
    // The bug this verb exists to prevent, caught rather than created:
    // the key is already in there under somebody else's fingerprint.
    let blob = key.split_whitespace().nth(1).unwrap_or_default();
    for (i, l) in existing.lines().enumerate() {
        if l.contains(blob) && !l.contains(fp.as_str()) {
            return Err(refused(format!(
                "line {} of {} already has this key, under a different command:\n  {}\n\
                 that line decides who the depot thinks is calling; fix or remove it first",
                i + 1,
                ak.display(),
                l.trim()
            )));
        }
    }
    // Matched on the fingerprint alone, never on the whole command: the
    // command gained --root once already, and a line that stops matching
    // when the format shifts is a line that gets silently written twice.
    let keyed = existing.lines().any(|l| l.contains(fp.as_str()));
    if !keyed {
        append_line(&ak, &line)?;
    }

    let mut added = Vec::new();
    for to in &recipients {
        if grant(&root, &fp, to)? {
            added.push(to.as_str());
        }
    }

    // stdout carries the line, so it can be piped to a depot elsewhere
    // even when this run had nothing of its own to write.
    println!("{line}");
    if keyed && added.is_empty() {
        return Err(Fail {
            code: 2,
            msg: format!("{fp} was already authorized for all {} recipients", recipients.len()),
        });
    }
    if !keyed {
        note(&format!("added {} to {}", fp, ak.display()));
    }
    match added.len() {
        0 => note(&format!("{fp} could already collect for every one of those")),
        1 => note(&format!("{fp} may now collect for {}", added[0])),
        n => note(&format!("{fp} may now collect for {n} recipients")),
    }
    if !keyed {
        note("sshd needs no reload; it reads authorized_keys on each connection");
    }
    Ok(())
}

/// A recipient, from either of the two things an operator has to hand.
///
/// The queue name is 32 raw ed25519 bytes in hex, and until now it was
/// the one argument here a human still had to produce by decoding a
/// base64 blob themselves -- the same transcription hazard `authorize`
/// exists to remove, left sitting in the other half of the command. beb
/// prints the key; this turns the key into the queue.
fn as_recipient(arg: &str) -> Result<String, Fail> {
    if valid_recipient(arg) {
        return Ok(arg.to_string());
    }
    let p = Path::new(arg);
    if p.is_file() {
        return recipient_of(p);
    }
    Err(refused(format!(
        "\"{arg}\" is neither a recipient nor a public key file\n\
         a recipient is 64 lowercase hex characters; a key file is the .pub of a \
         beb identity, whose contents beb whoami prints"
    )))
}

/// The queue a beb identity reads from: the key bytes, not the key text.
///
/// Derived the same way beb names the mailbox -- the second string of
/// the ssh wire encoding, which for ed25519 is exactly the 32 bytes.
fn recipient_of(p: &Path) -> Result<String, Fail> {
    let key = read_handover(p)?.key;
    let mut f = key.split_whitespace();
    let kind = f.next().unwrap_or_default().to_string();
    let blob = f.next().unwrap_or_default();
    let bytes =
        b64(blob).ok_or_else(|| refused(format!("{}: the key is not base64", p.display())))?;
    let raw = ssh_string(&bytes, 0)
        .and_then(|(t, at)| ssh_string(&bytes, at).map(|(k, _)| (t, k)))
        .filter(|(t, k)| *t == b"ssh-ed25519".as_slice() && k.len() == 32)
        .map(|(_, k)| k);
    match raw {
        Some(k) => Ok(k.iter().map(|b| format!("{b:02x}")).collect()),
        None => Err(refused(format!(
            "{} is a {kind} key; a beb identity is ed25519, and its queue name is \
             those 32 key bytes in hex",
            p.display()
        ))),
    }
}

/// Enough base64 to read one ssh public key. Written out rather than
/// depended on: the depot has one dependency, and this is nine lines.
fn b64(s: &str) -> Option<Vec<u8>> {
    let (mut out, mut acc, mut bits) = (Vec::new(), 0u32, 0u32);
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            _ => return None,
        } as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

/// One length-prefixed string of the ssh wire encoding, and where the
/// next one starts.
fn ssh_string(b: &[u8], at: usize) -> Option<(&[u8], usize)> {
    let n = u32::from_be_bytes(b.get(at..at + 4)?.try_into().ok()?) as usize;
    let (s, e) = (at + 4, (at + 4).checked_add(n)?);
    Some((b.get(s..e)?, e))
}

/// A courier's key and the queues it collects for, from one read.
///
/// One read and not two, so the path may be a pipe. `beb-depot
/// authorize /dev/stdin` is then the whole of the depot's side, which
/// matters because a handover always arrives from a machine the depot
/// cannot reach: the alternative is a copy, a chown, and a leftover
/// file to remember to remove.
///
/// A bare `.pub` is the same thing with no queue names in it.
struct Handover {
    key: String,
    recipients: Vec<String>,
}

fn read_handover(p: &Path) -> Result<Handover, Fail> {
    // "-" is the descriptor already open, not the path /dev/stdin.
    //
    // They are not the same thing where it matters. A depot account is
    // reached through another login -- ssh in as somebody who may become
    // it -- and `su` changes uid, after which re-opening /dev/stdin is
    // EACCES on a pipe the first user owns. The inherited descriptor
    // stays readable, so this reads that:
    //
    //   ssh depot "su -s /bin/sh beb -c 'beb-depot authorize -'" < x
    let dash = p == Path::new("-");
    let name = if dash { "the handover on stdin".to_string() } else { p.display().to_string() };
    let text = if dash {
        let mut s = String::new();
        io::stdin()
            .read_to_string(&mut s)
            .map_err(|e| Fail::from(format!("cannot read {name}: {e}")))?;
        s
    } else {
        fs::read_to_string(p).map_err(|e| Fail::from(format!("cannot read {name}: {e}")))?
    };
    if text.contains("PRIVATE KEY") {
        return Err(refused(format!(
            "{name} is a private key; authorize takes the public half, usually the same name with .pub"
        )));
    }
    let (mut keys, mut recipients) = (Vec::new(), Vec::new());
    for l in text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        if valid_recipient(l) {
            recipients.push(l.to_string());
        } else {
            keys.push(l);
        }
    }
    let key = match keys.as_slice() {
        [one] => *one,
        [] => return Err(refused(format!("{name} holds no key"))),
        many => {
            return Err(refused(format!(
                "{name} holds {} keys; authorize takes one, so that one line names one courier",
                many.len()
            )))
        }
    };
    let mut f = key.split_whitespace();
    let kind = f.next().unwrap_or_default();
    if f.next().is_none() || !(kind.starts_with("ssh-") || kind.starts_with("ecdsa-sha2-") || kind.starts_with("sk-")) {
        return Err(refused(format!(
            "{name} does not look like a public key; expected a line beginning ssh-ed25519, ssh-rsa, or similar"
        )));
    }
    Ok(Handover { key: key.to_string(), recipients })
}

/// ssh-keygen's answer, not ours. Computing a fingerprint here would
/// mean owning a second opinion about what sshd will compute, and the
/// only opinion that matters is sshd's.
fn fingerprint_of(p: &Path, key: &str) -> Result<String, Fail> {
    // The key text, not the path: the path may have been a pipe, and a
    // pipe read twice is empty the second time. ssh-keygen takes "-" for
    // stdin, so it still computes the fingerprint rather than this doing
    // it, which keeps the one opinion that matters sshd's.
    let mut child = std::process::Command::new("ssh-keygen")
        .arg("-lf")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| Fail::from(format!("cannot run ssh-keygen: {e}")))?;
    child
        .stdin
        .take()
        .expect("stdin piped")
        .write_all(format!("{key}\n").as_bytes())
        .map_err(|e| format!("cannot write to ssh-keygen: {e}"))?;
    let out = child
        .wait_with_output()
        .map_err(|e| Fail::from(format!("cannot run ssh-keygen: {e}")))?;
    if !out.status.success() {
        return Err(refused(format!(
            "ssh-keygen will not read {}: {}",
            p.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let fp = text.split_whitespace().nth(1).unwrap_or_default().to_string();
    if !valid_fingerprint(&fp) {
        return Err(format!("ssh-keygen printed no fingerprint for {}", p.display()).into());
    }
    Ok(fp)
}

/// This binary, by absolute path. A forced command runs with no useful
/// PATH, and naming the binary that wrote the line is the only way the
/// line stays true when a depot is installed somewhere unusual.
fn forced_command_binary() -> Result<String, Fail> {
    let exe = std::env::current_exe()
        .map_err(|e| Fail::from(format!("cannot find my own path: {e}")))?;
    Ok(exe.to_string_lossy().to_string())
}

/// One argument of the forced command, safe for the shell sshd hands it
/// to. `command="..."` is not the end of the quoting: sshd runs the
/// string through the login shell, so a path with a space in it becomes
/// two arguments unless something says otherwise.
fn shell_word(s: &str) -> Result<String, Fail> {
    if s.contains('\'') || s.contains('"') || s.contains('\\') || s.contains('\n') {
        return Err(refused(format!(
            "{s} cannot go in a forced command; a quote or a backslash in the path \
             would end the line early. move it somewhere plainer"
        )));
    }
    Ok(format!("'{s}'"))
}

/// Appended, never rewritten. authorized_keys is a file sshd depends on
/// and other things edit; replacing it wholesale to add one line risks
/// losing whatever arrived in between, and this verb's whole purpose is
/// to be the safe way to touch it.
fn append_line(p: &Path, line: &str) -> Result<(), Fail> {
    // Created if missing, and never chmodded if not. The parent here is
    // somebody else's directory -- ~/.ssh, or a home -- unlike every
    // other directory this program makes. Setting 700 on one that
    // already existed changed the mode of a depot account's home the
    // first time it was pointed anywhere but ~/.ssh, and would have
    // tried it on /tmp.
    if let Some(d) = p.parent() {
        if !d.as_os_str().is_empty() && !d.is_dir() {
            private_dir_all(d)
                .map_err(|e| Fail::from(format!("cannot create {}: {e}", d.display())))?;
        }
    }
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(FILE_MODE)
        .open(p)
        .map_err(|e| Fail::from(format!("cannot open {}: {e}", p.display())))?;
    // A file that does not end in a newline would otherwise gain a line
    // that is the tail of the previous one, and sshd would read neither.
    let needs_nl = fs::metadata(p).map(|m| m.len() > 0).unwrap_or(false)
        && !fs::read_to_string(p).unwrap_or_default().ends_with('\n');
    let text = if needs_nl { format!("\n{line}\n") } else { format!("{line}\n") };
    f.write_all(text.as_bytes())
        .and_then(|_| f.sync_all())
        .map_err(|e| Fail::from(format!("cannot write {}: {e}", p.display())))?;
    Ok(())
}

// ---- storage -----------------------------------------------------------

fn inbox(root: &Path, to: &str) -> PathBuf {
    root.join("inbox").join(to)
}

fn name(id: u64) -> String {
    format!("{id:018}")
}

/// Ids present in one recipient's inbox, ascending.
fn ids(dir: &Path) -> Vec<u64> {
    let mut out: Vec<u64> = match fs::read_dir(dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().to_str().and_then(|s| s.parse().ok()))
            .collect(),
        Err(_) => Vec::new(),
    };
    out.sort_unstable();
    out
}

// ---- serve: one connection ---------------------------------------------

/// sshd runs this, with the connecting courier's fingerprint already in
/// the command line. So the depot never decides who is calling: sshd
/// decided, and the caller cannot change a word of it.
///
/// The intent arrives in SSH_ORIGINAL_COMMAND, which is whatever the
/// client asked for and is therefore never trusted for anything but
/// which branch to take.
fn cmd_serve(args: &[String]) -> Result<(), Fail> {
    // sshd runs a forced command with none of the operator's environment,
    // so a depot whose root came from BEB_DEPOT_ROOT would serve out of
    // ~/.local/share/beb-depot and find no grants at all -- silently,
    // because an empty allow list and a wrong allow list look the same
    // from here. The line carries the root so the environment cannot
    // disagree with it.
    let (given, fp) = match args {
        [flag, path, fp] if flag == "--root" => (Some(PathBuf::from(path)), fp.as_str()),
        [fp] => (None, fp.as_str()),
        _ => {
            return Err("serve takes the connecting fingerprint: \
                        beb-depot serve [--root PATH] FINGERPRINT"
                .into())
        }
    };
    if !valid_fingerprint(fp) {
        return Err(format!("\"{fp}\" is not a fingerprint").into());
    }
    let root = match given {
        Some(r) => r,
        None => root()?,
    };
    let asked = std::env::var("SSH_ORIGINAL_COMMAND").unwrap_or_default();
    let mut words = asked.split_whitespace();
    match (words.next(), words.next(), words.next()) {
        (Some("drop"), Some(to), None) => do_drop(&root, fp, to),
        (Some("pickup"), None, None) => do_pickup(&root, fp, true),
        (Some("drain"), None, None) => do_pickup(&root, fp, false),
        _ => Err(refused(
            "say drop <recipient>, pickup, or drain; nothing else is served here",
        )),
    }
}

/// Read one frame from stdin and file it. The recipient is an argument,
/// never a field read out of the bytes: a depot that parsed a frame to
/// route it would be a depot that has to understand beb's format, and
/// then two programs would own that format instead of one.
fn do_drop(root: &Path, fp: &str, to: &str) -> Result<(), Fail> {
    if !valid_recipient(to) {
        return Err(refused(format!("\"{to}\" is not a recipient")));
    }
    // Anyone this depot serves may drop for anyone it holds for. What it
    // will not do is invent a queue: a recipient nobody may collect for has
    // nobody to collect it, so the frame would sit forever.
    if !allowed_line_exists(root, to) {
        return Err(refused(format!(
            "nobody collects for {to} here; an operator allows it with: beb-depot allow <fingerprint> {to}"
        )));
    }
    let dir = inbox(root, to);
    private_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;

    // Make room before deciding there is none: a queue full of frames
    // nobody came back for should not refuse the one arriving now.
    let q = sweep(&dir);
    swept(to, &q);

    let (items, bytes) = (q.items, q.bytes);
    if items >= HOLD_MAX_ITEMS {
        return Err(refused(format!(
            "{to} is holding {items} frames, which is the cap; \
             nothing more until a courier collects"
        )));
    }
    if bytes >= HOLD_MAX_BYTES {
        return Err(refused(format!(
            "{to} is holding {bytes} bytes, which is the cap of {HOLD_MAX_BYTES}; \
             nothing more until a courier collects"
        )));
    }

    let tmp = dir.join(format!(".tmp-{}", std::process::id()));
    let written = {
        let mut f = private_file(&tmp).map_err(|e| format!("cannot write: {e}"))?;
        let mut input = io::stdin().lock().take(FRAME_MAX + 1);
        let n = io::copy(&mut input, &mut f).map_err(|e| format!("cannot read the frame: {e}"))?;
        f.sync_all().map_err(|e| format!("cannot sync: {e}"))?;
        n
    };
    if written == 0 || written > FRAME_MAX {
        let _ = fs::remove_file(&tmp);
        return Err(refused(if written == 0 {
            "an empty frame is not a delivery".to_string()
        } else {
            format!("frame over {FRAME_MAX} bytes")
        }));
    }
    // The size was not knowable before reading it, so the byte cap is
    // checked once more now that it is. Refusing here costs a write that
    // is then thrown away, which is the price of not trusting a length
    // the sender would otherwise have to declare.
    if bytes + written > HOLD_MAX_BYTES {
        let _ = fs::remove_file(&tmp);
        return Err(refused(format!(
            "{to} is holding {bytes} bytes and this frame is {written} more, \
             over the cap of {HOLD_MAX_BYTES}; nothing more until a courier collects"
        )));
    }

    let id = next_id(&dir)?;
    fs::rename(&tmp, dir.join(name(id))).map_err(|e| format!("cannot place: {e}"))?;
    fsync_dir(&dir).map_err(|e| format!("cannot sync: {e}"))?;
    note(&format!("held {id} for {to}, {written} bytes, from {fp}"));
    Ok(())
}

fn allowed_line_exists(root: &Path, to: &str) -> bool {
    fs::read_to_string(allowed_path(root))
        .unwrap_or_default()
        .lines()
        .any(|l| l.split_whitespace().nth(1) == Some(to))
}

/// One id per recipient, under a lock, so two drops for one recipient
/// cannot claim the same number.
fn next_id(dir: &Path) -> Result<u64, String> {
    let lock = OpenOptions::new()
        .create(true)
        .write(true)
        .mode(FILE_MODE)
        .open(dir.join(".lock"))
        .map_err(|e| format!("cannot lock: {e}"))?;
    if unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&lock), libc::LOCK_EX) } != 0 {
        return Err(format!("cannot lock: {}", io::Error::last_os_error()));
    }
    let counter = dir.join(".counter");
    let id: u64 = fs::read_to_string(&counter)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
        + 1;
    let tmp = counter.with_extension("tmp");
    private_file(&tmp)
        .and_then(|mut f| f.write_all(id.to_string().as_bytes()).and_then(|_| f.sync_all()))
        .map_err(|e| format!("cannot advance the counter: {e}"))?;
    fs::rename(&tmp, &counter).map_err(|e| format!("cannot advance the counter: {e}"))?;
    Ok(id)
}

/// Hand over everything waiting for this courier, one frame at a time,
/// and keep the connection open when there is nothing.
///
/// The wire is the depot's own, and deliberately not beb's: a header
/// line of `<recipient> <id> <bytes>`, then exactly that many bytes.
/// Counting bytes is not parsing -- the depot still has no idea what is
/// inside one.
///
/// A frame is deleted when the courier says it landed, never before. A
/// connection that dies mid-stream leaves it here and the next
/// collection offers it again, which is safe because the beb receiving
/// it deduplicates.
/// `wait` is the whole difference between the two collecting intents.
///
/// A courier run at a turn boundary has to finish, and a courier holding
/// a connection open has to not. Both want every frame that is here;
/// they disagree only about an empty queue, so they are one function and
/// one flag rather than two paths that could drift.
fn do_pickup(root: &Path, fp: &str, wait: bool) -> Result<(), Fail> {
    let mine = allowed_for(root, fp);
    if mine.is_empty() {
        return Err(refused(format!(
            "{fp} collects for nobody here; an operator allows it with: beb-depot allow {fp} <recipient>"
        )));
    }
    // Once, at the start: a courier must never be handed something the
    // depot would have thrown away. Not on every poll -- that would be a
    // directory read per recipient per quarter second, to catch a frame
    // ageing out during the seconds a connection is actually blocked.
    for to in &mine {
        let q = sweep(&inbox(root, to));
        swept(to, &q);
    }
    let mut input = io::stdin().lock();
    loop {
        match oldest(root, &mine) {
            None if !wait => return Ok(()),
            None => {
                if !peer_present(POLL) {
                    // Not a failure and not a refusal: a courier that
                    // waited and left has done nothing wrong.
                    return Ok(());
                }
            }
            Some((to, id, path)) => {
                let mut f = match File::open(&path) {
                    Ok(f) => f,
                    // Another collector took it between the look and the
                    // open. Not an error: look again.
                    Err(e) if e.kind() == ErrorKind::NotFound => continue,
                    Err(e) => return Err(format!("cannot open {}: {e}", path.display()).into()),
                };
                let len = f.metadata().map_err(|e| format!("cannot stat: {e}"))?.len();
                {
                    let mut out = io::stdout().lock();
                    writeln!(out, "{to} {id} {len}").map_err(|e| format!("cannot write: {e}"))?;
                    io::copy(&mut f, &mut out).map_err(|e| format!("cannot write: {e}"))?;
                    out.flush().map_err(|e| format!("cannot write: {e}"))?;
                }
                let mut line = String::new();
                if input.read_line(&mut line).map_err(|e| format!("cannot read the ack: {e}"))? == 0 {
                    // The courier hung up before acking. The frame stays.
                    return Ok(());
                }
                if line.trim() != format!("ack {id}") {
                    return Err(refused(format!("expected \"ack {id}\", got \"{}\"", line.trim())));
                }
                fs::remove_file(&path).map_err(|e| format!("cannot remove: {e}"))?;
                let _ = fsync_dir(&inbox(root, &to));
            }
        }
    }
}

/// The oldest frame across everything this courier may collect for.
/// Ordered by id within a recipient; between recipients, whoever has the
/// lowest id goes first, which is arbitrary and does not need to be
/// otherwise -- two recipients are two conversations.
/// One queue, after expiry: what went, and what is left.
///
/// Both answers from one pass, because deciding whether a frame has
/// expired means stating it, and that same stat already carries the
/// length the caps are measured in. Asking separately walked every queue
/// twice: against an empty queue's 14.9ms, five thousand held added 31ms
/// to a drop that way, and adds 16ms this way.
///
/// Which also retired an ordering that looked like a saving and was not.
/// Checking the item cap before the byte cap, so a full queue could be
/// refused "without stating ten thousand files", saved nothing: expiry
/// had already stated every one of them.
///
/// A clock that has moved makes `elapsed` fail, and that counts as not
/// expired: the one thing a sweep must never do is delete mail because
/// the time was wrong.
struct Queue {
    gone: u64,
    freed: u64,
    items: usize,
    bytes: u64,
}

fn sweep(dir: &Path) -> Queue {
    let mut q = Queue { gone: 0, freed: 0, items: 0, bytes: 0 };
    for id in ids(dir) {
        let p = dir.join(name(id));
        let md = match fs::metadata(&p) {
            Ok(m) => m,
            Err(_) => continue,
        };
        let old = md
            .modified()
            .ok()
            .and_then(|t| t.elapsed().ok())
            .is_some_and(|age| age > HOLD_MAX_AGE);
        if old && fs::remove_file(&p).is_ok() {
            q.gone += 1;
            q.freed += md.len();
        } else {
            q.items += 1;
            q.bytes += md.len();
        }
    }
    q
}

fn days(d: Duration) -> u64 {
    d.as_secs() / (24 * 60 * 60)
}

fn swept(to: &str, q: &Queue) {
    if q.gone > 0 {
        note(&format!(
            "dropped {} frames for {to} that waited past {} days, {} bytes",
            q.gone,
            days(HOLD_MAX_AGE),
            q.freed
        ));
    }
}

/// Wait up to `timeout` for anything to change, and answer whether the
/// courier is still on the other end.
///
/// A `pickup` with nothing to hand over blocks, and what it is blocked
/// on is a connection somebody else can close. sshd does not signal a
/// forced command when that happens, so a depot that merely slept went
/// on reading this directory four times a second for as long as the
/// machine stayed up -- one such process for every courier that ever
/// disconnected while waiting. Eight of them survived a single run of
/// the test suite, which is how this was found.
///
/// So the sleep is a poll on the client instead: the same quarter
/// second when nothing happens, and an immediate answer when the far end
/// hangs up. POLLHUP is the whole signal -- it means the write end is
/// closed, whether or not bytes are still buffered -- and reading is
/// deliberately not done here, because the ack reader owns that stream
/// and a byte taken now would be a byte missing from its next line.
fn peer_present(timeout: Duration) -> bool {
    let mut p = libc::pollfd { fd: 0, events: libc::POLLIN, revents: 0 };
    let n = unsafe { libc::poll(&mut p, 1, timeout.as_millis() as libc::c_int) };
    if n < 0 || p.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
        return false;
    }
    if n > 0 {
        // Readable, and the peer is still there: a courier talking when
        // nothing was sent to it. Not ours to interpret, but it must not
        // become a spin, so wait out the interval poll cut short.
        std::thread::sleep(timeout);
    }
    true
}

fn oldest(root: &Path, mine: &[String]) -> Option<(String, u64, PathBuf)> {
    mine.iter()
        .filter_map(|to| {
            let dir = inbox(root, to);
            ids(&dir).first().map(|&id| (to.clone(), id, dir.join(name(id))))
        })
        .min_by_key(|(_, id, _)| *id)
}

// ---- held: what is waiting ---------------------------------------------

/// Whether the lines sshd reads still describe this depot.
///
/// A depot is two facts that have to agree and are written in different
/// places: the forced command in `authorized_keys`, and what is actually
/// installed here. Both of this depot's outages were that pair drifting
/// apart -- a line serving a root nobody had granted in, and elsewhere a
/// unit resolving a binary four versions behind -- and in both cases
/// every part looked healthy on its own. Nothing compared them, so
/// answering "is this wired correctly" took six commands.
///
/// So this compares them, and reports what it cannot check rather than
/// implying it did.
fn cmd_status(args: &[String]) -> Result<(), Fail> {
    if !args.is_empty() {
        return Err("status takes nothing: beb-depot status".into());
    }
    let root = root()?;
    let me = std::env::current_exe().ok();
    let mut wrong = Vec::new();

    let mode = fs::metadata(&root)
        .map(|m| m.permissions().mode() & 0o777)
        .unwrap_or(0);
    if !root.is_dir() {
        wrong.push(format!("{} is not there yet; nothing has been granted", root.display()));
    } else if mode != DIR_MODE {
        wrong.push(format!("{} is mode {mode:o}, and holds other people's mail", root.display()));
    }

    let text = fs::read_to_string(allowed_path(&root)).unwrap_or_default();
    let grants: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    let mut couriers: Vec<&str> = grants
        .iter()
        .filter_map(|l| l.split_whitespace().next())
        .collect();
    couriers.sort_unstable();
    couriers.dedup();

    // Every line sshd would run, taken apart the way sshd takes it apart.
    let ak = authorized_keys_path()?;
    let keys = fs::read_to_string(&ak).unwrap_or_default();
    let mut lines = 0usize;
    for (i, l) in keys.lines().enumerate() {
        let Some(cmd) = l.split('"').nth(1) else { continue };
        if !cmd.contains("serve") {
            continue;
        }
        lines += 1;
        let quoted: Vec<&str> = cmd.split('\'').skip(1).step_by(2).collect();
        let bin = quoted.first().copied().unwrap_or_default();
        let served = cmd
            .split("--root")
            .nth(1)
            .and_then(|r| r.split('\'').nth(1))
            .unwrap_or_default();
        if !Path::new(bin).is_file() {
            wrong.push(format!("line {} runs {bin}, which is not there", i + 1));
        } else if me.as_deref().is_some_and(|m| m != Path::new(bin)) {
            // Not fatal on its own -- status may be run from anywhere --
            // but a second binary is how a stale one goes unnoticed.
            wrong.push(format!(
                "line {} runs {bin}, and this is {}",
                i + 1,
                me.as_ref().expect("checked").display()
            ));
        }
        // Canonical both sides: authorize writes the resolved path, and
        // on macOS /var is a symlink to /private/var, so the same
        // directory spelled two ways would read as drift and make this
        // whole verb noise.
        let same = fs::canonicalize(served)
            .ok()
            .zip(fs::canonicalize(&root).ok())
            .map(|(a, b)| a == b)
            .unwrap_or_else(|| Path::new(served) == root);
        if !served.is_empty() && !same {
            wrong.push(format!(
                "line {} serves --root {served}, but the grants are in {}",
                i + 1,
                root.display()
            ));
        }
        if served.is_empty() {
            wrong.push(format!(
                "line {} names no --root, so it serves whatever the environment says, and sshd passes none",
                i + 1
            ));
        }
    }
    if lines == 0 {
        wrong.push(format!(
            "no line in {} runs this depot; authorize adds one",
            util_pretty(&ak)
        ));
    }

    let held: usize = fs::read_dir(root.join("inbox"))
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter(|e| e.file_name().to_str().is_some_and(valid_recipient))
                .map(|e| ids(&e.path()).len())
                .sum()
        })
        .unwrap_or(0);

    note(&format!(
        "{} at {}, root {} ({mode:o})",
        env!("CARGO_PKG_VERSION"),
        me.as_ref().map(|p| p.display().to_string()).unwrap_or_else(|| "?".into()),
        root.display()
    ));
    note(&format!(
        "{lines} {} in {}, {} couriers, {} grants, {held} waiting",
        if lines == 1 { "line" } else { "lines" },
        util_pretty(&ak),
        couriers.len(),
        grants.len()
    ));
    // sshd is the one thing this depends on and the one thing it does not
    // own, so it is named rather than checked: a wrong answer about
    // somebody else's service is worse than no answer.
    note("sshd runs this on each connection; check it with your service manager");

    if wrong.is_empty() {
        return Ok(());
    }
    for w in &wrong {
        note(w);
    }
    Err(refused(if wrong.len() == 1 {
        "one thing does not agree".to_string()
    } else {
        format!("{} things do not agree", wrong.len())
    }))
}

fn util_pretty(p: &Path) -> String {
    match std::env::var("HOME") {
        Ok(h) if !h.is_empty() && p.starts_with(&h) => {
            format!("~{}", p.display().to_string().trim_start_matches(&h))
        }
        _ => p.display().to_string(),
    }
}

fn cmd_held(args: &[String]) -> Result<(), Fail> {
    if !args.is_empty() {
        return Err("held takes nothing: beb-depot held".into());
    }
    let root = root()?;
    let mut rows = Vec::new();
    if let Ok(rd) = fs::read_dir(root.join("inbox")) {
        for e in rd.filter_map(|e| e.ok()) {
            let to = e.file_name().to_string_lossy().to_string();
            if !valid_recipient(&to) {
                continue;
            }
            // An operator asking what is here is the only thing that
            // reaches a queue no courier and no sender has touched, so
            // this is where those get swept.
            let q = sweep(&e.path());
            swept(&to, &q);
            if q.items > 0 {
                rows.push((to, q.items, q.bytes));
            }
        }
    }
    rows.sort();
    if rows.is_empty() {
        return Err(Fail { code: 2, msg: "nothing is waiting here".into() });
    }
    note(&format!("{} recipients with mail in {}", rows.len(), root.display()));
    let mut out = io::stdout().lock();
    for (to, n, bytes) in rows {
        writeln!(out, "{to}  {n}  {bytes}").map_err(|e| format!("cannot write: {e}"))?;
    }
    Ok(())
}
