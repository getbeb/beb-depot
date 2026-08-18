#!/usr/bin/env bash
# One message from a real beb, through a real depot, into a real beb on
# the other side. e2e.sh proves the depot behaves; this proves the two
# programs still agree about what a frame is and where the outbox puts
# the address. That agreement is the only thing either of them can
# break for the other, and neither repository's own suite would notice.
#
#   BEB_DEPOT_BIN=target/release/beb-depot BEB_BIN=../beb/target/release/beb \
#       bash tests/roundtrip.sh
#
# The courier is four lines of shell here, which is what a courier is.
set -u

DEPOT=${BEB_DEPOT_BIN:-beb-depot}
BEB=${BEB_BIN:-beb}
case "$DEPOT" in /*) ;; */*) DEPOT=$PWD/$DEPOT ;; esac
case "$BEB" in /*) ;; */*) BEB=$PWD/$BEB ;; esac

command -v "$BEB" >/dev/null 2>&1 || { echo "skip - no beb on PATH ($BEB)"; exit 0; }

n=0
ok() { n=$((n + 1)); echo "ok $n - $1"; }
die() { echo "not ok - $1"; exit 1; }

W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
export BEB_DEPOT_ROOT=$W/depot
FP="SHA256:cccc2222222222222222222222222222222222222222"

# Two machines, which here means two XDG roots: separate spools and
# separate known_signers. Sharing either would make this a test of one
# machine talking to itself, and a shared spool would deliver locally
# and never reach the depot at all.
mkdir -p "$W/alice" "$W/bob"
as() { # as <who> <command...>
    local who=$1; shift
    env XDG_DATA_HOME="$W/$who/data" XDG_CONFIG_HOME="$W/$who/cfg" \
        BEB_IDENTITY="$W/$who" "$BEB" "$@"
}
(cd "$W/alice" && env XDG_DATA_HOME="$W/alice/data" XDG_CONFIG_HOME="$W/alice/cfg" \
    "$BEB" init alice) >/dev/null 2>&1 || die "init alice"
(cd "$W/bob" && env XDG_DATA_HOME="$W/bob/data" XDG_CONFIG_HOME="$W/bob/cfg" \
    "$BEB" init bob) >/dev/null 2>&1 || die "init bob"
ok "two identities, two spools, neither reads on the other's machine"

# Each learns the other's name the way anyone does: a contacts line.
as alice contacts >>"$W/bob/cfg/beb/known_signers" || die "alice's contacts"
as bob contacts >>"$W/alice/cfg/beb/known_signers" || die "bob's contacts"
ok "each machine learns the name that resolves the other's key"

# Bob's address as beb prints it, and as the depot files it. The depot
# knows nothing about ssh wire format, so somebody has to do this once:
# the raw 32 bytes of the ed25519 key, in hex. It is the courier.
BOB=$(as bob whoami | awk '{print $2}')
test -n "$BOB" || die "no address for bob"
BOBHEX=$(python3 -c '
import base64, struct, sys
b = base64.b64decode(sys.argv[1])
n, = struct.unpack(">I", b[:4]); off = 4 + n          # "ssh-ed25519"
n, = struct.unpack(">I", b[off:off+4]); off += 4      # the key itself
print(b[off:off+n].hex())' "$BOB")
test ${#BOBHEX} -eq 64 || die "bob's key is not 32 bytes: $BOBHEX"
ok "an address is an ssh key; a depot queue is those same bytes in hex"

# And the depot agrees, from the key file alone. This is the one place
# the two programs' idea of a queue name is checked against each other:
# beb decides it when it writes the outbox, the depot decides it when an
# operator sets things up, and neither would notice the other drifting.
printf 'ssh-ed25519 %s bob\n' "$BOB" >"$W/bob.pub"
"$DEPOT" grant "SHA256:dddd3333333333333333333333333333333333333333" "$W/bob.pub" \
    >/dev/null 2>"$W/derr" || die "depot grant by key file: $(cat "$W/derr")"
grep -q "may now collect for $BOBHEX" "$W/derr" ||
    die "the depot derived a different queue than beb did: $(cat "$W/derr")"
ok "the depot derives the same queue name from the key that beb derives from it"

# Alice sends to a name that resolves to a key with no mailbox here, so
# beb spools it instead of delivering it.
as alice send bob --subject "across" --body "the whole path" \
    >/dev/null 2>&1 || die "send"
f=$(echo "$W"/alice/data/beb/outbox/0*)
test -f "$f" || die "nothing in the outbox"
ok "a message for someone who reads elsewhere waits in the outbox"

# The courier: the filename is the whole routing table.
name=${f##*/}; to=${name#*-}
test "$to" = "$BOBHEX" || die "the outbox names $to, bob is $BOBHEX"
ok "the outbox filename carries the recipient, so the courier reads no frames"

"$DEPOT" grant "$FP" "$BOBHEX" >/dev/null 2>&1 || die "grant"
SSH_ORIGINAL_COMMAND="drop $to" "$DEPOT" serve "$FP" <"$f" >/dev/null 2>&1 || die "drop at depot"
rm -f "$f"
test -e "$f" && die "the outbox still holds a shipped frame"
ok "the courier ships it and only then drops its copy"

# The far side: collect, hand to beb, ack only if beb took it.
python3 - "$DEPOT" "$FP" "$BEB" "$W/bob" <<'PY' || die "collect and deliver"
import os, subprocess, sys, time
depot, fp, beb, home = sys.argv[1:]
env = dict(os.environ, SSH_ORIGINAL_COMMAND="pickup")
p = subprocess.Popen([depot, "serve", fp], env=env, stdin=subprocess.PIPE,
                     stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
to, i, n = p.stdout.readline().decode().split()
frame = p.stdout.read(int(n))
r = subprocess.run([beb, "drop"], input=frame, capture_output=True,
                   env=dict(os.environ, BEB_IDENTITY=home,
                            XDG_DATA_HOME=home + "/data",
                            XDG_CONFIG_HOME=home + "/cfg"))
assert r.returncode == 0, r.stderr.decode()
assert b"accepted" in r.stderr, r.stderr.decode()
held = os.path.join(os.environ["BEB_DEPOT_ROOT"], "inbox", to, "%018d" % int(i))
assert os.path.exists(held), "the depot let go before the ack"
p.stdin.write(("ack %s\n" % i).encode()); p.stdin.flush()
# The depot goes back to blocking for the next frame rather than
# exiting, so wait for the shelf to clear rather than for the process.
for _ in range(100):
    if not os.path.exists(held):
        break
    time.sleep(0.05)
else:
    raise AssertionError("the depot still holds a frame it was told landed")
p.stdin.close(); p.kill()
PY
ok "the depot hands it over, beb installs it, the ack clears the shelf"

out=$(as bob read 2>&1) || die "read: $out"
echo "$out" | grep -q "the whole path" || die "the body did not survive: $out"
echo "$out" | grep -q "alice" || die "the sender did not resolve to a name: $out"
ok "bob reads it, signed by alice, across two machines that never met"

as bob read >/dev/null 2>&1; rc=$?
test "$rc" -eq 2 || die "a second read exited $rc, wanted 2 (nothing to do)"
ok "and once only: the second read has nothing to do"

# ---- register: a grant nobody had to type -------------------------------
#
# The depot verifies rather than trusts, and needs no trust store: the
# key is in the claim, and the queue it grants is derived from that same
# key rather than named beside it. Only a real beb can make one of
# these, which is why it is here rather than in e2e.sh.

ADDR=$(as alice whoami 2>/dev/null)
Q=$(printf '%s' "$ADDR" | python3 -c \
    'import base64,sys; print(base64.b64decode(sys.stdin.read().split()[1])[19:51].hex())')
OTHER="SHA256:dddd3333333333333333333333333333333333333333"
printf '%s\n%s\n' "$ADDR" "$FP" >"$W/payload"
as alice sign beb-collect <"$W/payload" >"$W/sig" 2>/dev/null || die "sign the claim"
cat "$W/payload" "$W/sig" >"$W/claim"

SSH_ORIGINAL_COMMAND="register" "$DEPOT" serve "$FP" <"$W/claim" 2>"$W/err" ||
    die "register: $(cat "$W/err")"
grep -q "^$FP $Q\$" "$BEB_DEPOT_ROOT/allowed" ||
    die "no grant was written: $(cat "$BEB_DEPOT_ROOT/allowed")"
ok "register verifies a claim and grants the queue derived from the signed key"

SSH_ORIGINAL_COMMAND="register" "$DEPOT" serve "$OTHER" <"$W/claim" 2>"$W/err" &&
    die "another courier presented that claim"
grep -q 'this connection is' "$W/err" || die "the fingerprint was not checked: $(cat "$W/err")"
ok "a claim authorises one fingerprint, and sshd decides which one is calling"

as alice sign beb <"$W/payload" >"$W/sig2" 2>/dev/null || die "sign in beb's namespace"
cat "$W/payload" "$W/sig2" >"$W/claim2"
SSH_ORIGINAL_COMMAND="register" "$DEPOT" serve "$FP" <"$W/claim2" 2>"$W/err" &&
    die "an envelope-namespace signature registered"
grep -q 'does not verify' "$W/err" || die "the namespace was not enforced: $(cat "$W/err")"
ok "and only in its own namespace, so an envelope cannot be replayed as one"

SSH_ORIGINAL_COMMAND="unregister $Q" "$DEPOT" serve "$FP" 2>"$W/err" ||
    die "unregister: $(cat "$W/err")"
grep -q "^$FP $Q\$" "$BEB_DEPOT_ROOT/allowed" && die "the grant is still there"
ok "a courier gives up its own grant with no signature at all"

echo "all $n tests passed"
