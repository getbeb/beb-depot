#!/usr/bin/env bash
# End-to-end tests for beb-depot. No beb, no ssh, no network: sshd's job
# is faked by setting SSH_ORIGINAL_COMMAND, which is exactly what sshd
# does. Run:
#
#   BEB_DEPOT_BIN=target/release/beb-depot bash tests/e2e.sh
#
# Most frames here are arbitrary bytes rather than real beb deliveries.
# That is the point: a depot that needed a valid frame would be a depot
# that parses one, and then two programs would own beb's format.
set -u

DEPOT=${BEB_DEPOT_BIN:-beb-depot}
case "$DEPOT" in /*) ;; */*) DEPOT=$PWD/$DEPOT ;; esac

n=0
ok() { n=$((n + 1)); echo "ok $n - $1"; }
die() {
    echo "not ok - $1"
    echo "--- stdout ---"; cat "$OUT" 2>/dev/null
    echo "--- stderr ---"; cat "$ERR" 2>/dev/null
    exit 1
}

W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
export BEB_DEPOT_ROOT=$W/root
OUT=$W/out; ERR=$W/err

A="SHA256:aaaa0000000000000000000000000000000000000000"
B="SHA256:bbbb1111111111111111111111111111111111111111"
KEY1=d811f21767d40b61a3c093d423fdd05f358ef53d07ba4c99691215c8ba0d756e
KEY2=0c74b660a5d210f74a832fede9cf5a6dd9068ea0c6de2f4996b3e40cd2d3e3d6
KEY3=3f2a91c0e7b84d16f5c03a8e2d9b7461fa50e83c2b1d6970a4e8fc35d20b7e19
# Granted to nobody, ever, so a drop for it has no one to collect it.
NOBODY=9e1d4c7a8b02f36510ad9c84e2b7f019354dc86a1f0b729e4d38c5a06e91b2f7

d() { "$DEPOT" "$@" >"$OUT" 2>"$ERR"; }
serve() { # <intent> <fingerprint> [stdin file]
    local intent=$1 fp=$2 in=${3:-/dev/null}
    SSH_ORIGINAL_COMMAND="$intent" "$DEPOT" serve "$fp" <"$in" >"$OUT" 2>"$ERR"
}

# ---- the surface -------------------------------------------------------

d --version || die "--version"
grep -q '^beb-depot [0-9]' "$OUT" || die "--version shape: $(cat "$OUT")"
ok "--version"

d --help || die "--help"
grep -q 'beb-depot serve' "$OUT" || die "--help lists no serve"
grep -q 'beb-depot authorize' "$OUT" || die "--help lists no authorize"
grep -q 'Exit: 0 did it' "$OUT" || die "--help omits the exit table"
ok "--help names the verbs and the exit codes"

d frobnicate && die "an unknown command succeeded"
grep -q 'beb-depot --help' "$ERR" || die "unknown command does not name --help"
ok "an unknown command names the thing that lists them"

# ---- allow -------------------------------------------------------------

d allow "not-a-fingerprint" "$KEY1" && die "a bad fingerprint was accepted"
grep -q 'is not a fingerprint' "$ERR" || die "fingerprint refusal: $(cat "$ERR")"
d allow "$A" "not-a-key" && die "a bad recipient was accepted"
grep -q 'is not a recipient' "$ERR" || die "recipient refusal: $(cat "$ERR")"
grep -q '64 lowercase hex' "$ERR" || die "the refusal does not say what a recipient is"
ok "allow refuses a fingerprint or a recipient it cannot use, and says which"

d allow "$A" "$KEY1" || die "allow: $(cat "$ERR")"
grep -q "may now collect for $KEY1" "$ERR" || die "allow ack: $(cat "$ERR")"
grep -qx "$A $KEY1" "$BEB_DEPOT_ROOT/allowed" || die "the line is not in the file"
ok "allow writes one greppable line, and says what it granted"

d allow "$A" "$KEY1"; rc=$?
test "$rc" -eq 2 || die "allowing twice exited $rc, wanted 2 (nothing to do)"
grep -q 'could already collect' "$ERR" || die "second allow: $(cat "$ERR")"
test "$(grep -c . "$BEB_DEPOT_ROOT/allowed")" -eq 1 || die "the line was written twice"
ok "allowing twice is nothing to do, not a failure, and writes nothing"

# ---- authorize ---------------------------------------------------------

export BEB_DEPOT_AUTHORIZED_KEYS=$W/authorized_keys
ssh-keygen -q -t ed25519 -N '' -C courier1 -f "$W/c1" || die "ssh-keygen"
ssh-keygen -q -t ed25519 -N '' -C courier2 -f "$W/c2" || die "ssh-keygen"
FP1=$(ssh-keygen -lf "$W/c1.pub" | awk '{print $2}')

d authorize "$W/c1.pub" && die "authorize with no recipient succeeded"
grep -q 'at least one recipient' "$ERR" || die "arity refusal: $(cat "$ERR")"
d authorize "$W/c1.pub" "not-a-key" && die "a bad recipient was authorized"
test -e "$BEB_DEPOT_AUTHORIZED_KEYS" && die "a refused authorize wrote the key in anyway"
ok "authorize checks every recipient before it writes anything"

d authorize "$W/c1" "$KEY1" && die "a private key was authorized"
grep -q 'is a private key' "$ERR" || die "private key refusal: $(cat "$ERR")"
grep -q '\.pub' "$ERR" || die "the refusal does not name the public half"
ok "handing it a private key is refused by name, not by parse error"

printf 'ssh-ed25519 AAAAfake one\nssh-ed25519 AAAAfake two\n' >"$W/two.pub"
d authorize "$W/two.pub" "$KEY1" && die "a file with two keys was authorized"
grep -q 'one line names one courier' "$ERR" || die "two-key refusal: $(cat "$ERR")"
ok "one line names one courier, so a file of keys is refused"

d authorize "$W/c1.pub" "$KEY1" "$KEY2" || die "authorize: $(cat "$ERR")"
grep -q "^command=\"" "$OUT" || die "the line is not on stdout: $(cat "$OUT")"
grep -q "$FP1" "$OUT" || die "the line carries no fingerprint: $(cat "$OUT")"
grep -q ',restrict ' "$OUT" || die "the line does not restrict: $(cat "$OUT")"
grep -qF "$(cat "$W/c1.pub" | awk '{print $2}')" "$BEB_DEPOT_AUTHORIZED_KEYS" ||
    die "the key is not in authorized_keys"
test "$(grep -c "$FP1" "$BEB_DEPOT_ROOT/allowed")" -eq 2 || die "both grants were not written"
ok "authorize writes the sshd line and both grants in one act"

# The fingerprint nobody typed: it must be the one ssh-keygen computes.
grep -qF "$FP1" "$BEB_DEPOT_AUTHORIZED_KEYS" || die "the written fingerprint is not ssh-keygen's"
ok "the fingerprint in the line is derived, never transcribed"

# It must be usable: serve accepts what authorize wrote.
SSH_ORIGINAL_COMMAND="pickup" timeout 1 "$DEPOT" serve "$FP1" >/dev/null 2>"$ERR"
grep -q 'collects for nobody' "$ERR" && die "the fingerprint authorize wrote collects nothing"
ok "the fingerprint authorize wrote is the one serve honours"

# sshd runs a forced command with none of the operator's environment, so
# the root has to travel in the line. A live sshd caught this; this keeps
# it caught. Every argument is quoted because sshd hands the string to a
# shell, and a path with a space in it would otherwise become two.
ROOTREAL=$(cd "$BEB_DEPOT_ROOT" && pwd -P)
grep -qF "serve --root '$ROOTREAL'" "$BEB_DEPOT_AUTHORIZED_KEYS" ||
    die "the line does not carry the root: $(cat "$BEB_DEPOT_AUTHORIZED_KEYS")"
grep -q "^command=\"'" "$BEB_DEPOT_AUTHORIZED_KEYS" || die "the binary is not quoted for the shell"
ok "the line carries the root, quoted, because a forced command has no environment"

# The proof it matters: three roots, and the frame must land in the one
# named on the command line rather than the one in the environment.
env BEB_DEPOT_ROOT="$W/other" "$DEPOT" allow "$FP1" "$KEY1" >/dev/null 2>&1 ||
    die "allow in a second root"
SSH_ORIGINAL_COMMAND="drop $KEY1" env BEB_DEPOT_ROOT="$W/nowhere" \
    "$DEPOT" serve --root "$W/other" "$FP1" <"$W/c1.pub" >/dev/null 2>"$ERR" ||
    die "serve --root did not override the environment: $(cat "$ERR")"
test -s "$W/other/inbox/$KEY1/000000000000000001" || die "the frame is not in the named root"
test -d "$W/nowhere" && die "serve wrote to the root named in the environment"
test -e "$BEB_DEPOT_ROOT/inbox/$KEY1" && die "serve wrote to the default root"
ok "--root wins over the environment, which is the whole point of it"

d authorize "$W/c1.pub" "$KEY1" "$KEY2"; rc=$?
test "$rc" -eq 2 || die "re-authorizing exited $rc, wanted 2 (nothing to do)"
test "$(grep -c "$FP1" "$BEB_DEPOT_AUTHORIZED_KEYS")" -eq 1 || die "the sshd line was written twice"
grep -q "^command=\"" "$OUT" || die "a no-op authorize printed no line"
ok "re-authorizing is nothing to do, prints the line, and duplicates neither file"

d authorize "$W/c1.pub" "$KEY1" "$KEY2" "$KEY3" || die "adding one recipient: $(cat "$ERR")"
test "$(grep -c "$FP1" "$BEB_DEPOT_AUTHORIZED_KEYS")" -eq 1 || die "the sshd line was written twice"
test "$(grep -c "$FP1" "$BEB_DEPOT_ROOT/allowed")" -eq 3 || die "the third grant is missing"
ok "re-running with one more recipient adds only the one"

# The bug the verb exists to prevent: this key, somebody else's command.
FP2=$(ssh-keygen -lf "$W/c2.pub" | awk '{print $2}')
printf 'command="beb-depot serve %s",restrict %s\n' "$FP2" "$(cat "$W/c2.pub")" \
    >>"$BEB_DEPOT_AUTHORIZED_KEYS"
sed -i.bak "s|serve $FP2|serve $FP1|" "$BEB_DEPOT_AUTHORIZED_KEYS"
d authorize "$W/c2.pub" "$KEY1" && die "a key under the wrong fingerprint was accepted"
grep -q 'under a different command' "$ERR" || die "mismatch refusal: $(cat "$ERR")"
grep -q 'who the depot thinks is calling' "$ERR" || die "the refusal does not say why it matters"
ok "a key already in there under another fingerprint is refused, with the line number"

sed -i.bak "s|serve $FP1|serve $FP2|2" "$BEB_DEPOT_AUTHORIZED_KEYS"
rm -f "$BEB_DEPOT_AUTHORIZED_KEYS".bak

# ---- serve: what it will and will not answer ---------------------------

serve "" "$A" && die "an empty intent was served"
grep -q 'drop <recipient> or pickup' "$ERR" || die "empty intent refusal: $(cat "$ERR")"
serve "rm -rf /" "$A" && die "an arbitrary command was served"
grep -q 'nothing else is served here' "$ERR" || die "arbitrary intent refusal: $(cat "$ERR")"
ok "serve answers two intents and refuses everything else"

"$DEPOT" serve "not-a-fingerprint" >"$OUT" 2>"$ERR" && die "serve took a bad fingerprint"
ok "serve refuses a fingerprint sshd would never have given it"

# ---- drop --------------------------------------------------------------

printf 'not a beb frame at all, just bytes' >"$W/f1"

serve "drop $NOBODY" "$A" "$W/f1"; rc=$?
test "$rc" -eq 3 || die "an unregistered drop exited $rc, wanted 3 (refused)"
grep -q 'nobody collects for' "$ERR" || die "unregistered drop refusal: $(cat "$ERR")"
grep -q "beb-depot allow" "$ERR" || die "the refusal does not name the fix"
test -e "$BEB_DEPOT_ROOT/inbox/$NOBODY" && die "a refused drop created a queue"
ok "a drop nobody could ever collect is refused, and nothing is created"

serve "drop $KEY1" "$A" "$W/f1" || die "drop: $(cat "$ERR")"
grep -q "held 1 for $KEY1" "$ERR" || die "drop ack: $(cat "$ERR")"
test -s "$BEB_DEPOT_ROOT/inbox/$KEY1/000000000000000001" || die "the frame is not held"
cmp -s "$W/f1" "$BEB_DEPOT_ROOT/inbox/$KEY1/000000000000000001" ||
    die "what is held is not what was sent"
ok "a drop is held byte-exact, under an id, and the depot never read it"

serve "drop $KEY1" "$A" /dev/null && die "an empty frame was held"
grep -q 'empty frame' "$ERR" || die "empty frame refusal: $(cat "$ERR")"
ok "an empty frame is not a delivery"

printf 'second' >"$W/f2"
serve "drop $KEY1" "$B" "$W/f2" || die "second drop: $(cat "$ERR")"
grep -q "held 2 for" "$ERR" || die "ids are not monotonic: $(cat "$ERR")"
ok "ids climb per recipient, whoever dropped it"

# ---- held --------------------------------------------------------------

d held || die "held: $(cat "$ERR")"
grep -q "^$KEY1  2  " "$OUT" || die "held rows: $(cat "$OUT")"
grep -q '1 recipients with mail' "$ERR" || die "held summary: $(cat "$ERR")"
ok "held names each recipient, how many, and how many bytes"

# ---- pickup ------------------------------------------------------------

serve "pickup" "$B" && die "a courier with no grant collected"
grep -q 'collects for nobody here' "$ERR" || die "ungranted pickup: $(cat "$ERR")"
ok "a courier collects for nobody until an operator says otherwise"

# The wire: a header line, then exactly that many bytes, then an ack
# before anything is deleted.
python3 - "$DEPOT" "$A" "$W" <<'PY' || die "pickup wire"
import os, subprocess, sys
depot, fp, w = sys.argv[1:]
env = dict(os.environ, SSH_ORIGINAL_COMMAND="pickup")
p = subprocess.Popen([depot, "serve", fp], env=env, stdin=subprocess.PIPE,
                     stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
to, i, n = p.stdout.readline().decode().split()
body = p.stdout.read(int(n))
assert body == open(w + "/f1", "rb").read(), "streamed bytes differ from what was dropped"
assert i == "1", i
# Not acked yet, so it must still be there.
root = os.environ["BEB_DEPOT_ROOT"]
held = os.path.join(root, "inbox", to, "%018d" % 1)
assert os.path.exists(held), "the frame went before the ack did"
p.stdin.write(b"ack 1\n"); p.stdin.flush()
# The next one arrives on the same connection.
to2, i2, n2 = p.stdout.readline().decode().split()
assert i2 == "2", i2
assert p.stdout.read(int(n2)) == open(w + "/f2", "rb").read()
assert not os.path.exists(held), "the acked frame is still held"
p.stdin.close(); p.kill()
PY
ok "pickup streams one frame at a time, keeps the connection, and deletes only on ack"

# What the ack buys: a courier that dies mid-transfer loses nothing.
python3 - "$DEPOT" "$A" <<'PY' || die "hang-up"
import os, subprocess, sys
depot, fp = sys.argv[1:]
env = dict(os.environ, SSH_ORIGINAL_COMMAND="pickup")
p = subprocess.Popen([depot, "serve", fp], env=env, stdin=subprocess.PIPE,
                     stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
to, i, n = p.stdout.readline().decode().split()
p.stdout.read(int(n))
p.kill()                      # died holding it, never acked
root = os.environ["BEB_DEPOT_ROOT"]
assert os.path.exists(os.path.join(root, "inbox", to, "%018d" % int(i))), \
    "a frame vanished when the courier died"
PY
ok "a courier that dies mid-transfer leaves the frame where it was"

# ---- limits ------------------------------------------------------------

# Every one of these fills a queue by writing files into it directly
# rather than by dropping thousands of frames: what is under test is the
# refusal, not the depot's ability to spend a minute getting there.
CAPPED=$BEB_DEPOT_ROOT/inbox/$KEY1
fill() { python3 -c '
import os, sys
d, n, size = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
os.makedirs(d, exist_ok=True)
for i in range(1, n + 1):
    with open(os.path.join(d, "%018d" % i), "wb") as f:
        f.truncate(size)   # sparse: the size is real, the disk use is not
' "$@"; }
age() { python3 -c '
import os, sys, time
d, count, delta = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
t = time.time() + delta
for n in sorted(os.listdir(d))[:count]:
    p = os.path.join(d, n); os.utime(p, (t, t))
' "$@"; }

rm -rf "$CAPPED"; fill "$CAPPED" 10000 1
serve "drop $KEY1" "$A" "$W/f1"; rc=$?
test "$rc" -eq 3 || die "a drop onto a full queue exited $rc, wanted 3 (refused)"
grep -q 'frames, which is the cap' "$ERR" || die "item cap refusal: $(cat "$ERR")"
grep -q 'until a courier collects' "$ERR" || die "the refusal does not name the fix"
test "$(ls "$CAPPED" | wc -l | tr -d ' ')" -eq 10000 || die "the refused drop was stored anyway"
ok "a queue at the item cap takes nothing more, and says what would clear it"

rm -rf "$CAPPED"; fill "$CAPPED" 1 1073741824
serve "drop $KEY1" "$A" "$W/f1"; rc=$?
test "$rc" -eq 3 || die "a drop onto a full-by-bytes queue exited $rc, wanted 3"
grep -q 'bytes, which is the cap' "$ERR" || die "byte cap refusal: $(cat "$ERR")"
ok "a queue at the byte cap takes nothing more, whatever the item count"

# One byte under, and a frame that would cross it. A frame's size is not
# knowable until it has been read, so this is the check that happens after.
rm -rf "$CAPPED"; fill "$CAPPED" 1 1073741823
serve "drop $KEY1" "$A" "$W/f1"; rc=$?
test "$rc" -eq 3 || die "a frame crossing the byte cap exited $rc, wanted 3"
grep -q 'and this frame is' "$ERR" || die "crossing refusal: $(cat "$ERR")"
test "$(ls "$CAPPED" | wc -l | tr -d ' ')" -eq 1 || die "the frame was kept after being refused"
ok "a frame that would cross the byte cap is refused once measured, and not kept"

# Expiry. Nothing here waits 30 days; the frames are simply born old.
rm -rf "$CAPPED"; fill "$CAPPED" 3 10; age "$CAPPED" 2 -2678400
serve "drop $KEY1" "$A" "$W/f1" || die "drop after expiry: $(cat "$ERR")"
grep -q 'waited past 30 days' "$ERR" || die "the sweep said nothing: $(cat "$ERR")"
test "$(ls "$CAPPED" | wc -l | tr -d ' ')" -eq 2 || die "expiry kept or took the wrong ones"
ok "a drop sweeps what waited past 30 days first, and says how many went"

# The queue nothing else reaches: no sender, no courier, only an operator.
rm -rf "$CAPPED"; fill "$CAPPED" 2 10; age "$CAPPED" 2 -2678400
d held; rc=$?
test "$rc" -eq 2 || die "held exited $rc after sweeping the last frames, wanted 2"
grep -q 'waited past 30 days' "$ERR" || die "held did not sweep: $(cat "$ERR")"
test -z "$(ls "$CAPPED")" || die "held left expired frames behind"
ok "held sweeps the queues nothing else ever touches"

# A clock that moved must never be a reason to delete mail.
rm -rf "$CAPPED"; fill "$CAPPED" 1 10; age "$CAPPED" 1 3600
d held || die "held with a future mtime: $(cat "$ERR")"
test "$(ls "$CAPPED" | wc -l | tr -d ' ')" -eq 1 || die "a frame from the future was deleted"
ok "a frame whose mtime is ahead of the clock is wrong, not expired"

# ---- an empty depot ----------------------------------------------------

rm -rf "$BEB_DEPOT_ROOT/inbox"
d held && die "held on an empty depot reported success"
grep -q 'nothing is waiting' "$ERR" || die "empty held: $(cat "$ERR")"
ok "an empty depot is nothing to do, not a failure"

# ---- streams -----------------------------------------------------------

# Everything the depot says goes to stderr with a prefix, so a courier
# reading stdout gets frames and nothing else.
serve "drop $KEY1" "$A" "$W/f1" || die "drop for the stream test"
test -s "$OUT" && die "drop wrote to stdout: $(cat "$OUT")"
test -s "$ERR" || die "drop said nothing at all"
grep -v '^beb-depot: ' "$ERR" >"$W/unprefixed"
test -s "$W/unprefixed" && die "unprefixed on stderr: $(cat "$W/unprefixed")"
ok "prose on stderr with a prefix; stdout is frames only"

# The same for a refusal, which is the line an operator actually reads.
serve "drop $NOBODY" "$A" "$W/f1"
grep -v '^beb-depot: ' "$ERR" >"$W/unprefixed"
test -s "$W/unprefixed" && die "unprefixed refusal: $(cat "$W/unprefixed")"
ok "a refusal is prefixed too"

echo "all $n tests passed"
