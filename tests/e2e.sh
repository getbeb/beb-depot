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
grep -q 'beb-depot serve FINGERPRINT' "$OUT" || die "--help lists no serve"
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

d allow "$A" "$KEY1" && die "allowing twice reported success"
test $? -eq 2 || true
grep -q 'could already collect' "$ERR" || die "second allow: $(cat "$ERR")"
ok "allowing twice is nothing to do, not a failure"

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

serve "drop $KEY2" "$A" "$W/f1" && die "a drop for an unregistered recipient was held"
grep -q 'nobody collects for' "$ERR" || die "unregistered drop refusal: $(cat "$ERR")"
grep -q "beb-depot allow" "$ERR" || die "the refusal does not name the fix"
test -e "$BEB_DEPOT_ROOT/inbox/$KEY2" && die "a refused drop created a queue"
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
grep -qv '^beb-depot: ' "$ERR" && grep -q . "$ERR" && grep -vq '^beb-depot: ' "$ERR" &&
    die "a line on stderr carries no prefix: $(cat "$ERR")"
ok "prose on stderr with a prefix; stdout is frames only"

echo "all $n tests passed"
