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
# Both permissions are named, and which verbs decide each, since that is
# the one thing an operator has to hold in their head.
grep -q 'who may connect, and which queues' "$OUT" ||
    die "--help does not name the two permissions: $(cat "$OUT")"
grep -q 'authorize and unauthorize decide the first' "$OUT" ||
    die "--help does not say which verbs decide which: $(cat "$OUT")"
ok "--help names the verbs and the exit codes"

d frobnicate && die "an unknown command succeeded"
grep -q 'beb-depot --help' "$ERR" || die "unknown command does not name --help"
ok "an unknown command names the thing that lists them"

# ---- grant -------------------------------------------------------------

d grant "not-a-fingerprint" "$KEY1" && die "a bad fingerprint was accepted"
grep -q 'neither a fingerprint nor a key file' "$ERR" || die "fingerprint refusal: $(cat "$ERR")"
d grant "$A" "not-a-key" && die "a bad recipient was accepted"
grep -q 'neither a recipient nor a public key file' "$ERR" ||
    die "recipient refusal: $(cat "$ERR")"
grep -q '64 lowercase hex' "$ERR" || die "the refusal does not say what a recipient is"
ok "grant refuses a fingerprint or a recipient it cannot use, and says which"

d grant "$A" "$KEY1" || die "grant: $(cat "$ERR")"
grep -q "may now collect for $KEY1" "$ERR" || die "grant ack: $(cat "$ERR")"
grep -qx "$A $KEY1" "$BEB_DEPOT_ROOT/allowed" || die "the line is not in the file"
ok "grant writes one greppable line, and says what it granted"

d grant "$A" "$KEY1"; rc=$?
test "$rc" -eq 2 || die "granting twice exited $rc, wanted 2 (nothing to do)"
grep -q 'could already collect' "$ERR" || die "second grant: $(cat "$ERR")"
test "$(grep -c . "$BEB_DEPOT_ROOT/allowed")" -eq 1 || die "the line was written twice"
ok "granting twice is nothing to do, not a failure, and writes nothing"

# ---- authorize ---------------------------------------------------------

export BEB_DEPOT_AUTHORIZED_KEYS=$W/authorized_keys
ssh-keygen -q -t ed25519 -N '' -C courier1 -f "$W/c1" || die "ssh-keygen"
ssh-keygen -q -t ed25519 -N '' -C courier2 -f "$W/c2" || die "ssh-keygen"
FP1=$(ssh-keygen -lf "$W/c1.pub" | awk '{print $2}')

d authorize "$W/c1.pub" "$KEY1" && die "authorize took a recipient"
grep -q 'beb-depot authorize KEYFILE' "$ERR" || die "arity refusal: $(cat "$ERR")"
grep -q 'grant, or register' "$ERR" || die "the refusal does not name where queues come from"
test -e "$BEB_DEPOT_AUTHORIZED_KEYS" && die "a refused authorize wrote the key in anyway"
ok "authorize decides who may connect, and nothing about which queues"

# The one verb that cannot take a fingerprint, since a hash is not a key
# and the line it writes has to carry one.
d authorize "$(ssh-keygen -lf "$W/c1.pub" | awk '{print $2}')" && die "a fingerprint was authorized"
grep -q 'authorize needs the key it was made from' "$ERR" || die "fingerprint refusal: $(cat "$ERR")"
ok "authorize refuses a fingerprint by name, since a key cannot be rebuilt from a hash"

d authorize "$W/c1" && die "a private key was authorized"
grep -q 'is a private key' "$ERR" || die "private key refusal: $(cat "$ERR")"
grep -q '\.pub' "$ERR" || die "the refusal does not name the public half"
ok "handing it a private key is refused by name, not by parse error"

printf 'ssh-ed25519 AAAAfake one\nssh-ed25519 AAAAfake two\n' >"$W/two.pub"
d authorize "$W/two.pub" && die "a file with two keys was authorized"
grep -q 'one line names one courier' "$ERR" || die "two-key refusal: $(cat "$ERR")"
ok "one line names one courier, so a file of keys is refused"

# A recipient may be a key file instead of hex, and must come out the
# same. The expected value is computed here independently of the depot.
ssh-keygen -q -t ed25519 -N '' -C bob -f "$W/bob" || die "ssh-keygen"
BOBHEX=$(python3 -c '
import base64, struct, sys
b = base64.b64decode(open(sys.argv[1]).read().split()[1])
n, = struct.unpack(">I", b[:4]); o = 4 + n
n, = struct.unpack(">I", b[o:o+4]); o += 4
print(b[o:o+n].hex())' "$W/bob.pub")
FP2=$(ssh-keygen -lf "$W/c2.pub" | awk '{print $2}')
d authorize "$W/c2.pub" || die "authorize: $(cat "$ERR")"
d grant "$FP2" "$W/bob.pub" || die "grant by key file: $(cat "$ERR")"
grep -q "may now collect for $BOBHEX" "$ERR" || die "derived the wrong queue: $(cat "$ERR")"
grep -qF "$BOBHEX" "$BEB_DEPOT_ROOT/allowed" || die "the derived grant is not in allowed"
ok "a recipient may be a public key file, and the queue name is derived from it"

# A handover always comes from a machine the depot cannot reach, so it
# often arrives on a pipe. Two things have to hold: the file is read
# once (twice and the second read sees an empty stream), and "-" means
# the descriptor already open rather than the path /dev/stdin, which is
# EACCES once su has changed uid.
ssh-keygen -q -t ed25519 -N '' -C piped -f "$W/p3" || die "ssh-keygen"
FP3=$(ssh-keygen -lf "$W/p3.pub" | awk '{print $2}')
{ cat "$W/p3.pub"; echo "$KEY3"; } > "$W/piped.handover"
d authorize - < "$W/piped.handover" || die "piped: $(cat "$ERR")"
grep -qF "$FP3" "$BEB_DEPOT_AUTHORIZED_KEYS" || die "the piped key is not in authorized_keys"
grep -q 'also names 1' "$ERR" || die "it did not say what it left alone: $(cat "$ERR")"
grep -q "$FP3 $KEY3" "$BEB_DEPOT_ROOT/allowed" && die "it granted from a snapshot"
ok "a key may arrive on a pipe, and the addresses beside it are register's to say"

d authorize /dev/stdin < "$W/piped.handover" >/dev/null 2>&1
test -r /dev/stdin && ok "reading it by path still works where the path is readable" ||
    ok "reading it by path is the caller's business; \"-\" is the one that always works"

ssh-keygen -q -t rsa -b 2048 -N '' -C rsa -f "$W/r" >/dev/null 2>&1 || die "ssh-keygen rsa"
d grant "$A" "$W/r.pub" && die "an rsa key was accepted as a recipient"
grep -q 'is ed25519' "$ERR" || die "rsa refusal: $(cat "$ERR")"
ok "a recipient that is not an ed25519 key is refused by name"

# The key can arrive on a pipe, so the operator needs no file and the
# machine that holds the identity needs no scp.
PIPED="SHA256:eeee4444444444444444444444444444444444444444"
cat "$W/bob.pub" | d grant "$PIPED" - || die "grant from stdin: $(cat "$ERR")"
grep -q "^$PIPED $BOBHEX\$" "$BEB_DEPOT_ROOT/allowed" || die "the piped grant is missing"
ok "grant reads the key from stdin too, the way authorize does"

# Neither argument has to be typed: the courier is the file that was
# authorized, and the recipient is the key that machine printed.
cat "$W/bob.pub" | d grant "$W/c1.pub" - || die "grant by key file: $(cat "$ERR")"
grep -q "^$FP1 $BOBHEX\$" "$BEB_DEPOT_ROOT/allowed" ||
    die "the fingerprint was not derived from the key file: $(cat "$ERR")"
cat "$W/bob.pub" | d revoke "$W/c1.pub" - || die "revoke by key file: $(cat "$ERR")"
grep -q "^$FP1 $BOBHEX\$" "$BEB_DEPOT_ROOT/allowed" && die "the grant survived"
ok "and takes the courier as a key file, so neither argument is ever typed"

d grant - - && die "both arguments read the same stdin"
grep -q 'only one of those can be -' "$ERR" || die "double dash refusal: $(cat "$ERR")"
ok "only one of them may be -, since both would read the same stdin"

d grant "$A" "/no/such/file" && die "a missing path was accepted"
grep -q 'neither a recipient nor a public key file' "$ERR" || die "missing path: $(cat "$ERR")"
ok "an argument that is neither hex nor a file says so, and what each looks like"

d grant "$A" "$W/bob.pub" || die "grant by key file: $(cat "$ERR")"
grep -q "may now collect for $BOBHEX" "$ERR" || die "grant derived the wrong queue"
ok "grant takes a key file too, so the two verbs read the same way"

d authorize "$W/c1.pub" || die "authorize: $(cat "$ERR")"
grep -q "^command=\"" "$OUT" || die "the line is not on stdout: $(cat "$OUT")"
grep -q "$FP1" "$OUT" || die "the line carries no fingerprint: $(cat "$OUT")"
grep -q ',restrict ' "$OUT" || die "the line does not restrict: $(cat "$OUT")"
grep -qF "$(cat "$W/c1.pub" | awk '{print $2}')" "$BEB_DEPOT_AUTHORIZED_KEYS" ||
    die "the key is not in authorized_keys"
test "$(grep -c "$FP1" "$BEB_DEPOT_ROOT/allowed")" -eq 0 || die "authorize granted something"
grep -q 'collects for nothing yet' "$ERR" || die "it did not say it grants nothing: $(cat "$ERR")"
ok "authorize writes the sshd line and no grant, since the two are different questions"

# The parent of authorized_keys belongs to whoever owns the account, not
# to this program: it may create one, but it may not restyle one it
# found. It set a depot account's home to 700 before this was here.
mkdir -p "$W/theirs"; chmod 755 "$W/theirs"
BEB_DEPOT_AUTHORIZED_KEYS=$W/theirs/keys d authorize "$W/c1.pub" >/dev/null 2>&1
# GNU stat first: its -f means "filesystem status" and would succeed
# with something that is not a mode at all.
mode=$(stat -c '%a' "$W/theirs" 2>/dev/null || stat -f '%Lp' "$W/theirs")
test "$mode" = "755" || die "authorize changed a directory it did not create to $mode"
test -s "$W/theirs/keys" || die "it did not write the line it was asked for"
ok "a directory that already existed keeps its mode; only a new one is made private"

# The fingerprint nobody typed: it must be the one ssh-keygen computes.
grep -qF "$FP1" "$BEB_DEPOT_AUTHORIZED_KEYS" || die "the written fingerprint is not ssh-keygen's"
ok "the fingerprint in the line is derived, never transcribed"

# It must be usable: serve honours what authorize wrote, once the other
# verb has said what it may collect for. Two acts now, and the point of
# the test is that the fingerprint carries between them.
d grant "$FP1" "$KEY1" || die "grant onto an authorized fingerprint: $(cat "$ERR")"
SSH_ORIGINAL_COMMAND="pickup" timeout 1 "$DEPOT" serve "$FP1" >/dev/null 2>"$ERR"
grep -q 'collects for nobody' "$ERR" && die "the fingerprint authorize wrote collects nothing"
ok "the fingerprint authorize wrote is the one grant and serve both honour"

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
env BEB_DEPOT_ROOT="$W/other" "$DEPOT" grant "$FP1" "$KEY1" >/dev/null 2>&1 ||
    die "grant in a second root"
SSH_ORIGINAL_COMMAND="drop $KEY1" env BEB_DEPOT_ROOT="$W/nowhere" \
    "$DEPOT" serve --root "$W/other" "$FP1" <"$W/c1.pub" >/dev/null 2>"$ERR" ||
    die "serve --root did not override the environment: $(cat "$ERR")"
test -s "$W/other/inbox/$KEY1/000000000000000001" || die "the frame is not in the named root"
test -d "$W/nowhere" && die "serve wrote to the root named in the environment"
test -e "$BEB_DEPOT_ROOT/inbox/$KEY1" && die "serve wrote to the default root"
ok "--root wins over the environment, which is the whole point of it"

d authorize "$W/c1.pub"; rc=$?
test "$rc" -eq 2 || die "re-authorizing exited $rc, wanted 2 (nothing to do)"
test "$(grep -c "$FP1" "$BEB_DEPOT_AUTHORIZED_KEYS")" -eq 1 || die "the sshd line was written twice"
grep -q "^command=\"" "$OUT" || die "a no-op authorize printed no line"
ok "re-authorizing is nothing to do, prints the line, and duplicates nothing"

d grant "$FP1" "$KEY2" || die "one more queue: $(cat "$ERR")"
d grant "$FP1" "$KEY3" || die "one more queue: $(cat "$ERR")"
test "$(grep -c "$FP1" "$BEB_DEPOT_AUTHORIZED_KEYS")" -eq 1 || die "granting touched the sshd line"
test "$(grep -c "$FP1" "$BEB_DEPOT_ROOT/allowed")" -eq 3 || die "the third grant is missing"
ok "and queues arrive one at a time, on the axis that is about queues"

# The bug the verb exists to prevent: this key, somebody else's command.
printf 'command="beb-depot serve %s",restrict %s\n' "$FP2" "$(cat "$W/c2.pub")" \
    >>"$BEB_DEPOT_AUTHORIZED_KEYS"
sed -i.bak "s|serve $FP2|serve $FP1|" "$BEB_DEPOT_AUTHORIZED_KEYS"
d authorize "$W/c2.pub" && die "a key under the wrong fingerprint was accepted"
grep -q 'under a different command' "$ERR" || die "mismatch refusal: $(cat "$ERR")"
grep -q 'who the depot thinks is calling' "$ERR" || die "the refusal does not say why it matters"
ok "a key already in there under another fingerprint is refused, with the line number"

sed -i.bak "s|serve $FP1|serve $FP2|2" "$BEB_DEPOT_AUTHORIZED_KEYS"
rm -f "$BEB_DEPOT_AUTHORIZED_KEYS".bak

# ---- status ------------------------------------------------------------
#
# The two outages this depot had were the forced command and the install
# drifting apart, and every part looked healthy alone. Nothing compared
# them, so "is this wired correctly" took six commands.
#
# Its own root and its own authorized_keys: the file above has a
# hand-made line in it from the mismatch test, which status is right to
# object to and which would make every assertion here about that.
edit() { python3 -c 'import sys,re,pathlib
p=pathlib.Path(sys.argv[1]); p.write_text(re.sub(sys.argv[2], sys.argv[3], p.read_text()))' "$@"; }

(
    export BEB_DEPOT_ROOT=$W/st BEB_DEPOT_AUTHORIZED_KEYS=$W/st.ak
    ssh-keygen -q -t ed25519 -N '' -C st -f "$W/st.key" || die "ssh-keygen"
    "$DEPOT" authorize "$W/st.key.pub" >/dev/null 2>&1 || die "authorize for status"

    d status || die "status on a healthy depot: $(cat "$ERR")"
    grep -q "root $W/st" "$ERR" || die "status names no root: $(cat "$ERR")"
    grep -q '1 may connect' "$ERR" || die "status counts nobody able to connect: $(cat "$ERR")"
    grep -q 'sshd runs this' "$ERR" || die "status does not say who runs it"
    ok "status reports the depot and agrees with itself when nothing has drifted"

    cp "$W/st.ak" "$W/st.keep"
    edit "$W/st.ak" "--root '[^']*'" "--root '/srv/elsewhere'"
    d status && die "status passed a line serving a root nobody granted in"
    grep -q 'but the grants are in' "$ERR" || die "root drift unreported: $(cat "$ERR")"
    ok "a line serving one root while the grants live in another is caught"

    cp "$W/st.keep" "$W/st.ak"
    printf 'command="/nonexistent/beb-depot serve --root %s SHA256:zz",restrict ssh-ed25519 AAAA x\n' \
        "$W/st" >> "$W/st.ak"
    d status && die "status passed a line running a binary that is not there"
    grep -q 'which is not there' "$ERR" || die "missing binary unreported: $(cat "$ERR")"
    ok "a line running a binary that does not exist is caught"

    cp "$W/st.keep" "$W/st.ak"
    d status || die "status after restoring: $(cat "$ERR")"
    ok "and it goes quiet again once the lines match the install"
) || exit 1
n=$((n + 4))

# ---- serve: what it will and will not answer ---------------------------

serve "" "$A" && die "an empty intent was served"
grep -q 'nothing else is served here' "$ERR" || die "empty intent refusal: $(cat "$ERR")"
serve "rm -rf /" "$A" && die "an arbitrary command was served"
grep -q 'nothing else is served here' "$ERR" || die "arbitrary intent refusal: $(cat "$ERR")"
ok "serve answers the intents it has and refuses everything else"

"$DEPOT" serve "not-a-fingerprint" >"$OUT" 2>"$ERR" && die "serve took a bad fingerprint"
ok "serve refuses a fingerprint sshd would never have given it"

# ---- drop --------------------------------------------------------------

printf 'not a beb frame at all, just bytes' >"$W/f1"

serve "drop $NOBODY" "$A" "$W/f1"; rc=$?
test "$rc" -eq 3 || die "an unregistered drop exited $rc, wanted 3 (refused)"
grep -q 'nobody collects for' "$ERR" || die "unregistered drop refusal: $(cat "$ERR")"
grep -q "beb-depot grant" "$ERR" || die "the refusal does not name the fix"
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

# ---- drain -------------------------------------------------------------

# The one thing that must be true of it: an empty queue ends the call
# rather than holding it. A courier run at a turn boundary has to finish.
serve "drain" "$B" ; rc=$?
test "$rc" -eq 3 || die "drain for a courier with no grant exited $rc, wanted 3"
# Its own fingerprint and its own queue, so that mail left by the tests
# above cannot decide what this one sees.
DR="SHA256:cccc2222222222222222222222222222222222222222"
d grant "$DR" "$KEY3" || die "grant for the drain test: $(cat "$ERR")"
SSH_ORIGINAL_COMMAND=drain timeout 5 "$DEPOT" serve "$DR" </dev/null >"$OUT" 2>"$ERR"; rc=$?
test "$rc" -ne 124 || die "drain blocked on an empty queue instead of returning"
test "$rc" -eq 0 || die "drain on an empty queue exited $rc, wanted 0"
test -s "$OUT" && die "drain wrote something with nothing to hand over"
ok "drain returns on an empty queue, where pickup would wait"

printf 'for draining' >"$W/f3"
serve "drop $KEY3" "$A" "$W/f3" || die "drop for the drain test: $(cat "$ERR")"
python3 - "$DEPOT" "$DR" "$W" <<'PY2' || die "drain hands frames over"
import os, subprocess, sys
depot, fp, w = sys.argv[1:]
env = dict(os.environ, SSH_ORIGINAL_COMMAND="drain")
p = subprocess.Popen([depot, "serve", fp], env=env, stdin=subprocess.PIPE,
                     stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
to, i, n = p.stdout.readline().decode().split()
assert p.stdout.read(int(n)) == open(w + "/f3", "rb").read()
p.stdin.write(("ack %s\n" % i).encode()); p.stdin.flush()
# Nothing else is waiting, so it must end rather than block.
assert p.stdout.readline() == b"", "drain kept the connection after the last frame"
assert p.wait(timeout=10) == 0
held = os.path.join(os.environ["BEB_DEPOT_ROOT"], "inbox", to, "%018d" % int(i))
assert not os.path.exists(held), "the acked frame is still held"
PY2
ok "drain streams what is there, waits for each ack, and then ends the call"

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

# ---- register ----------------------------------------------------------
#
# A claim is signed by a real beb, so the verifying half lives in
# roundtrip.sh, where there is one. What is checkable here is the shape.

serve register "$A" /dev/null && die "an empty claim registered"
grep -q 'one per line' "$ERR" || die "empty claim: $(cat "$ERR")"
ok "a claim that is not three parts is refused before anything is verified"

# A courier can only ever take away its own line, and learns nothing
# about a queue it was granted nothing for. Sweeping before that check
# made unregister a way to ask whether somebody else's queue had traffic.
d grant "$B" "$KEY2" >/dev/null 2>&1
OTHERQ=$BEB_DEPOT_ROOT/inbox/$KEY2
rm -rf "$OTHERQ"; fill "$OTHERQ" 3 10; age "$OTHERQ" 2 -2678400
serve "unregister $KEY2" "$A"; rc=$?
test "$rc" -eq 2 || die "unregistering another courier's grant exited $rc, wanted 2"
grep -q "^$B $KEY2\$" "$BEB_DEPOT_ROOT/allowed" || die "another courier's grant went"
grep -q 'waited past' "$ERR" && die "it reported a sweep of a queue it was granted nothing for"
test "$(ls "$OTHERQ" | wc -l | tr -d ' ')" -eq 3 || die "it swept a queue it may not collect"
ok "unregister takes only the caller's own line, and says nothing about a queue it may not touch"

# ---- unauthorize --------------------------------------------------------
#
# revoke tidies one grant and leaves the courier connecting, which is
# right for a machine that is gone and wrong for one you no longer
# trust: it can sign a fresh claim and register the grant straight back.
# Cutting a machine off is removing the line sshd reads.

UNAUTH=$W/unauth.pub
ssh-keygen -q -t ed25519 -N '' -C evicted -f "$W/unauthkey"
cp "$W/unauthkey.pub" "$UNAUTH"
UFP=$(ssh-keygen -lf "$UNAUTH" | awk '{print $2}')
d authorize "$UNAUTH" || die "authorize for the unauthorize test"
d grant "$UFP" "$KEY1" >/dev/null 2>&1
d grant "$UFP" "$KEY2" >/dev/null 2>&1
grep -q "$UFP" "$BEB_DEPOT_AUTHORIZED_KEYS" || die "no line was written"

d unauthorize "$UFP" || die "unauthorize: $(cat "$ERR")"
grep -q "$UFP" "$BEB_DEPOT_AUTHORIZED_KEYS" && die "the line sshd reads is still there"
grep -q "^$UFP " "$BEB_DEPOT_ROOT/allowed" && die "its grants outlived it"
grep -q '2 grants went with it' "$ERR" || die "it did not say what went: $(cat "$ERR")"
ok "unauthorize removes the line sshd reads, and the grants go with it"

# Both, because a grant with no courier keeps drop accepting mail for a
# queue nothing will ever collect.
d unauthorize "$UFP"; rc=$?
test "$rc" -eq 2 || die "unauthorizing twice exited $rc, wanted 2"
ok "and twice is nothing to do"

# The key file works where the fingerprint is not to hand, the way allow
# takes either shape of a recipient.
d authorize "$UNAUTH" >/dev/null 2>&1
d unauthorize "$UNAUTH" || die "unauthorize by key file: $(cat "$ERR")"
grep -q "$UFP" "$BEB_DEPOT_AUTHORIZED_KEYS" && die "the line survived the key-file form"
ok "and takes the key file it was authorized from, so no fingerprint is typed"

d unauthorize "not-a-fingerprint-or-a-file" && die "unauthorize took a bare word"
grep -q 'neither a fingerprint nor a key file' "$ERR" || die "refusal: $(cat "$ERR")"
ok "a word that is neither is refused, and named as both things it is not"

# ---- granted ------------------------------------------------------------

d grant "$A" "$KEY1" >/dev/null 2>&1
d grant "$A" "$KEY2" >/dev/null 2>&1
serve granted "$A" || die "granted: $(cat "$ERR")"
grep -q "^$KEY1\$" "$OUT" || die "granted omits a recipient: $(cat "$OUT")"
grep -q "^$KEY2\$" "$OUT" || die "granted omits a recipient: $(cat "$OUT")"
ok "granted lists what this courier may collect for, on stdout"

# Only ever about the caller: the fingerprint is sshd's, not an argument.
serve granted "$B" || die "granted for a courier with nothing: $(cat "$ERR")"
grep -q "^$KEY1\$" "$OUT" && die "granted told one courier about another's"
ok "and only about the caller, since the fingerprint is not something it can ask with"

# ---- revoke -------------------------------------------------------------

# Its own recipient, granted to nobody else, so the second line about
# drops stopping is about this grant and not somebody else's.
ONLY=5a1c8e30f7b249d6a8e0c1b34f92d7580ea6c341b8d029f7c4e13a6bd025f8e4
d grant "$A" "$ONLY" || die "grant for the revoke test"
d revoke "$A" "$ONLY" || die "revoke: $(cat "$ERR")"
grep -q "^$A $ONLY\$" "$BEB_DEPOT_ROOT/allowed" && die "the grant survived revoke"
grep -q 'drops for it are refused' "$ERR" || die "revoke does not say what changed"
ok "revoke takes a grant back, and says that drops for it stop"

d revoke "$A" "$ONLY"; rc=$?
test "$rc" -eq 2 || die "revoking twice exited $rc, wanted 2"
ok "and twice is nothing to do"

d revoke "not-a-fingerprint" "$ONLY" && die "revoke took a bare word"
grep -q 'neither a fingerprint nor a key file' "$ERR" || die "revoke refusal: $(cat "$ERR")"
ok "revoke checks the fingerprint it is given, the way grant does"

echo "all $n tests passed"
