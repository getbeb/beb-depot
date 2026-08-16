#!/usr/bin/env bash
# The depot behind a real sshd, reached over a real ssh connection.
#
#   BEB_DEPOT_BIN=target/release/beb-depot bash tests/sshd.sh
#
# e2e.sh fakes sshd by setting SSH_ORIGINAL_COMMAND, which is accurate
# about the interface and silent about the environment. This is the
# difference: a forced command inherits none of the operator's shell,
# and the first run of this script found that the depot then served out
# of the default root and saw no grants at all. Nothing that stubs sshd
# can find that, so this does not stub sshd.
#
# Skips rather than fails where no sshd can be started, because that is
# a property of the machine and not of the depot.
set -u

DEPOT=${BEB_DEPOT_BIN:-beb-depot}
case "$DEPOT" in /*) ;; */*) DEPOT=$PWD/$DEPOT ;; esac

SSHD=""
for c in /usr/sbin/sshd /usr/local/sbin/sshd; do
    test -x "$c" && { SSHD=$c; break; }
done
test -n "$SSHD" || { echo "skip - no sshd on this machine"; exit 0; }
command -v ssh >/dev/null || { echo "skip - no ssh client"; exit 0; }

n=0
ok() { n=$((n + 1)); echo "ok $n - $1"; }
die() { echo "not ok - $1"; test -f "${W:-}/sshd.log" && tail -20 "$W/sshd.log"; exit 1; }

W=$(mktemp -d)
PID=""
# Killed by pid, never by pattern: this machine runs other people's sshd.
cleanup() { test -n "$PID" && kill "$PID" 2>/dev/null; rm -rf "$W"; }
trap cleanup EXIT

export BEB_DEPOT_ROOT=$W/depot BEB_DEPOT_AUTHORIZED_KEYS=$W/authorized_keys
KEY=d811f21767d40b61a3c093d423fdd05f358ef53d07ba4c99691215c8ba0d756e

ssh-keygen -q -t ed25519 -N '' -f "$W/hostkey" || die "host key"
ssh-keygen -q -t ed25519 -N '' -C courier -f "$W/courier" || die "courier key"

PORT=0
for try in 1 2 3 4 5; do
    p=$((20000 + RANDOM % 20000))
    cat > "$W/sshd_config" <<EOF
Port $p
ListenAddress 127.0.0.1
HostKey $W/hostkey
AuthorizedKeysFile $W/authorized_keys
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
StrictModes no
PidFile $W/sshd.pid
LogLevel VERBOSE
EOF
    "$SSHD" -f "$W/sshd_config" -E "$W/sshd.log" 2>/dev/null
    sleep 1
    if [ -f "$W/sshd.pid" ]; then PORT=$p; PID=$(cat "$W/sshd.pid"); break; fi
done
test "$PORT" -ne 0 || { echo "skip - could not start an sshd here"; exit 0; }
ok "an sshd of our own on 127.0.0.1:$PORT"

sshc() { # <remote command> [stdin file]
    ssh -q -p "$PORT" -i "$W/courier" -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null -o IdentitiesOnly=yes \
        127.0.0.1 "$1" <"${2:-/dev/null}"
}

"$DEPOT" authorize "$W/courier.pub" "$KEY" >"$W/line" 2>/dev/null || die "authorize"
ok "authorize wrote the line sshd is about to read"

printf 'a real frame over a real wire' >"$W/frame"
sshc "drop $KEY" "$W/frame" 2>"$W/err" || die "drop over ssh: $(cat "$W/err")"
grep -q "held 1 for $KEY" "$W/err" || die "drop ack: $(cat "$W/err")"
cmp -s "$W/frame" "$BEB_DEPOT_ROOT/inbox/$KEY/000000000000000001" ||
    die "what crossed the wire is not what was stored"
ok "a drop over ssh lands byte-exact in the root the line named"

# The operator ran authorize with BEB_DEPOT_ROOT set; the connection had
# no such variable. They agree only because the line carries the root.
"$DEPOT" held >"$W/out" 2>/dev/null || die "held"
grep -q "^$KEY  1  " "$W/out" || die "held rows: $(cat "$W/out")"
ok "the operator and the connection agree about where things are kept"

sshc "cat /etc/passwd" >"$W/out" 2>"$W/err"
grep -q 'nothing else is served here' "$W/err" || die "arbitrary command: $(cat "$W/err")"
test -s "$W/out" && die "an arbitrary command produced output"
ok "sshd runs the forced command and nothing the client asked for"

# Collect it back, on the connection, and ack so the depot lets go.
python3 - "$W" "$PORT" "$KEY" <<'PY' || die "pickup over ssh"
import os, subprocess, sys, time
w, port, key = sys.argv[1:]
p = subprocess.Popen(["ssh", "-q", "-p", port, "-i", w + "/courier",
                      "-o", "StrictHostKeyChecking=no",
                      "-o", "UserKnownHostsFile=/dev/null",
                      "-o", "IdentitiesOnly=yes", "127.0.0.1", "pickup"],
                     stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                     stderr=subprocess.DEVNULL)
to, i, n = p.stdout.readline().decode().split()
assert to == key, to
body = p.stdout.read(int(n))
assert body == open(w + "/frame", "rb").read(), "the frame changed in transit"
held = os.path.join(os.environ["BEB_DEPOT_ROOT"], "inbox", to, "%018d" % int(i))
assert os.path.exists(held), "the depot let go before the ack"
p.stdin.write(("ack %s\n" % i).encode()); p.stdin.flush()
for _ in range(100):
    if not os.path.exists(held):
        break
    time.sleep(0.05)
else:
    raise AssertionError("the depot still holds a frame it was told landed")
p.stdin.close(); p.kill()
PY
ok "pickup streams it back over ssh, and the ack clears the shelf"

"$DEPOT" held >/dev/null 2>&1; rc=$?
test "$rc" -eq 2 || die "held exited $rc after everything was collected, wanted 2"
ok "and the depot is empty again"

echo "all $n tests passed"
