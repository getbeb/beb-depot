# beb-depot

A place [beb](https://github.com/getbeb/beb) mail waits when two machines cannot reach each other.

beb delivers into a mailbox on one machine. Two agents on two machines need
something between them, and in a real network that something is not a direct
link: clients can reach a hub, the hub can reach nobody. NAT, firewalls,
laptops that sleep.

The depot is the one address everybody can reach. It holds signed frames for
keys that read somewhere else, and hands them over when their owner asks.

It does not run beb, does not parse a frame, and does not verify a signature.
sshd decides who is calling; this decides where the bytes go.

## Install

On the machine that will hold the mail, as an unprivileged account of its own:

```
cargo build --release
sudo install -m755 target/release/beb-depot /usr/local/bin/beb-depot
```

Install it before authorizing anything. `authorize` writes its own absolute
path into the sshd line, so running it out of `target/release` produces a line
that points into your build directory forever.

The depot needs an sshd and nothing else. No daemon of its own, no port, no
unit file: every connection is one sshd child that exits.

## Setting one up

**On each courier machine**, one key for the machine, not one per identity:

```
ssh-keygen -t ed25519 -C courier@laptop -f ~/.ssh/beb_courier
```

Then say which identities that machine reads for. beb names each mailbox for
the identity's key, so the spool already holds the answer, and the answer is
already in the form the depot wants:

```
$ ls "${XDG_DATA_HOME:-$HOME/.local/share}/beb" | grep -E '^[0-9a-f]{64}$'
bb68ed0016fd16b5b04cd295b0433c3a54e15f34dcf898ca248dfb34dfa446f0
```

The filter is not cosmetic: `outbox` sits beside the mailboxes. What is left is
exactly who reads here, because sending to a stranger never invents a mailbox,
and each appears at `beb init` rather than on first delivery, which is when you
need it. For a single identity, `beb whoami > bob.pub` works too.

Send those lines, and `beb_courier.pub`, to whoever runs the depot.

**On the depot**, which is a different machine and usually cannot reach back:

```
$ beb-depot authorize courier.pub bob.pub
command="'/usr/local/bin/beb-depot' serve --root '/home/beb/.local/share/beb-depot' SHA256:yIemYIIM…",restrict ssh-ed25519 AAAA… courier@laptop
beb-depot: added SHA256:yIemYIIM… to /home/beb/.ssh/authorized_keys
beb-depot: SHA256:yIemYIIM… may now collect for 640452f4b6c5d6ca…c90169
beb-depot: sshd needs no reload; it reads authorized_keys on each connection
```

That is the whole of it. The courier key goes into `authorized_keys` behind a
forced command, and the grant goes into the depot's `allowed` file, in one act
so that the fingerprint linking them is derived rather than typed twice.

A recipient is either a key file, as above, or the queue name itself: 64
lowercase hex characters, being the 32 raw bytes of the identity's ed25519 key.
Pass as many as that courier collects for:

```
beb-depot authorize courier.pub bb68ed00…f0 25157d60…2e
```

The queue names came from the other machine, so this is a paste. Only if some
one host can reach both spool and depot does the list pipe straight through,
and by the depot's own premise that is the exception:

```
ssh laptop 'ls ~/.local/share/beb' | grep -E '^[0-9a-f]{64}$' |
    xargs beb-depot authorize courier.pub
``` Later ones can be added with
`beb-depot allow <fingerprint> <recipient>`, or by re-running `authorize` with
the fuller list, which adds only what is new.

## Using it

The seam with beb is a directory and one verb. Outbound needs nothing running,
because the filename in beb's outbox carries the recipient:

```sh
for f in "$SPOOL"/outbox/0*; do
    to=${f##*/}; to=${to#*-}
    ssh depot "drop $to" < "$f" && rm -f "$f"
done
```

Inbound holds a connection open, because a depot cannot dial a client that is
behind NAT:

```sh
ssh depot pickup
```

which streams `<recipient> <id> <bytes>` and then exactly that many bytes, over
and over on the one connection, blocking when there is nothing. Pipe each frame
to `beb drop`, and reply `ack <id>` once beb has taken it. Nothing is deleted
before the ack, so a courier that dies mid-transfer loses nothing, and the beb
on the far end deduplicates whatever it is handed twice.

Both halves are what [beb-courier](https://github.com/getbeb/beb-courier) will
do. Until it exists, the loops above are enough.

## Looking at it

```
$ beb-depot held
beb-depot: 1 recipients with mail in /home/beb/.local/share/beb-depot
640452f4b6c5d6ca49950c2c7611b6a37ea908c8a16f59ace0e3bb6a75c90169  3  1704
```

Recipient, frames, bytes. Exit 2 when nothing is waiting.

Storage is a directory per recipient key and a flat file of grants, both under
`BEB_DEPOT_ROOT`, which defaults to `~/.local/share/beb-depot`:

```
allowed                      SHA256:abc… <recipient>, one line per grant
inbox/640452f4…/000000000000000001    one whole frame per file
```

## Limits

The depot cannot tell a mistake from an attack, so it holds a few opinions and
they are constants rather than settings:

| | |
|---|---|
| 64 MiB | one frame, refused before a byte of it is stored |
| 10000 | frames waiting for one recipient |
| 1 GiB | bytes waiting for one recipient |
| 30 days | how long any frame may wait |

Expiry runs on traffic rather than on a timer, since there is no process to
hold one. A drop sweeps the queue it is about to write to, a pickup sweeps the
queues it may collect from, and `held` sweeps everything, which is what reaches
a queue no sender and no courier has touched in a month.

## Exit codes

| | |
|---|---|
| 0 | did it |
| 1 | change the command |
| 2 | nothing to do |
| 3 | refused |

## Tests

```
cargo test --release
```

Three suites, all shell, because what they test is behaviour at the edges:
streams, exit codes, and files.

- `tests/e2e.sh` drives the depot directly, faking sshd by setting
  `SSH_ORIGINAL_COMMAND`, which is exactly what sshd does.
- `tests/sshd.sh` stands up a real sshd on a loopback port and connects to it.
  A forced command inherits none of the operator's environment, and no stub can
  model that. Skips where no sshd can be started.
- `tests/roundtrip.sh` sends from one real beb and reads on another, which is
  the only place the two programs' agreement is checked. Skips without beb.

## What it trusts

Nothing about the bytes. A frame is opaque, signed by somebody the depot has no
opinion about, addressed to somebody it merely stores for. What it trusts is
sshd: that the fingerprint in its own command line names the key that
authenticated. Everything else follows from that one fact.

See [DESIGN.md](DESIGN.md) for why it is shaped this way.

## License

MIT
