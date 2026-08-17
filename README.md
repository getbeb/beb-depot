# beb-depot

Where [beb](https://github.com/getbeb/beb) mail waits when two machines
cannot reach each other.

Clients can reach a hub; the hub can reach nobody. NAT, firewalls,
laptops that sleep. The depot is the one address everybody can reach:
it holds signed frames for keys that read somewhere else and hands them
over when their owner asks.

```console
$ beb-depot held
beb-depot: 1 recipients with mail in ~/.local/share/beb-depot
640452f4b6c5d6ca49950c2c7611b6a37ea908c8a16f59ace0e3bb6a75c90169  3  1704
```

It runs no beb, parses no frame, and verifies no signature. sshd
decides who is calling; this decides where the bytes go.

## Install

On the machine that holds the mail, as an unprivileged account of its
own:

```sh
curl -fsSL https://getbeb.dev/depot.sh | sh
```

Or from source with cargo (Rust 1.75+):

```sh
cargo install --git https://github.com/getbeb/beb-depot
```

Install before authorizing, and to where it will stay. `authorize`
writes the binary's own absolute path into the sshd line, so a depot
authorized out of a build directory points there forever.

It needs an sshd and nothing else. No daemon, no port, no unit: every
connection is one sshd child that exits.

## Quick start

A courier hands you one file, printed by
[beb-courier](https://github.com/getbeb/beb-courier) on the client:

```console
$ beb-depot authorize laptop.handover
command="'/usr/local/bin/beb-depot' serve --root '/home/beb/.local/share/beb-depot' SHA256:yIemYIIM…",restrict ssh-ed25519 AAAA… courier@laptop
beb-depot: added SHA256:yIemYIIM… to /home/beb/.ssh/authorized_keys
beb-depot: SHA256:yIemYIIM… may now collect for 640452f4b6c5d6ca…c90169
beb-depot: sshd needs no reload; it reads authorized_keys on each connection
```

That is the whole setup. The key goes into `authorized_keys` behind a
forced command and the grants go into `allowed`, in one act, so the
fingerprint linking them is derived rather than typed into two files
that have to agree.

Without a courier, the same two facts by hand: a public key, and the
queue names, which are the mailbox directories in beb's spool because
beb names each one for the identity's key.

```console
$ ls "${XDG_DATA_HOME:-$HOME/.local/share}/beb" | grep -E '^[0-9a-f]{64}$'
bb68ed0016fd16b5b04cd295b0433c3a54e15f34dcf898ca248dfb34dfa446f0
$ beb-depot authorize courier.pub bb68ed00…f0
```

The filter matters: `outbox` sits beside the mailboxes. Add recipients
later with `beb-depot allow`, or re-run `authorize`, which adds only
what is new.

## Commands

```console
$ beb-depot
beb-depot holds beb mail for keys that read somewhere else.

  beb-depot authorize KEYFILE [RECIPIENT...]
      let that courier in, and let it collect for those recipients
  beb-depot serve [--root PATH] FINGERPRINT
      answer one connection; sshd runs this as a forced command
  beb-depot allow FINGERPRINT RECIPIENT
      one more recipient for a courier already let in
  beb-depot held
      what is waiting, and for whom

  beb-depot --help
  beb-depot --version

A RECIPIENT is a queue name, 64 lowercase hex, or the path to a beb
identity's public key file, which this converts to one. A KEYFILE is a
courier's public key; its fingerprint is derived, never typed. If it is
what beb-courier whoami printed, it names its own recipients and you
need give none.

Exit: 0 did it, 1 change the command, 2 nothing to do, 3 refused.

It holds at most 64 MiB per frame, and per recipient 10000 frames or
1 GiB, whichever comes first. Anything that has waited more than 30
days is dropped, swept by whatever touches the queue next.

BEB_DEPOT_ROOT names where it keeps things. It defaults to
~/.local/share/beb-depot, and holds:

  allowed                    one "FINGERPRINT RECIPIENT" line each
  inbox/<recipient>/<id>     one whole frame per file

BEB_DEPOT_AUTHORIZED_KEYS names the file authorize writes. It defaults
to ~/.ssh/authorized_keys, and gains one line per courier:

  command="'/path/to/beb-depot' serve --root '/path' SHA256:...",restrict ssh-...

That fingerprint is the depot's whole notion of who is calling, which
is why authorize derives it from the key file rather than asking.
```

## The wire

`serve` answers three intents and refuses everything else:

```sh
ssh depot "drop <recipient>"   # one frame on stdin
ssh depot pickup               # stream, then block when empty
ssh depot drain                # stream, then return when empty
```

Collecting streams `<recipient> <id> <bytes>` and then exactly that
many bytes, over and over on the one connection. Reply `ack <id>` once
beb has taken it; nothing is deleted before the ack, so a courier that
dies mid-transfer loses nothing and the beb on the far end deduplicates
whatever it is handed twice.

`pickup` blocks because that is the only way an unreachable client
learns anything. `drain` exists because a run at a turn boundary has to
finish.

## Design

Storage is keyed by recipient, not by courier, so a drop is a write
with no lookup and moving an identity to another machine moves no
files. The caps and the 30 day expiry are constants rather than
settings: a depot cannot tell a mistake from an attack, and an opinion
every deployment states differently is not an opinion.

What it trusts is sshd, and only sshd: that the fingerprint in its own
command line names the key that authenticated. Everything else follows
from that one fact.

[DESIGN.md](DESIGN.md) has the storage layout, the custody rules, and
why there is no registration protocol.

## License

MIT
