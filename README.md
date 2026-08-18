# beb-depot

A relay store for [beb](https://github.com/getbeb/beb). When two
machines cannot reach each other, both connect outbound to a depot,
which holds their mail until the recipient's courier collects it.

```
beb          signs, stores and reads mail on one machine
beb-courier  carries it between machines
beb-depot    holds it when two machines cannot reach each other

identity ─ beb ─ courier ─────── courier ─ beb ─ identity
                         \     /
                          depot
                        (optional)
```

Both machines connect outbound to the depot; it connects to nobody.

```
authorize   this courier may connect
grant       this courier may collect for one recipient
register    the courier asks for its own grant, signed
```

It runs no beb and never inspects message contents. sshd decides who is
calling; this decides where the bytes go.

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

Install before authorizing, and to where it will stay: `authorize`
writes the binary's own absolute path into the sshd line.

It needs an sshd and nothing else. No daemon, no port, no unit.

## Quick start

A courier hands you one file, printed by
[beb-courier](https://github.com/getbeb/beb-courier) on the client:

```console
# on the depot
$ beb-depot authorize laptop.handover
command="'/usr/local/bin/beb-depot' serve --root '…' SHA256:yIemYIIM…",restrict ssh-ed25519 AAAA…
beb-depot: added SHA256:yIemYIIM… to /home/beb/.ssh/authorized_keys
beb-depot: sshd needs no reload; it reads authorized_keys on each connection
beb-depot: it collects for nothing yet: beb-depot grant SHA256:yIemYIIM… <recipient>
beb-depot: or that machine says so itself, with beb-courier register
```

That lets the machine connect, but it cannot collect anything yet. Each
recipient queue is granted separately, and normally the client asks for
its own: `register` sends a signed claim over the connection `authorize`
just allowed, asking for the queue belonging to that identity.

```sh
# on the client
BEB_IDENTITY=~/newthing beb whoami | beb-courier register
```

Grant it here instead when the client cannot ask. The first argument
identifies the courier, the second the recipient queue, and either can
be a key file or `-` for a key on stdin, so nothing is typed:

```sh
# on the depot
ssh client 'BEB_IDENTITY=~/alice beb whoami' | beb-depot grant laptop.handover -
```

`authorize` reads the handover once, so it can come straight off a pipe.
Use `-` rather than `/dev/stdin`, which `su` cannot re-open:

```sh
ssh depot "su -s /bin/sh beb -c 'beb-depot authorize -'" < alice.handover
```

## Commands

```console
$ beb-depot
beb-depot 0.2.0 stores beb mail until an authorized courier collects it.

Two permissions: who may connect, and which queues they may collect.
authorize and unauthorize decide the first, grant and revoke the second.

  beb-depot authorize KEYFILE
      let a courier connect; KEYFILE is its public key, or - for stdin
  beb-depot unauthorize COURIER
      stop it connecting, and remove every queue grant it holds

  beb-depot grant COURIER RECIPIENT
      let a courier collect for one recipient queue
  beb-depot revoke COURIER RECIPIENT
      stop it collecting for that one

  beb-depot held
      queued mail, and the recipients it is waiting for
  beb-depot status
      whether this install still matches the authorized_keys entries
  beb-depot serve [--root PATH] FINGERPRINT
      serve one connection; sshd runs this, not you

  beb-depot --help
  beb-depot --version

A courier normally asks for a queue itself, with beb-courier register,
signed and sent over a connection authorize already allowed. Use grant
when the recipient cannot ask.

A COURIER is a fingerprint, or the key file it came from, or - for that
key on stdin. A RECIPIENT is a 64-character lowercase hex id, or a beb
identity's public key file, or - for that key on stdin. Given a key,
either is derived from it, so nothing long is ever typed.

Exit: 0 did it, 1 change the command, 2 nothing to do, 3 refused.

A frame may be at most 64 MiB. A queue holds at most 10000 frames or
1 GiB, and frames older than 30 days go when it is next used. None of
those four is configurable.

BEB_DEPOT_ROOT is the storage directory, ~/.local/share/beb-depot by
default: one grant per line in allowed, and one frame per file under
inbox/<recipient>/<id>.

BEB_DEPOT_AUTHORIZED_KEYS is the authorized_keys file authorize writes,
~/.ssh/authorized_keys by default. Each entry looks like:

  command="'/path/to/beb-depot' serve --root '/path' SHA256:...",restrict ssh-...

The fingerprint in it is who beb-depot takes the connection to be, which
is why authorize needs the key and cannot take a fingerprint.
```

## Is it wired correctly

There is nothing to start or enable: sshd runs the depot per connection
and it exits with the connection. So `status` reports whether the lines
sshd reads still describe this install, rather than whether a daemon is
up.

```console
$ beb-depot status
beb-depot: 0.2.0 at /usr/local/bin/beb-depot, root /home/beb/.local/share/beb-depot (700)
beb-depot: 4 lines in ~/.ssh/authorized_keys, 4 may connect, 6 grants, 0 waiting
beb-depot: sshd runs this on each connection; check it with your service manager
```

It compares what the forced command says against what is installed, and
exits 3 when they disagree:

```console
$ beb-depot status
beb-depot: line 2 runs /home/op/src/beb-depot/target/release/beb-depot, and this is /usr/local/bin/beb-depot
beb-depot: line 3 serves --root /srv/old, but the grants are in /home/beb/.local/share/beb-depot
beb-depot: 2 things do not agree
```

In production, both outages we have seen were that pair drifting apart.

## The wire

`serve` answers six intents and refuses everything else:

```sh
ssh depot "drop <recipient>"   # one frame on stdin
ssh depot pickup               # stream, then block when empty
ssh depot drain                # stream, then return when empty
ssh depot register             # a signed claim on stdin, verified here
ssh depot "unregister <recipient>"
ssh depot granted              # what this courier may collect for
```

Collecting streams `<recipient> <id> <bytes>` and then exactly that
many bytes, over and over on the one connection. Reply `ack <id>` once
beb has taken it; nothing is deleted before the ack, so a courier that
dies mid-transfer loses nothing and the beb on the far end deduplicates
whatever it is handed twice.

`pickup` blocks because that is the only way an unreachable client
learns anything. `drain` exists because a run at a turn boundary has to
finish.

A `register` claim is an address, the fingerprint it authorises, and an
sshsig over those two lines. The queue it grants is derived from the
signed key, so a claim can only ever be about the identity that made it.
`unregister` removes one, and carries no signature. `granted` is
read-only and answers only about the caller.

## Design

Storage is keyed by recipient, not by courier, and what it trusts is
sshd alone: that the fingerprint in its own command line names the key
that authenticated.

[DESIGN.md](DESIGN.md) has the storage layout, the custody rules, and
what a claim has to prove.

## License

MIT
