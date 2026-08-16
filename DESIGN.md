# beb-depot

A place mail waits when the two machines cannot reach each other.

## Why it exists

beb delivers into a mailbox on one machine. Two agents on two machines
need something between them, and in a real network that something is
not a direct link: clients can reach a hub, the hub can reach nobody.
NAT, firewalls, laptops that sleep. One flat network, one depot;
depot-to-depot is out of scope.

So the depot is the one address everybody can reach. It holds frames
for keys that read somewhere else, and hands them over when their
owner asks.

## What it is not

**It does not run beb.** No spool, no mailboxes, no `.beb`, no cursor.
A frame that lands here has not been delivered; it is waiting. beb's
`drop` would have to *install* it, which would make the depot the
recipient, which it is not.

**It does not parse frames.** The recipient arrives as an argument,
supplied by whoever hands the bytes over. Nothing here reads an
envelope, and nothing here verifies a signature: a signature
authenticates the sender to the *reader*, and the depot is neither.

**It is not a transport.** It answers a connection somebody else
opened. Which scheme carried the bytes is the courier's business, and
the depot would store them the same either way.

## Storage

    inbox/
    └── d811f21767d40b61.../      one directory per recipient key,
        ├── 000000000000000001    named for the key itself
        └── 000000000000000002    each file a whole frame

    allowed                       one line per grant:
                                  SHA256:abc... <recipient>

Keyed by **recipient**, not by courier. Three things follow:

- a drop is a write with no lookup, so it cannot fail on a grant that
  is missing or stale
- moving an identity to another machine moves no files; the new
  courier drains the same directory
- who may collect is consulted once per session, on collection, where
  it is an authorisation question rather than a routing one

`allowed` is one flat file rather than a directory per courier because
the only two questions ever asked of it are "does this line exist" and
"what may this fingerprint collect", and both are a scan of a file an
operator can read, grep, diff, and edit. A directory would be the
right shape at a scale this depot does not have.

## How a connection works

sshd runs the depot as a forced command, with the connecting courier's
fingerprint baked into the line:

    command="'/usr/local/bin/beb-depot' serve --root '/srv/beb' SHA256:abc...",restrict ssh-ed25519 AAAA...

So the depot never decides who is calling; sshd decided, and the
fingerprint is not something the caller can change. A courier cannot
ask for another's mail because it cannot reach it, which is better
than a check that says no.

Everything the connection needs is in that line, because a forced
command inherits none of the operator's environment: no PATH worth
using and no `BEB_DEPOT_ROOT`. A depot that read its root from the
environment would serve out of the default one and find no grants at
all -- silently, since an empty allow list and the wrong allow list
look identical from inside. Each argument is single-quoted because
sshd hands the string to a shell, so a path with a space in it would
otherwise arrive as two arguments.

Two intents:

    drop <recipient>     read one frame from stdin, file it under
                         inbox/<recipient>/
    pickup               block until something is waiting for a key
                         this courier is allowed to collect; stream it;
                         wait for an ack; delete

`pickup` blocks because that is the only way an unreachable client
learns anything: it holds the connection open and the depot answers
inside it. One-way ssh is one-way about who *initiates*.

## Who may collect, and why there is no register

A courier collects for a recipient because an operator said so:

    beb-depot authorize courier.pub d811f21767d40b61...

One act: the key goes into `authorized_keys` behind the right forced
command, and the grant goes into `allowed`.

Both halves in one command because the fingerprint is the whole of the
depot's notion of who is calling, and it used to be typed twice -- once
into each file, 43 base64 characters that had to agree. When they
disagreed nothing noticed, because from inside the depot the
fingerprint simply *is* the caller; a mistyped one means one courier
quietly collecting another's mail. So `authorize` derives it with
`ssh-keygen -lf` and nobody transcribes anything. It also refuses a key
that is already in `authorized_keys` under a different command, which
is the same mistake arriving from the other direction.

This is gitolite's answer, which solves the identical problem -- one
Unix account, many keys, a forced command carrying the identity -- by
generating `authorized_keys` rather than letting an operator write it.
What stays human is the decision: this key, these recipients.

`allow` remains for the case where the key is already in
`authorized_keys`: one more recipient, no new courier.

The design once had a `register` verb instead -- the courier
presenting a claim signed by each identity it holds, binding the
identity key, the courier key, this depot, the operation, a nonce and
an expiry -- and that protocol is right, but it buys one thing: adding
an identity to a machine without an operator touching the depot. That
is a scaling property, not a correctness one.

It is worth noticing what the real problem with operator-granted
access turned out to be. It was never that a human decides; it was
that a human transcribes. `authorize` fixes the transcription, and a
signature-verification path stops being worth its weight.

The two are not alternatives to hold side by side. A depot that
verifies signed claims does not also want a second, weaker way to
grant the same thing; when `register` arrives it should replace
`allow`, which is why `allow` stays deliberately thin -- a line in a
file, with nothing built on top of it.

What makes deferring safe is that neither the wire nor the storage
knows how a grant was made. `allowed` is consulted in one place, on
collection, and a signed claim would write the same line.

## Custody

The depot deletes a frame when the courier says it landed, and not
before. A connection that dies mid-stream leaves the frame here, and
the next collection offers it again -- which is safe because the
receiving beb deduplicates.

Nothing here retries, schedules, or expires. The depot holds and hands
over; deciding when to try again is the courier's.

## Limits

Any connecting courier may drop for any allowed recipient, so disk is
bounded by policy rather than by trust. These are the depot's only
opinions, and it needs them because it cannot tell a mistake from an
attack.

There are three, and they are constants rather than settings, because
an opinion every deployment states differently is not an opinion:

    64 MiB     one frame, refused before a byte of it is stored
    10000      frames waiting for one recipient
    1 GiB      bytes waiting for one recipient
    30 days    how long any frame may wait

The frame ceiling bounds a single mistake. The per-recipient caps bound
a persistent one -- a courier that never comes back, a sender in a loop
-- and there are two of them because the two ways to fill a disk are
not the same shape: many small frames exhaust a directory, and an
operator's patience, long before they exhaust the space.

Expiry runs on traffic, not on a timer, because the depot has no
process of its own -- every connection is one sshd child that exits. A
drop sweeps the queue it is about to write to, a pickup sweeps the
queues it may collect from, and `held` sweeps everything, which is what
reaches a queue no sender and no courier has touched in a month. A
clock that has moved backwards counts as not expired: the one thing a
sweep must never do is delete mail because the time was wrong.

A drop pays for this, since deciding what has expired means stating
every frame in the queue. Against an empty queue's 14.9ms, five
thousand frames waiting add 16ms -- and the same pass yields the counts
the caps are checked against, so nothing is walked twice.

## What it trusts

Nothing about the bytes. A frame is opaque, signed by somebody the
depot has no opinion about, addressed to somebody it merely stores
for. What it trusts is sshd: that the fingerprint in its own command
line names the key that authenticated. Everything else follows from
that one fact.
