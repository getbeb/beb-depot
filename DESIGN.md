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

## Depend on an interface, never compute what the other computes

Which is the line all three programs hold, and it is narrower than
"know nothing about each other" for a reason: a courier that knew
nothing about beb would need three knobs where it has none, since beb's
filename is what makes a routing table unnecessary.

The storage here is already opaque. A recipient is sixty-four lowercase
hex characters and a frame is bytes nothing opens, so what waits here
could be anything.

The place it looks like this rule is broken is `authorize`, `grant` and
`register`, which turn a public key into a queue name. That is not beb's
naming rule being copied. **This depot keys storage by the recipient's
key**, which is its own decision, stated above, and hex of the 32 raw
bytes is the encoding of that key rather than a second opinion about
what beb calls a mailbox. The two agree because there is one sensible
encoding of 32 bytes, not because either is reading the other.

Where it would be broken is putting that derivation somewhere it is not
needed. `register` must relate a key to a queue: it verifies a signature
made by a key and has to grant that key's queue and no other, and no
arrangement of the claim avoids it. `unregister` verifies nothing, so it
takes a queue name and the courier hands it through without
understanding it. The convenience of piping `beb whoami` into both would
have cost a derivation on the wire to save a paste, and `status` naming
the address is the answer to that instead.

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
    pickup               stream every frame waiting for a key this
                         courier may collect, waiting for an ack after
                         each; when there are none, block
    drain                the same, but when there are none, return

`pickup` blocks because that is the only way an unreachable client
learns anything: it holds the connection open and the depot answers
inside it. One-way ssh is one-way about who *initiates*.

`drain` exists because a courier run at a turn boundary has to finish.
The two differ in nothing but an empty queue, so they are one code path
and one flag rather than two that could drift.

What it blocks on is the client as much as the directory. sshd does
not signal a forced command when its connection closes, so a `pickup`
that only slept between looks went on reading an empty directory four
times a second for as long as the machine stayed up, one process per
courier that ever disconnected while waiting. It waits on the client
instead: the same quarter second when nothing happens, and an
immediate exit when the far end hangs up. A courier that waited and
left has done nothing wrong, so that exit is a 0.

## Two questions, two pairs of verbs

Who may connect is one question, and which queues they may collect is
another. They were one act while both answers had to reach a machine the
courier was built to be unable to talk to, and `register` ended that.

    authorize / unauthorize     the courier: may it connect at all
    grant / revoke              the queue: may it collect for that one

**`authorize` is the only verb here that cannot take a fingerprint**, and
the reason is not a preference. A fingerprint is a hash of the key, and
the line sshd reads has to carry the key itself:

    command="…",restrict ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA… courier@laptop

sshd matches what a client offers against that blob, and nothing can
rebuild it from a digest. A key store to look one up in would be a
second copy of `authorized_keys`, able to disagree with the first.

So the fingerprint is the name and the key is the thing. Exactly one
verb introduces a courier and needs the thing; everything after refers to
it by name, which is why `grant`, `revoke`, `serve`, `status` and
`allowed` all speak fingerprints. `unauthorize` refers, so it takes
either: the name, or the key file it is derived from.

Nothing is transcribed on either axis. The courier's fingerprint comes
from `ssh-keygen -lf`; a recipient may be given as a queue name, since
that is what a courier puts on the wire, or as the identity's public key
file, whose queue name is its 32 raw ed25519 bytes in hex.

The fingerprint used to be typed twice, once into each file, 43 base64
characters that had to agree. When they disagreed nothing noticed,
because from inside the depot the fingerprint simply *is* the caller: a
mistyped one means one courier quietly collecting another's mail. So it
is derived, and `authorize` also refuses a key already in
`authorized_keys` under a different command, which is the same mistake
arriving from the other direction.

This is gitolite's answer to the identical problem -- one Unix account,
many keys, a forced command carrying the identity -- by generating
`authorized_keys` rather than letting an operator write it. What stays
human is the decision: this key connects.

`authorize` still reads the file `beb-courier whoami` prints, and takes
only the key out of it. The addresses beside it are named in the ack and
left alone, because that list is a snapshot of what the machine read the
day it was printed, and granting from a snapshot is how a grant list
goes quietly stale. The identities say it themselves now, and say it
signed.

## register, and why it eventually earned its weight

`authorize` fixed the transcription, which was the real problem with
operator-granted access: it was never that a human decides, it was that
a human copies 43 base64 characters into two files that must agree. What
it did not fix was frequency. The key crosses once; the list of who
reads on that machine goes stale every time somebody runs `beb init`,
and re-declaring it meant another round trip to a machine the courier
was built to be unable to reach.

A handover crosses because it must. After it has, the two machines can
talk, and the identity can say the thing itself:

    register        read a claim from stdin, verify it, and grant

A claim is three parts: the address, the fingerprint it authorises, and
an sshsig over exactly those two lines.

    ssh-ed25519 AAAA…
    SHA256:abc…
    -----BEGIN SSH SIGNATURE-----

Verified with no trust store, which the depot could not have had anyway.
The key is in the claim, so the one-line `allowed_signers` handed to
`ssh-keygen -Y verify` is built from the thing being checked -- the same
move beb makes on an envelope, for the same reason: there is nothing
here that would know which keys to believe.

Three checks, and the third is what the protocol is for.

**The signature verifies**, in the namespace `beb-collect` and no other.
An envelope is signed in `beb`, so a message can never be replayed as a
claim on a queue.

**The fingerprint in the claim is the one sshd says is calling.** So an
intercepted claim is useless to anybody else, and a claim is not a
bearer token.

**The queue is derived from the signed key, never named beside it.**
This is the one that keeps a valid claim from being aimed somewhere
else. A courier that could put the queue name in a field could present
somebody's genuine claim and ask for a third party's mail; deriving it
means the grant can only ever be for the identity that signed.

`grant` stays, and did not become the weaker second way this document
once worried about, because the two answer different questions.
`register` is a machine saying "this identity reads here". `grant` is an
operator saying "collect for that one", which is still the only way to
give a queue to a courier that cannot sign for it.

`unregister <recipient>` is the courier giving up its own grant, and
carries no signature. sshd already said who is calling and a courier can
only remove its own line, so the worst it can do is stop its own mail.
Adding a claim asserts something about an identity; dropping one asserts
nothing. It is refused while frames are still waiting and nobody else
collects for that recipient, because taking the last grant turns the
next drop into a refusal and leaves what is already here with no
collector: closer to deleting than to tidying, and one `sync` away from
being neither.

`revoke` is the operator's half of the same act, for the machine that
never comes back. It cannot call in to give anything up, and its grant
would otherwise keep a queue alive that nothing collects -- the one
failure neither side can see from where it stands, since the depot sees
a grant and the sender sees mail accepted.

**`revoke` tidies a grant; it does not evict a machine**, and once
`register` existed the difference stopped being academic. A courier
whose line is still in `authorized_keys` can connect, and if it still
holds an identity's key it signs a fresh claim and takes the grant
straight back, in one command and without an operator. Re-granting used
to need one; it does not now.

So `unauthorize` is the inverse of `authorize`, and the only thing here
that cuts a machine off. `authorize` wrote two things, a line sshd reads
and a set of grants, and both go: leaving the grants would keep `drop`
accepting mail for a queue no courier can ever come for, which is the
hazard this document names elsewhere and would be creating on purpose.

It is the one place that rewrites `authorized_keys` rather than
appending, which `authorize` refuses to do, and there is no way around
it -- a line cannot be removed by appending. Written beside and renamed
over, so no reader sees half a file, and each line it takes is printed
first, because that file is one other things also write to.

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
