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

    command="beb-depot serve SHA256:abc...",restrict ssh-ed25519 AAAA...

So the depot never decides who is calling; sshd decided, and the
fingerprint is not something the caller can change. A courier cannot
ask for another's mail because it cannot reach it, which is better
than a check that says no.

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

    beb-depot allow SHA256:abc... d811f21767d40b61...

One line, next to the `authorized_keys` line that let the courier
connect at all. The design once had a `register` verb instead -- the
courier presenting a claim signed by each identity it holds, binding
the identity key, the courier key, this depot, the operation, a nonce
and an expiry -- and that protocol is right, but it buys one thing:
adding an identity to a machine without an operator touching the
depot. That is a scaling property, not a correctness one, and it is
not worth a signature-verification path here while the trust boundary
is already a human act at the same moment.

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

Today there is one: a maximum frame size, refused before a byte is
stored. Still owed are a per-recipient byte and item cap, and an age
after which a frame is dropped. The frame ceiling bounds a single
mistake; the other two bound a persistent one, which is the case a
depot left running unattended actually meets.

## What it trusts

Nothing about the bytes. A frame is opaque, signed by somebody the
depot has no opinion about, addressed to somebody it merely stores
for. What it trusts is sshd: that the fingerprint in its own command
line names the key that authenticated. Everything else follows from
that one fact.
