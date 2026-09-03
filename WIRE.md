# uictl wire protocol

**Status:** complete. **Protocol version:** 1. **Daemon:** 0.3.0.

This is the normative specification of the protocol spoken between a
uictl client and `uictld` over the `AF_UNIX` socket at
`$XDG_RUNTIME_DIR/uictld.sock`. It exists so that a consumer can be
written in any language without linking `libuictl` — the C library is a
convenience, this document is the contract.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be
interpreted as in RFC 2119.

Where this document and `src/proto.h` disagree, **this document is
wrong** and should be fixed — the header is generated from the same
decisions but is checked by the compiler.

## Contents

| § | Section | Status |
|---|---|---|
| 1 | **Transport** | **normative** |
| 2 | **Frame format** | **normative** |
| 3 | **Handshake** | **normative** |
| 4 | **Result codes and response classes** | **normative** |
| 5A | **Opcodes — the pointer** | **normative** |
| 5B | **Opcodes — the keyboard, and `BATCH`** | **normative** |
| 6 | **Held state** | **normative** |
| 7 | **Confirmation** | **normative** |
| 8 | **Connection lifecycle and restart** | **normative** |
| 9 | **Conformance vectors** | **normative** |

---

# 1. Transport

## 1.1 The socket

One `AF_UNIX`, `SOCK_STREAM` socket at **`$XDG_RUNTIME_DIR/uictld.sock`**.

If `XDG_RUNTIME_DIR` is unset the daemon MUST refuse to start. It does
not fall back to `/tmp`: a world-writable directory means another user
can pre-create the path, win the race, and own the name every client
connects to.

`SOCK_STREAM`, never `SOCK_DGRAM`. Datagrams make request/response
impossible to match, make `SO_PEERCRED` unreliable, and make a
variable-length payload awkward — and on a local `AF_UNIX` socket a
stream costs nothing extra.

**The socket file's mode is `0700`** (`srwx------`), and it gets that
mode because the daemon calls `umask(0077)` **before** `bind()`. The
kernel creates the node with `0777 & ~umask`; there is no window in
which it exists at any looser mode. `fchmod()` after `bind()` would
leave exactly such a window, and a process that wins it can `connect()`
and keep that connection after the mode tightens — the check is at
`connect()` time, not per-write.

> The mode is `0700`, not `0600`. Earlier prose in `plan.md` said
> `0600`, describing an intent rather than the syscall: `umask(0077)`
> cannot clear the owner-execute bit, and `bind()` does not ask for one.
> The execute bit on a socket node means nothing to anything. What
> matters is that all six group and world bits are clear.

The path is `unlink()`ed before `bind()`, so a stale node from a crashed
daemon does not produce `EADDRINUSE`. That unlink is safe only because
§1.4 has already established that no other daemon is live.

Both the listening socket and every accepted connection are created with
`SOCK_CLOEXEC` (`socket()` and `accept4()` respectively). The daemon
never `exec`s anything today — `plan.md` forbids it — but an fd that
leaks across a future `exec` is an input device handed to a process
nobody audited.

The listen backlog is 16.

## 1.2 Who may connect

**`SO_PEERCRED` is the only identity in this protocol that cannot be
forged.** Immediately after `accept4()`, before the connection is
entered in any table, the daemon reads `struct ucred` and MUST refuse
the peer if `cred.uid != getuid()`.

The `0700` mode already enforces this in practice. The explicit check is
what survives a configuration mistake the mode cannot cover — a
misconfigured mount, a sandbox that forwards an already-connected fd, a
future `--allow-uid` extension — and it costs one `getsockopt`.

`cred.pid` is the key for every per-peer limit in this document: the
admission storm counter (§1.3), the per-pid connection cap (§1.3), and
the rate-limit bucket (§5A.0). A client cannot choose it. This is the
whole reason `source_tag` is advisory (§2.5): the fields a client writes
itself are never policy inputs.

A refusal at this stage happens before the peer is a connection, so
there is no request to answer. The daemon still writes one frame before
closing, best-effort and without blocking:

| field | value |
|---|---|
| `version` | the daemon's `UICTL_PROTO_VERSION` |
| `opcode` | `0` (`OP_INVALID`) |
| `source_tag` | `0` |
| `seq` | `0` |
| `payload_len` | `2` |
| payload | the `u16` result code |

A client MUST be prepared to read this frame at any point after
`connect()` succeeds, including before it has sent anything.
`connect()` succeeding means the kernel queued the connection, not that
the daemon admitted it. A client that treats "connected" as "admitted"
reports a refusal as a mysterious EOF.

## 1.3 Admission: three checks, in this order

Every accepted fd passes three checks before it becomes a connection.
All three refuse with **`ERR_BUSY`**, which is retryable — none of them
says anything is wrong with the client.

1. **Connection-attempt storm** — at most 60 attempts per peer pid in a
   sliding 10 s window (§8.7). Runs first, and the order is load-bearing:
   it has to count attempts the other two would refuse anyway, or a
   client hammering a full table is never recorded and can retry at full
   speed forever. It is also the cheapest of the three.
2. **Per-pid connection cap** — `MAX_CONNS_PER_PID = 4`. The reaper
   cannot substitute for this: an idle connection with no frame in
   progress is well-behaved by this daemon's own rules, so 32 idle
   connections from one pid are 32 innocent connections, and this is the
   only thing that stops them from being all of them.
3. **Global connection table** — `MAX_CONNS = 32`.

The daemon `accept()`s and then closes a connection it will not serve,
rather than leaving it queued: an unaccepted connection keeps the
listening socket readable forever and the daemon spins.

`ERR_BUSY` is deliberately not `ERR_DENIED_BY_POLICY`. "No room right
now" clears in milliseconds; "your uid is wrong" never clears. A client
that cannot tell them apart either hammers a daemon that told it to go
away, or gives up on a transient condition.

## 1.4 One daemon per user

Singleton enforcement is **`flock(LOCK_EX|LOCK_NB)`** on
`~/.local/state/uictl/uictld.lock` (mode `0600`), taken before the
socket is bound.

Not a connect-probe. Two daemons starting in the same instant both get
`ECONNREFUSED` from a probe, both conclude they are alone, and both race
to `unlink` and `bind` — the loser's clients connect to a socket node
its owner has already replaced. `flock` has no such window, and the lock
is released by the kernel however the process dies, including `SIGKILL`.

`~/.local/state/uictl/` MUST be mode `0700` and owned by the invoking
uid; the daemon checks `st_uid` and `st_mode & 0077` on the directory
and on `audit.log`, and refuses to start if either is loose. The
directory holds the lock and the audit log, and an audit log another
user can write is not an audit log.

## 1.5 Byte order

**Little-endian, always.** Every multi-byte field in this document is
little-endian, on every architecture. There is a `_Static_assert` in
`proto.h` that fails the build on a big-endian target rather than
shipping a daemon that silently disagrees with its clients.

Do **not** use `htons`/`htonl` to encode this protocol. Those are
network byte order — big-endian — and on the little-endian machines this
runs on today they would byte-swap every field into garbage. The wire is
the native layout of the structs, `memcpy`'d.

This is a per-user local socket, not a network protocol; a portable
encoder would be work spent on a case that cannot occur, and the assert
is what stops that assumption from becoming silent.

## 1.6 The daemon never blocks on a client

Every fd is non-blocking and driven by `epoll`. Three consequences a
client can observe:

- **Fairness cap.** One connection may have at most
  `CONN_FRAMES_PER_TURN = 32` frames dispatched for it per `epoll_wait`
  turn. This is not a rate limit — it does not slow anyone down over
  time — it bounds how long one connection can own the loop before the
  others are looked at.
- **Partial frames are reaped.** A connection that has delivered part of
  a frame and gone quiet for `CONN_PARTIAL_TIMEOUT_SEC = 5` is closed.
  The reaper scans every `REAPER_TICK_SEC = 1`, so the effective deadline
  is 5–6 s, not exactly 5. A client MUST NOT send a header and then wait
  on something else before sending the payload.
- **Undelivered responses are reaped.** A connection whose reply has been
  staged but not drained for the same 5 s is also closed — a peer that
  stops *reading* occupies a slot exactly as a peer that stops *sending*
  does. No error frame is attempted on this path: the peer is by
  definition not reading, so the write could block the daemon, which is
  the failure this whole design removes.

A reaped connection is closed, and closing releases everything it held
(§6.4.1, §8.3).

`SIGPIPE` is set to `SIG_IGN` at startup. A client that vanishes
mid-reply produces `EPIPE` on a `write()` the daemon handles, not a
signal that kills it.

---

# 2. Frame format

## 2.1 The header

Every frame — request, response, and the one unsolicited daemon frame —
begins with the same 16-byte header.

```c
struct uictl_frame_header {
    uint16_t version;
    uint16_t opcode;
    uint32_t source_tag;
    uint32_t seq;
    uint32_t payload_len;
};
```

| offset | size | field | |
|---|---|---|---|
| 0 | 2 | `version` | protocol version this frame is stamped with |
| 2 | 2 | `opcode` | see §2.2 |
| 4 | 4 | `source_tag` | **advisory only**, see §2.5 |
| 8 | 4 | `seq` | client's request id, echoed verbatim |
| 12 | 4 | `payload_len` | bytes following the header |

Exactly 16 bytes, asserted at compile time. There is no padding and no
alignment hole: `u16 u16 u32 u32 u32` packs exactly.

`payload_len` MUST NOT exceed **`UICTL_MAX_PAYLOAD = 4096`**. It is the
single most attacker-controlled field in the protocol — a `u32` that the
very next read uses as a length into a 4 KB buffer — so the daemon
bounds it *before* it is copied anywhere, and before anything else about
the frame is considered except the version.

## 2.2 Opcodes

Opcode values are on the wire. **Append only, never renumber**: a client
built against an older header must keep meaning the same thing by the
same number.

| # | opcode | direction | § |
|---|---|---|---|
| 0 | `OP_INVALID` | — | never sent as a request; appears in refusals (§1.2) |
| 1 | `OP_PING` | c→d | §2.7 |
| 2 | `OP_MOVE_ABS` | c→d | §5A.1 |
| 3 | `OP_HELLO` | c→d | §3 |
| 4 | `OP_KEY_TAP` | c→d | §5B.1 |
| 5 | `OP_KEY_SEQUENCE` | c→d | §5B.2 |
| 6 | `OP_KEY_DOWN` | c→d | §5B.3 |
| 7 | `OP_KEY_UP` | c→d | §5B.3 |
| 8 | `OP_CONFIRM_SUBSCRIBE` | c→d | §7 |
| 9 | `OP_CONFIRM_REQUEST` | **d→c** | §7 |
| 10 | `OP_CONFIRM_DECIDE` | c→d | §7 |
| 11 | `OP_BUTTON` | c→d | §5A.4 |
| 12 | `OP_MOVE_REL` | c→d | §5A.2 |
| 13 | `OP_SCROLL` | c→d | §5A.3 |
| 14 | `OP_BATCH` | c→d | §5B.4 |

A client MUST NOT infer the set of implemented opcodes from this table
or from `daemon_version`. It discovers them from `opcode_bitmap` in the
`HELLO` response (§3.4), where bit *N* set means opcode *N* is
implemented by *this* daemon. Feature-sniffing by version number is how
a protocol acquires a compatibility matrix nobody can test.

An opcode the daemon does not implement is answered `ERR_OPCODE_UNKNOWN`
(2), per-frame, and the connection survives.

## 2.3 The payload

`payload_len` bytes follow the header, laid out per opcode. `OP_PING`
and `OP_CONFIRM_SUBSCRIBE` carry none: `payload_len == 0`, and the frame
is the whole message.

**Command payloads are exact-size, never "at least".** A command frame
is only ever sent after the version has been negotiated and pinned
(§3.3), so there is no version skew to absorb, and a wrong length means
a broken client — the stricter check is the better one. The one
exception is `OP_HELLO`, which is checked with `>=` for the reason §3.1
gives.

Reserved fields MUST be zero. They are wire space the daemon *reads and
rejects* rather than ignores, so that a future field cannot collide with
junk an old client happened to leave there.

## 2.4 Responses

**A response is the request's header echoed** — `version`, `opcode`,
`source_tag`, `seq` unchanged — with `payload_len` rewritten, followed
by:

```
uint16_t result;      /* always present, always first */
uint8_t  data[...];   /* opcode-specific, may be empty */
```

so every response has `payload_len >= 2`, and the answer's length is
`payload_len - 2`.

Two things follow from `result` being first rather than living in a
separate reply header. An old decoder that reads two bytes and stops
still reads the right two bytes; and adding an answer to an opcode that
previously only acknowledged costs a length check moving from `==` to
`>=`, not a protocol version. Before this, `payload_len` was hardcoded
to 2 and the daemon could acknowledge a command but never answer a
question — which is why `OP_HELLO` had nowhere to put a capability set.

**Response data grows append-only.** A client MUST accept a response
longer than it understands and ignore the tail; it MUST NOT require an
exact length. `uictl_resp_hello` has already used this once — it grew
from 24 to 32 bytes in §8.6 with no version bump, and a test asserting
`>= 24` kept passing untouched.

## 2.5 `source_tag` is advisory. Permanently.

The client writes `source_tag` itself, in every frame, unauthenticated.
It MUST NOT be an input to any decision. Its only legitimate consumer is
the audit log, where it is a hint about what the client *says* it was
doing.

Do not key a rate limit, a deny-list, an allowlist, a confirmation
prompt, or anything else on it. That was the original design — a token
bucket keyed on `source_tag`, CLI 50/s versus LLM 5/s — and it does not
work for the exact case it exists for: the LLM agent sets `SRC_CLI` and
gets 50/s. **A client choosing its own limit is not a limit.**

The policy inputs are, and remain, the peer pid/uid from `SO_PEERCRED`
(§1.2) and the class the daemon derives at `HELLO` from its own local
registry (§3.5). Both live on the daemon's side of the socket.

Defined bits: `SRC_CLI` (1), `SRC_HOTKEY` (2), `SRC_LLM` (4).

## 2.6 Per-frame errors, and the two that kill the stream

Most refusals are **per-frame**: the payload was fully consumed, the
next frame boundary is known, and the connection continues. A client may
send its next request immediately.

Exactly two are **fatal to the stream**. Both are detected at the header,
before the payload is read, and both leave the daemon unable to find the
next frame boundary:

| result | why the stream is lost |
|---|---|
| `ERR_VERSION` (1) at the header | the version is rejected, so `payload_len` is not trustworthy either |
| `ERR_TOO_LARGE` (5) | those payload bytes are still queued and would be misparsed as the next header |

On both the daemon writes the error frame **and then** closes, in that
order — the close waits for the reply to actually drain. An earlier
version wrote best-effort and closed immediately, and a client whose
reply did not drain learned nothing but "connection reset".

Note that `ERR_VERSION` is *also* returned per-frame, by the `HELLO`
handler, when the two version ranges do not overlap (§3.3). The
difference is where it was detected: at the header the payload has not
been read, in the handler it has. Same code, and a client library should
not need to tell them apart — one closes and one does not, which it
observes either way.

## 2.7 Ordering, pipelining, and the one unsolicited frame

Responses on a connection arrive **in request order**. A client may
pipeline — the daemon dispatches up to 32 frames per turn (§1.6) — and
matches replies by position or by `seq`. A confirmable request parks the
connection and stops it being read until the decision resolves (§7), so
ordering holds there too.

`seq` is opaque to the daemon. It is never interpreted, never
range-checked, and never required to be unique or increasing; it is
echoed so a client can match a reply to a request. It appears in the
audit log.

**`OP_CONFIRM_REQUEST` (9) is the single exception to request/response.**
It is sent by the daemon, unprompted, to a client that has subscribed
with `OP_CONFIRM_SUBSCRIBE`. A confirmer MUST therefore be written to
read frames it did not ask for. A normal client never sees one, because
the daemon only ever pushes on a connection that subscribed — but a
client library that assumes "one read per write" forever is a library
that cannot host a confirmer.

`OP_PING` (1) carries a zero-length payload and answers `OK` with no
data. It is exempt from the handshake (§3.7) and free of rate-limit
charge, so it stays usable as a bare liveness probe by a supervisor, a
health check, or `uictl ping`.

---

# 3. Handshake

`OP_HELLO` is **mandatory**. Every opcode except `OP_PING` and
`OP_HELLO` itself is refused with `ERR_HANDSHAKE_REQUIRED` (8) until it
has succeeded on *this connection*.

The handshake is where the daemon derives the client's class from its
own registry. Without it, a client that skips `HELLO` operates at
whatever the un-negotiated default is, forever.

## 3.1 The request

```c
struct uictl_payload_hello {
    uint16_t proto_min;
    uint16_t proto_max;
    char     client_name[32];   /* UICTL_CLIENT_NAME_MAX */
};
```

Exactly 36 bytes as defined today. The daemon checks
`payload_len >= 36`, **not `==`** — the only `>=` in the protocol.

**`HELLO` is the version-invariant bootstrap frame.** Its envelope and
the prefix of its payload are fixed for all protocol versions, and the
daemon accepts a `HELLO` stamped with *any* version. Otherwise
negotiation is impossible for exactly the clients that need it: a v9
client talking to a v1 daemon cannot send a v9-stamped frame the daemon
would admit, and cannot know to send a v1-stamped one until it has
asked. The bootstrap frame has to be readable before agreement exists.

The payload grows append-only for the same reason: an older daemon reads
the prefix of a newer client's `HELLO`, answers with its own range, and
the client retries inside it. Every *other* opcode is gated on the
negotiated version.

`client_name` is fixed-width and NUL-terminated rather than
length-prefixed. At 32 bytes the waste is irrelevant, and a fixed width
means the payload has exactly one legal size — one fewer thing for a
decoder to get wrong.

## 3.2 What the daemon checks, in order

1. **Duplicate `HELLO` on this connection** → `ERR_DENIED_BY_POLICY` (4).
   See §3.6.
2. **Name validity** → `ERR_PAYLOAD_INVALID` (3). See §3.5.
3. **`proto_min > proto_max`** → `ERR_PAYLOAD_INVALID`. An inverted range.
4. **Header version outside the declared range** → `ERR_PAYLOAD_INVALID`.
   The frame is self-describing, so it MUST NOT contradict itself: a
   client claiming to speak 2–3 while stamping this very header version 1
   has a bug, and guessing which half to believe is how a negotiation
   ends with two disagreeing parties that both think they succeeded.
5. **Range intersection** → `ERR_VERSION` (1) if empty. See §3.3.

All five are per-frame, not fatal. `hello_seen` is set only on success,
so a client MAY retry `HELLO` with a different range on the same
connection.

## 3.3 Version selection

The daemon speaks `[UICTL_PROTO_MIN, UICTL_PROTO_MAX]` — currently
`[1, 1]`. The client declares `[proto_min, proto_max]`. The selected
version is the **highest mutually supported**:

```
lo = max(client.proto_min, daemon.MIN)
hi = min(client.proto_max, daemon.MAX)
selected = hi          if lo <= hi
ERR_VERSION            otherwise
```

Highest, because both sides claim to speak everything in their range, so
the newest common version has the most features and no downside.

**The version is then pinned for the life of the connection.** Every
subsequent frame MUST carry `version == selected` or it is refused with
a fatal `ERR_VERSION` (§2.6). Allowing a client to hop versions
mid-connection would mean the same opcode could carry two different
payload layouts on one stream and the daemon would be guessing which one
it had just parsed. Negotiation that can be revised is not negotiation.

Before `HELLO` succeeds, a non-`HELLO` frame is admitted at any version
the daemon speaks — the pin does not exist yet.

### 3.3.1 When to bump the version

**Bump `UICTL_PROTO_MAX` only for a change that breaks an existing
decoder**: a field resized, reordered, or given a new meaning.

Do **not** bump for additions. A new opcode is discovered through
`opcode_bitmap`, a new device ability through `device_caps`, and a new
trailing field through the append-only response rule (§2.4). That is the
entire point of shipping a capability map, and it is why adding
`OP_HELLO` itself needed no bump. Raise `UICTL_PROTO_MIN` only to drop
support for an old version, which is a deliberate compatibility break.

## 3.4 The response

`result` is `OK`, followed by:

```c
struct uictl_resp_hello {          /* 32 bytes */
    uint16_t proto_selected;       /* version pinned for this connection */
    uint16_t device_caps;          /* CAP_* bits                         */
    uint32_t abs_range_max;        /* ABS_X/ABS_Y max, device units      */
    uint64_t opcode_bitmap;        /* bit N set => opcode N implemented  */
    uint32_t daemon_version;       /* informational only                 */
    uint32_t reserved;             /* MUST be zero                       */
    /* appended in §8.6: */
    uint8_t  reconnect_mode;       /* RECONNECT_*                        */
    uint8_t  reconnect_max_tries;  /* 0 = unbounded                      */
    uint16_t reconnect_base_ms;    /* first delay, doubling              */
    uint32_t reserved2;            /* MUST be zero                       */
};
```

A client MUST accept any response of at least 24 bytes — the pre-§8.6
prefix — and ignore a tail it does not understand. A client that demands
exactly 32 has already broken the growth rule for the next field.

`device_caps` bits:

| bit | | |
|---|---|---|
| 1 | `CAP_POINTER_ABS` | `EV_ABS` `ABS_X`/`ABS_Y` |
| 2 | `CAP_KEYBOARD` | `EV_KEY` |
| 4 | `CAP_POINTER_REL` | `REL_X`/`REL_Y`, wheels |
| 8 | `CAP_BUTTONS` | `BTN_LEFT`/`RIGHT`/`MIDDLE` |

**`device_caps` describes the device; `opcode_bitmap` describes the
protocol. Capability is not permission.** The daemon registers every
keycode on the virtual keyboard while the RPC layer still refuses most
of them, so `CAP_KEYBOARD` can be set in a build where no key opcode is
advertised. A client MUST gate on the opcode bit.

`daemon_version` (`major<<16 | minor<<8 | patch`) is informational.
Branching on it is the feature-sniffing §2.2 forbids.

`abs_range_max` is the coordinate contract: `MOVE_ABS` coordinates are
**device units, `0..abs_range_max`, and the client converts** — not
pixels, not a fraction. The daemon clamps to this range. It deliberately
does not know your screen geometry, because learning it means talking to
the compositor, which drags a Wayland dependency into the most
security-sensitive binary in the stack.

`reserved` and `reserved2` are explicit fields, not compiler padding.
The struct is `memcpy`'d straight onto a socket, and uninitialised tail
padding on the wire is a stack-content leak to whatever is listening.
Naming them means they get zeroed like everything else, and
`tests/test_m36_hello.py` asserts `reserved == 0` as a canary. That is
also why `reserved` was not repurposed when §8.6 needed four bytes:
spending it would have meant deleting a security check to save four
bytes on a message sent once per connection.

## 3.5 The name is a label, not a credential

`client_name` is **self-asserted and always will be.** Anything that
must be unforgeable comes from `SO_PEERCRED` instead.

Its value is that it is asserted *once, at a checkpoint*, where an
unknown name can default to the most restrictive class — rather than
per-frame, like `source_tag`.

**A daemon MAY additionally bind a name to a binary.** A registry entry
may require that its name be claimed only by a peer running a particular
executable, checked against `/proc/<peer-pid>/exe`; a peer that fails is
refused with `ERR_DENIED_BY_POLICY` (4), terminal.

This is **local policy, not protocol**. Nothing on the wire changes,
nothing is negotiated, and a client cannot discover whether a binding
applies to it — it either handshakes or it does not. A client library
should not special-case it: the refusal is already terminal and already
means "stop and tell the user".

What it changes is the *cost of claiming a name*. Without it, any
process of the same uid can call itself `agent` and inherit whatever the
registry gives that name. With it, claiming the name requires running
the bound binary — a considerably higher bar than typing a string into a
`HELLO`.

What it does **not** change is that this is evidence, not proof. The
link is read once, just after `accept()`, so it describes the program
that was running when the connection was made; a process can `exec`
something else immediately afterwards while keeping the connected file
descriptor. Two things bound that: becoming a bound binary requires
`exec`ing it, which destroys the caller's own image, and the descriptor
kept across a later `exec` was still opened by the bound program. Treat
it as a strong signal that is cheap to add, not as a capability.

An unknown executable — `/proc` unreadable, or the binary replaced or
deleted since it started — **fails the check**. A daemon that cannot
show the peer is the bound program must not act as though it did.

A valid name is 1–31 bytes of `[A-Za-z0-9._-]`, NUL-terminated, with
every byte after the NUL also zero. This is not cosmetic:

- The name's destination is the **audit log**, which is
  newline-delimited text. A name containing `\n` lets a client write
  forged audit lines — invented pids, invented opcodes, invented denials
  — into the one record that exists to hold it accountable. The
  character set kills that class outright, along with terminal escape
  sequences aimed at whoever reads the log with `cat`.
- Bytes after the NUL are invisible to every consumer, so allowing them
  would make two different payloads produce identical log lines, and hand
  a covert channel to a client whose whole purpose is to be observable.

On an invalid name the daemon answers `ERR_PAYLOAD_INVALID` and
**deliberately does not echo the name back** — it just failed the check
that makes it safe to put in a log.

The name is looked up in `~/.config/uictl/clients`, read **once at
startup**, one entry per line:

```
<name> <class> [confirm] [confirmer] [exe=/abs/path]
               [reconnect=never|backoff[:BASE_MS[:MAX_TRIES]]]
```

It yields:

| | |
|---|---|
| class | `untrusted` (5/s), `standard` (20/s), `interactive` (100/s) |
| roles | `confirm` (device requests need a human, §7), `confirmer` (may subscribe) |
| binary binding | `exe=` — the name may only be claimed by that executable |
| reconnect advice | returned in the response, §8.6 |

**A name not in the registry — or no registry file at all — is
`untrusted`**, which is the 5/s floor and no roles. That is what the
v2.x LLM agent gets until someone writes it into the file deliberately.
The registry file must be a regular file owned by the invoking uid with
no group/world bits, or the daemon ignores it entirely and says so on
stderr: the file decides who gets elevated, so another user being able to
write it would be the whole game.

Loading once rather than per-`HELLO` keeps file I/O out of the request
path and means a config edit does not take effect halfway through a
session, for some connections and not others. The daemon's policy is
whatever it started with — which is also what makes the audit log
meaningful.

## 3.6 One `HELLO` per connection

A second successful `HELLO` on the same connection is
`ERR_DENIED_BY_POLICY` — terminal, not retryable.

A second one would let a client rename itself *after* the daemon has
attached a class to the first name, which is exactly the per-frame
self-assertion this frame exists to replace. **The connection is the
scope of the handshake.** A client that wants a different identity opens
a different connection.

Nothing negotiated here survives the connection. Reconnecting requires a
fresh `HELLO`, and no client may cache a previous connection's selected
version, class, or capability set — see §8.2 and §8.4.

## 3.7 What is exempt, and why

`OP_PING` is exempt from the handshake on purpose: it neither reads
state nor touches the device, and it stays usable as a bare liveness
probe. `OP_HELLO` is exempt for the obvious reason.

The handshake check runs **before** the opcode switch, so an
un-handshaked peer is told to handshake rather than told which opcodes
exist. The refusal reveals nothing about the daemon's surface, and there
is exactly one thing the client can do next. `ERR_OPCODE_UNKNOWN` is a
post-handshake answer.

`OP_PING` and `OP_HELLO` are also free of rate-limit charge. A liveness
probe and a handshake are how a client finds out it is being limited;
charging them would mean a throttled client cannot ask why. This is the
same principle that makes every *release* free — §6.3.

---

# 4. Result codes and response classes

## 4.1 The codes

Values are on the wire. **Append only — never insert, never reorder.** A
client built against an older header must keep decoding every code it
already knows to the same meaning.

| # | code | class | meaning |
|---|---|---|---|
| 0 | `OK` | — | success |
| 1 | `ERR_VERSION` | terminal | no overlapping protocol version, or a frame stamped off the pinned version (§3.3) |
| 2 | `ERR_OPCODE_UNKNOWN` | terminal | this daemon does not implement that opcode |
| 3 | `ERR_PAYLOAD_INVALID` | terminal | wrong length, out-of-range value, or a non-zero reserved field |
| 4 | `ERR_DENIED_BY_POLICY` | terminal | peer uid mismatch (§1.2), a name bound to another binary (§3.5), duplicate `HELLO` (§3.6) |
| 5 | `ERR_TOO_LARGE` | terminal | `payload_len > 4096` |
| 6 | `ERR_INTERNAL` | terminal | the write to `/dev/uinput` failed, or a daemon bug |
| 7 | `ERR_BUSY` | retryable | no connection slot right now (§1.3) |
| 8 | `ERR_HANDSHAKE_REQUIRED` | correctable | send `OP_HELLO` on this connection, then retry |
| 9 | `ERR_KEY_DENYLISTED` | terminal | a destructive key. Static, in the daemon, not configurable |
| 10 | `ERR_KEY_NOT_ALLOWED` | fixable | absent from `~/.config/uictl/policy` |
| 11 | `ERR_RATE_LIMITED` | retryable after a wait | going faster than this client's class allows |
| 12 | `ERR_KEY_ALREADY_HELD` | client bug | *you* already hold this key |
| 13 | `ERR_KEY_HELD_BY_OTHER` | retryable after a wait | another connection holds it |
| 14 | `ERR_KEY_NOT_HELD` | client bug | an `UP` for a key this connection does not hold |
| 15 | `ERR_TOO_MANY_HELD` | client bug | over `MAX_HELD_PER_CONN = 16` |
| 16 | `ERR_CONFIRM_UNAVAILABLE` | fixable | this client needs a human and no confirmer is connected |
| 17 | `ERR_CONFIRM_DENIED` | terminal | a human saw it and said no |
| 18 | `ERR_CONFIRM_TIMEOUT` | retryable | nobody answered in time |
| 19 | `ERR_NOT_CONFIRMER` | terminal | `SUBSCRIBE` from a client without the `confirmer` role, or a second subscriber |

## 4.2 The five classes

The classes exist because **a client library needs to tell them apart to
have a sane retry policy at all**, and the failure mode of conflating
them is concrete in both directions: answer a rate limit with a retry
storm and you make it worse; give up on `ERR_BUSY` and you have
abandoned a condition that clears in milliseconds.

**terminal** — retrying changes nothing. Report it and stop.
`ERR_VERSION`, `ERR_OPCODE_UNKNOWN`, `ERR_PAYLOAD_INVALID`,
`ERR_DENIED_BY_POLICY`, `ERR_TOO_LARGE`, `ERR_INTERNAL`,
`ERR_KEY_DENYLISTED`, `ERR_CONFIRM_DENIED`, `ERR_NOT_CONFIRMER`.

**fixable** — retrying identically fails, but a stated change to local
configuration makes it work. The client SHOULD say what the change is.
`ERR_KEY_NOT_ALLOWED` ("add the keycode to `~/.config/uictl/policy` and
restart the daemon"), `ERR_CONFIRM_UNAVAILABLE` ("run `uictl-confirm`").

**retryable** — the daemon is momentarily out of room, or another
connection is mid-gesture, or you are going too fast. Back off and try
again. `ERR_BUSY`, `ERR_KEY_HELD_BY_OTHER`, `ERR_RATE_LIMITED`,
`ERR_CONFIRM_TIMEOUT`.

**client bug** — the request contradicts state the client itself
established. Retrying identically fails; the client has to reconcile its
own held set first. `ERR_KEY_ALREADY_HELD`, `ERR_KEY_NOT_HELD`,
`ERR_TOO_MANY_HELD`.

**correctable** — the request was fine, the connection was not ready.
`ERR_HANDSHAKE_REQUIRED`: send `OP_HELLO` on this same connection and
the retry succeeds.

## 4.3 Why some distinctions are two codes and not one

Each of these pairs was deliberately not collapsed, and in each case the
reason is that the *right client response differs*:

- **`ERR_KEY_DENYLISTED` vs `ERR_KEY_NOT_ALLOWED`.** One is a
  destructive key, static in the daemon, not overridable by
  configuration; the other is one line of config away from working. A
  client that cannot distinguish them can only print "denied", which
  leaves the user to guess between "add a line to a file" and "this will
  never work, do something else". Telling a user to edit their policy
  file for a deny-listed key sends them to do something that cannot
  succeed.
- **`ERR_BUSY` vs `ERR_RATE_LIMITED`.** `ERR_BUSY` says the daemon has
  no room and nothing about the client was wrong. `ERR_RATE_LIMITED`
  says the client is going faster than its class allows and the fix is
  to *pace itself*, not to retry harder.
- **`ERR_BUSY` vs `ERR_DENIED_BY_POLICY`.** Before `ERR_BUSY` existed,
  "table full" and "wrong uid" were the same code, so a client had to
  either hammer a daemon that had told it to go away or give up on a
  condition that clears in milliseconds.
- **`ERR_KEY_ALREADY_HELD` vs `ERR_KEY_HELD_BY_OTHER` vs
  `ERR_KEY_NOT_HELD`.** You lost track of your own state; someone else is
  mid-gesture, back off; the key is up either way. Three different next
  moves — see §6.2.
- **`ERR_CONFIRM_DENIED` vs `ERR_DENIED_BY_POLICY`.** "The user said no"
  and "the rules say no" are different events: one is a decision that
  could go the other way next time, the other is a property of the
  configuration.

## 4.4 What is deliberately absent

**There is no result code for "a release was refused."**

A client that holds a key MUST always be able to release it, so the
release path is not policy-gated, not rate-limited, and not
confirmation-gated. Any refusal of a release is a stuck key, which is
the failure this protocol works hardest to make impossible. §6.3 is the
normative statement; this is the note that the gap in the enum is
intentional and must stay.

`ERR_KEY_NOT_HELD` is not a counterexample: it reports that there was
nothing to release, and the key is up either way — which is what the
client wanted.

---

# 5. Opcodes

Split by device, because that is where the real seam is: since M5.5 the
daemon registers **two** virtual devices, the kernel gives them separate
event nodes and separate handler lists, and an event frame is atomic per
device and only per device. A client that only moves the pointer needs
§5A and nothing else; a client that only types needs §5B and nothing
else. Neither half references the other.

| § | Opcodes |
|---|---|
| 5A | `MOVE_ABS`, `MOVE_REL`, `SCROLL`, `BUTTON` — the pointer |
| 5B | `KEY_TAP`, `KEY_SEQUENCE`, `KEY_DOWN`, `KEY_UP`, `BATCH` — the keyboard, and the one opcode that spans both |

`PING` and `HELLO` are not here: `PING` is a transport-level liveness
probe (§1) and `HELLO` is the whole subject of §3. The three `CONFIRM_*`
opcodes are not here either — they are a flow, not a request shape, and
one of them travels daemon→client. They are specified in §7.

## 5A. The pointer

All four opcodes write to the device named `uictl virtual pointer`. Its
name is fixed for all time: compositors key per-device configuration off
it, so renaming it would silently discard every user's settings.

### 5A.0 The gate every one of these passes

In this order, and the order is normative because a client can tell
which check refused it from the result code alone:

1. **handshake** — `ERR_HANDSHAKE_REQUIRED` if no `HELLO` on this
   connection (§3).
2. **rate limit** — `ERR_RATE_LIMITED`. Charged *before* validation: a
   client flooding malformed frames is still flooding, and a limiter
   that counts only well-formed requests fails to limit the case most
   worth limiting.
3. **confirmation** — `ERR_CONFIRM_*` if the client's registry role
   requires a human (§7).
4. **payload size** — `ERR_PAYLOAD_INVALID`. Exact length, never
   "at least": a command frame is sent only after the version is pinned,
   so there is no skew to absorb and a wrong length means a broken
   client.
5. **range** — `ERR_PAYLOAD_INVALID`, per opcode below.
6. **deny-list** — `ERR_KEY_DENYLISTED`. Applies to `BUTTON`; it
   currently contains no buttons, but the check is not skipped.
7. **arbitration** — `BUTTON` only, see 5A.4.
8. **write**, then **record the hold** (`BUTTON` down only).

`ERR_INTERNAL` is possible at step 8 for any of them and means the write
to `/dev/uinput` failed. It is not retryable in any useful sense: the
device is gone or the daemon is broken.

**The key allowlist (`~/.config/uictl/policy`) does NOT apply to any
opcode in 5A.** That file is a list of *keycodes* a user opted into.
Requiring `272` in it before a client may click would be a default-deny
with no upside: a click is visible and reversible, the pointer is not a
destructive surface the way `KEY_POWER` is, and a user who genuinely
wanted to forbid clicking would have to be told to write a number they
have no way to look up.

### 5A.1 `MOVE_ABS` — absolute position

```c
struct uictl_payload_move_abs {
    int32_t x;
    int32_t y;
};                                  /* exactly 8 bytes */
```

**Coordinate contract: values are DEVICE units, `0 .. abs_range_max`,
and the client converts.** `abs_range_max` comes from the HELLO response
and is 32767 today. The daemon never learns the display geometry — not
the resolution, not the number of monitors, not the layout — and a
client that wants to click a pixel is responsible for the mapping.

That is a deliberate refusal, not an omission. A daemon that knew screen
geometry would need to track hotplug, mode changes, scaling and monitor
arrangement, all through interfaces it has no business holding open, and
all so that it could do arithmetic the client is better placed to do.

Out-of-range values are **clamped**, not refused: `x < 0` becomes 0,
`x > abs_range_max` becomes `abs_range_max`, same for `y`. Clamping is
right here because the coordinate space has a natural edge and "as far
as it goes" is what the client meant — the same thing a real pointer
does at the screen edge.

The audit log records the value **as asked, before clamping**, because
the audit records intent (security rule 5) and the intent is the number
the client sent.

Results: `OK`, or `ERR_PAYLOAD_INVALID` for a wrong-sized payload.
Any in-range or out-of-range coordinate pair succeeds.

### 5A.2 `MOVE_REL` — relative nudge

```c
struct uictl_payload_move_rel {
    int32_t dx;
    int32_t dy;
};                                  /* exactly 8 bytes */
```

Positive `dx` is right, positive `dy` is down — kernel convention, not a
screen convention.

**Out of range is an error here, not a clamp**, and the difference from
`MOVE_ABS` is the point. A relative delta has no natural ceiling to
clamp *to*. Silently shrinking a nudge of 100000 to 32767 would move the
pointer a different distance than the client asked for and report `OK`,
leaving the client to discover the discrepancy by looking at the screen.
In range is exact; out of range is refused.

- `|dx| > abs_range_max` or `|dy| > abs_range_max` → `ERR_PAYLOAD_INVALID`
- `dx == 0 && dy == 0` → `ERR_PAYLOAD_INVALID`

A zero nudge is refused rather than treated as a no-op because it is
always a client bug and because the input core would discard the empty
frame anyway — returning `OK` for a request that provably did nothing is
the failure mode §8.8 objects to.

Results: `OK`, `ERR_PAYLOAD_INVALID`.

### 5A.3 `SCROLL` — wheel notches

```c
struct uictl_payload_scroll {
    int32_t notches_v;              /* + = up    */
    int32_t notches_h;              /* + = right */
};                                  /* exactly 8 bytes */
```

**Notches, not pixels.** One notch is one detent of a physical wheel.
The daemon emits both the classic notch event and the hi-res value the
kernel expects alongside it; a client never has to know that, and MUST
NOT try to send hi-res values itself.

Bounds are `±1000` on each axis — far below the `int32` range, and
deliberately so: the hi-res value is 120× the notch count, and a client
asking for 20 million notches would overflow it. Such a client is
broken, not scrolling.

- `|notches_v| > 1000` or `|notches_h| > 1000` → `ERR_PAYLOAD_INVALID`
- both zero → `ERR_PAYLOAD_INVALID`, same reasoning as `MOVE_REL`

Both axes may be non-zero in one request; they are emitted in one frame.

Results: `OK`, `ERR_PAYLOAD_INVALID`.

### 5A.4 `BUTTON` — press and release

```c
struct uictl_payload_button {
    uint16_t code;                  /* BTN_* */
    uint8_t  down;                  /* 1 = press, 0 = release */
    uint8_t  reserved;              /* MUST be zero */
};                                  /* exactly 4 bytes */
```

`reserved != 0` or `down > 1` → `ERR_PAYLOAD_INVALID`. The daemon
validates the padding byte rather than ignoring it, so that it stays
available for a future field instead of being quietly filled with
whatever clients happened to leave there.

**Valid codes are exactly the five the pointer device registered:**

| Code | Name |
|---|---|
| 272 | `BTN_LEFT` |
| 273 | `BTN_RIGHT` |
| 274 | `BTN_MIDDLE` |
| 275 | `BTN_SIDE` |
| 276 | `BTN_EXTRA` |

Anything else → `ERR_PAYLOAD_INVALID`, including keycodes that are
perfectly valid for §5B. The keyboard device does not register these and
the pointer device does not register keys; the two sets are disjoint by
construction, from one list in the daemon that the pointer registers,
the keyboard skips, and the router switches on.

#### `BUTTON` is held state

A press is not an event, it is a **hold**, and it is recorded in the same
per-connection bitset as held keys (§6). Everything in §6 applies
unchanged: arbitration between connections, release on every path a
connection ends, the dead-man timer, and the cap on simultaneous holds.

That reuse is only correct because `BTN_*` codes live in the kernel's
keycode space — which is why the held bitset is sized `0..KEY_MAX`
rather than by a count of keys.

Press (`down = 1`):

- already held by this connection → `ERR_KEY_ALREADY_HELD`
- held by another connection → `ERR_KEY_HELD_BY_OTHER` (retryable; back
  off, the other client is mid-gesture)
- this connection is at the hold cap → `ERR_TOO_MANY_HELD`

Release (`down = 0`):

- not held by this connection → `ERR_KEY_NOT_HELD`, **except** for the
  forgiving window in §8.3.1, where a release on a connection that has
  never held anything returns `OK` and writes nothing.

#### A release is never refused for a policy reason

The release path is the thinnest gate in the daemon: size, range, "do
you hold it", write. **No rate limit** — a button *down* is charged
against the client's budget and a button *up* is not.

The reasoning is a safety one rather than a generosity. A client that has
spent its budget holding a button must still be able to let go; charging
the release means the way to produce a stuck button is to be slightly too
fast. Never make the escape hatch depend on the resource that ran out.
Policy already had its say on the press — nothing can be held that was
not allowed — so re-asking on the way up can only ever *create* a stuck
button, never prevent one.

Results: `OK`, `ERR_PAYLOAD_INVALID`, `ERR_KEY_DENYLISTED`,
`ERR_KEY_ALREADY_HELD`, `ERR_KEY_HELD_BY_OTHER`, `ERR_KEY_NOT_HELD`,
`ERR_TOO_MANY_HELD`, `ERR_RATE_LIMITED` (press only), `ERR_INTERNAL`.

### 5A.5 What the audit log records

`MOVE_ABS`, `MOVE_REL` and `SCROLL` are **coalesced**: one line per
second per (pid, opcode), recording the count and the last values, not
one line per request. A drag at 60 Hz would otherwise produce 60 audit
lines a second and bury the events an operator actually cares about.

`BUTTON` is **never coalesced**. Every press and release keeps its own
line forever, on the same principle as keys: a click is a discrete act a
user might need to account for, and motion is not.

Only **successful** motion is coalesced. Every refused `MOVE_ABS`,
`MOVE_REL` or `SCROLL` takes the normal path and gets its own line — the
coalescing exists to stop a working client burying the log, not to hide
a broken one.

A burst shorter than one second still gets its own line when it ends —
the accumulator flushes on a one-second tick, so granularity is one
second, not one burst.

### 5A.6 A worked client

Everything a pointer client does, in order, with nothing omitted:

```
connect()                        AF_UNIX, $XDG_RUNTIME_DIR/uictld.sock
HELLO                            mandatory; read abs_range_max and
                                 opcode_bitmap from the reply (§3)
  check bit MOVE_ABS etc. are set in opcode_bitmap before using them
MOVE_ABS  x*32767/screen_w, y*32767/screen_h
BUTTON    272 down=1
MOVE_REL  dx dy                  ... the drag
BUTTON    272 down=0
close()                          any hold still open is released here
```

A client MUST gate on `opcode_bitmap`, never on `daemon_version` or the
protocol version. Feature-sniffing by version number is how a protocol
acquires a compatibility matrix nobody can test.

If the connection drops anywhere in that sequence, §8 applies in full:
the button is released by the daemon, the client's held set is empty,
nothing is replayed, and the next connection starts with a fresh
`HELLO`.

---

## 5B. The keyboard, and `BATCH`

`KEY_TAP`, `KEY_SEQUENCE`, `KEY_DOWN` and `KEY_UP` write to the device
named `uictl virtual keyboard`. `BATCH` is here because it spans both
devices and cannot be specified until §5A and the rest of §5B are.

### 5B.0 Two lists, and only one of them is negotiable

Every keycode in §5B passes **both**. §5A's opcodes pass neither — the
pointer is not governed by either list (§5A.0).

**The deny-list** is static, compiled into the daemon's platform layer,
and **configuration cannot unlock it**. It refuses with
`ERR_KEY_DENYLISTED`, and the audit line names the category:

| Category | What it covers |
|---|---|
| `power` | `KEY_POWER`, `KEY_POWER2` |
| `suspend` | `KEY_SLEEP`, `KEY_SUSPEND` |
| `restart`, `logoff` | `KEY_RESTART`, `KEY_LOGOFF` |
| `sysrq` | `KEY_SYSRQ` — Alt+SysRq talks straight to the kernel |
| `rfkill`, `radio` | `KEY_RFKILL`, `KEY_BLUETOOTH`, `KEY_WLAN`, `KEY_UWB` |
| `eject` | `KEY_EJECTCD` … `KEY_EJECTCLOSECD` |
| `brightness` | every brightness key |
| `fn block` | `KEY_FN` … `KEY_FN_RIGHT_SHIFT` |
| `braille block`, `numeric block` | unused surfaces, closed on principle |

Two shapes of reason. Most are keys where **one keystroke ends the
session or the machine**, and several of them take away the very thing
an operator would use to stop the daemon — a radio key can disconnect
the session you would SSH in over, and zero brightness is
indistinguishable from a dead display while needing the screen you just
turned off to recover. The braille and numeric blocks are different:
nothing legitimate wants them, and an unused surface is worth closing.

**The allowlist** is `~/.config/uictl/policy`, written by the user, one
keycode or `lo-hi` range per line, `#` comments. It refuses with
`ERR_KEY_NOT_ALLOWED`.

**Strict default-deny: no policy file means no keys at all.** Not "all
keys", not "safe keys". A fresh install injects nothing until its owner
writes down what they want, and the daemon says so at startup. `uictl
key-tap` doing nothing on a new machine is the allowlist working.

The file must be mode `0600` and owned by the caller; anything looser is
**ignored entirely**, which under default-deny means no keys — it fails
safe. Both lists load once at startup, like the client registry, because
policy that changes mid-session is policy nobody can audit afterwards.

The two error codes are separate because they call for opposite
responses. `ERR_KEY_NOT_ALLOWED` means *add a line to a file*.
`ERR_KEY_DENYLISTED` means *this will never work, do something else*. A
client that collapsed them could only print "denied", leaving the user
to guess which of those two situations they are in — and sending someone
to edit a config file that cannot help them is worse than saying no.

If a policy file names a deny-listed code, the deny-list wins and
startup warns that the entry is dead.

### 5B.1 `KEY_TAP` — press and release, one frame

```c
struct uictl_payload_key {
    uint16_t keycode;
};                                  /* exactly 2 bytes */
```

Valid keycodes are `1 .. 767` (`KEY_MAX`); `0` and above the ceiling are
`ERR_PAYLOAD_INVALID`. That is a *range* check, not policy — the type
bounds what is expressible, the daemon bounds what is acceptable.

Numeric keycodes only. A symbolic `KEY_A` table belongs in the client;
keeping the wire numeric is honest about what it carries.

Results: `OK`, `ERR_PAYLOAD_INVALID`, `ERR_KEY_DENYLISTED`,
`ERR_KEY_NOT_ALLOWED`, `ERR_RATE_LIMITED`, `ERR_CONFIRM_*`,
`ERR_INTERNAL`.

A tap leaves nothing held, so §6 does not apply to it.

### 5B.2 `KEY_SEQUENCE` — atomic, and self-balancing

```c
struct uictl_payload_key_seq {      /* header */
    uint16_t count;                 /* 1 .. 16 */
    uint16_t reserved;              /* MUST be zero */
};
struct uictl_seq_item {             /* × count */
    uint16_t keycode;
    uint8_t  value;                 /* 1 = press, 0 = release, nothing else */
    uint8_t  reserved;              /* MUST be zero */
};
```

`payload_len` is exactly `4 + 4 × count`. Both `reserved` fields are
read and rejected rather than ignored, so a future field cannot collide
with junk an old client happened to send.

This is what modifier-plus-key needs. Ctrl+A is
`down 29, down 30, up 30, up 29` — four transitions in **one request**,
applied under a single `SYN_REPORT`. A client sending four separate
requests could be interrupted between any two of them by another
client's request, and would land Ctrl on someone else's keystroke.

#### Self-balancing is the whole design

**Every press must have its matching release inside the same request.**
The daemon refuses a sequence that is not balanced.

That constraint is why this opcode could ship while `KEY_DOWN`/`KEY_UP`
were still blocked on the machinery in §6: a balanced request cannot
leave a key held, so there is no orphaned kernel state for a dying
client to strand. Refusing to create the possibility was cheaper than
building the cleanup — and when the cleanup arrived, this opcode did not
need it.

Balance is tracked item by item, not counted at the end:

- a press of a code the sequence already holds → `ERR_PAYLOAD_INVALID`
- a release of a code the sequence does not hold → `ERR_PAYLOAD_INVALID`
- anything still held after the last item → `ERR_PAYLOAD_INVALID`

Checking as it goes rather than summing makes "balanced" a statement
about each key's state rather than arithmetic that `down A, down A, up A,
up A` would satisfy.

#### Two passes, and the order of the errors is deliberate

Pass 1 validates **structure and balance** for every item. Pass 2
applies **policy** — deny-list, then allowlist — to every item. Only
then is anything written.

Structure before policy, so that an unbalanced request that *also* names
an unlisted key reports the malformed sequence. Report the policy miss
first and the user edits their policy file, retries, and meets the real
error on the second attempt.

Validate-everything-then-write is the same rule `BATCH` follows and for
the same reason: a per-item check-then-write loop leaves a rejected
item's predecessors already delivered, and when one of those was a press
that is the stuck-key scenario arriving through the back door.

#### Cost

A sequence costs **one rate-limit unit per press**, not one per request.
A 16-key combo is sixteen keystrokes; pricing it as one would make this
opcode a way around the limit.

Results: `OK`, `ERR_PAYLOAD_INVALID`, `ERR_KEY_DENYLISTED`,
`ERR_KEY_NOT_ALLOWED`, `ERR_RATE_LIMITED`, `ERR_CONFIRM_*`,
`ERR_INTERNAL`.

### 5B.3 `KEY_DOWN` / `KEY_UP` — held keys

Both take `struct uictl_payload_key`, 2 bytes — the question ("which
key?") is the same as `KEY_TAP`'s.

These are the opcodes §6 exists for. Everything there applies: the
shared hold set, the cap of 16, one holder per code, release on every
disconnect path, the 30-second dead-man timer, and §8.3.1's forgiving
window. This section does not restate it.

What belongs here is the split in what the two opcodes are allowed to
refuse.

`KEY_DOWN` runs the **full gate**, identical to `KEY_TAP`'s, plus
arbitration: range → deny-list → allowlist → already-held → held-by-other
→ hold cap → write → record.

`KEY_UP` runs **almost nothing**: size, range, "do you hold it", write.
No deny-list, no allowlist, no rate limit, **no confirmation** (§6.3).
The reasoning is in §6.3 and the short version is that policy already
had its say on the press, so re-asking on the way up can only ever
create a stuck key.

**A one-shot process should not use these.** The release fires when the
connection closes, so `KEY_DOWN` from a program that then exits is an
elaborate `KEY_TAP`. They exist for long-lived clients holding a code
*across* other requests — which is exactly what `KEY_SEQUENCE`
deliberately cannot express, since it must balance within one frame.

`KEY_DOWN` results: `KEY_TAP`'s, plus `ERR_KEY_ALREADY_HELD`,
`ERR_KEY_HELD_BY_OTHER`, `ERR_TOO_MANY_HELD`.
`KEY_UP` results: `OK`, `ERR_PAYLOAD_INVALID`, `ERR_KEY_NOT_HELD`,
`ERR_INTERNAL`.

### 5B.4 `BATCH` — several sub-ops, atomic per device

```c
struct uictl_payload_batch {        /* header */
    uint16_t count;                 /* 1 .. 16 */
    uint16_t reserved;              /* MUST be zero */
};
struct uictl_batch_item {           /* × count, 12 bytes each */
    uint16_t opcode;
    uint16_t reserved;              /* MUST be zero */
    int32_t  a;
    int32_t  b;
};
```

`payload_len` is exactly `4 + 12 × count`.

The item is a fixed-size tagged union, so the whole batch validates in
one pass with no pointer chasing. `a` and `b` mean whatever the sub-op
means:

| Sub-opcode | `a` | `b` |
|---|---|---|
| `MOVE_ABS` | `x` | `y` |
| `MOVE_REL` | `dx` | `dy` |
| `SCROLL` | `notches_v` | `notches_h` |
| `BUTTON` | button code | `1` = down, `0` = up |
| `KEY_DOWN` | keycode | unused |
| `KEY_UP` | keycode | unused |

**Exactly those six are batchable.** Anything else, including `KEY_TAP`,
`KEY_SEQUENCE`, `PING`, `HELLO` and a nested `BATCH`, is
`ERR_PAYLOAD_INVALID`. `KEY_TAP` and `KEY_SEQUENCE` are excluded because
each is already an atomic multi-event request; nesting atomicity inside
atomicity buys nothing and complicates the balance rules.

#### "Atomic per device" is the subtlety

An event frame is atomic **per device**, and nothing below the kernel
joins two devices into one frame. Since the pointer and keyboard are
separate virtual devices, a batch touching both lands as **two**
`SYN_REPORT`s — pointer items in one, keyboard items in the other.

A modifier plus a click is therefore two reports. That is not a
limitation being apologised for: it is what the same gesture is on real
hardware, where the modifier comes from a keyboard and the click from a
mouse.

A client that needs true single-frame atomicity must stay within one
device — `KEY_SEQUENCE` for keys, or a batch of pointer-only items.

#### All-or-nothing

Pass 1 validates every item — structure, range, deny-list, allowlist,
and the §6 hold rules against a *hypothetical* hold set that tracks what
the batch would hold. Pass 2 writes. Nothing between them can fail on
policy grounds.

So a batch whose last item is invalid writes **nothing at all**, and the
result names the offending item's index. There is no partial-failure
story because there is no partial failure.

The hold rules are checked against what the batch *would* hold, not only
against what the connection already holds: a batch pressing the same
code twice, or exceeding the cap of 16 partway through, is refused as a
whole.

A release inside a batch is **not** covered by §8.3.1's forgiving
window. A batch is one unit the client composed, so a stray release
inside it is a composition error rather than a reconnect artifact — and
§8.5 forbids resending a batch across a reconnect anyway.

#### One sharp edge

A batch from a client with the `confirm` role can be **too large to
prompt**. The parked-request buffer is 128 bytes and a full 16-item
batch is 196, so it is refused with `ERR_TOO_LARGE` rather than
truncated: a prompt describing less than what would execute is worse
than no prompt. Flagged clients should keep batches to 10 items or send
sub-ops individually.

Results: `OK`, `ERR_PAYLOAD_INVALID`, `ERR_TOO_LARGE`, and every result
its sub-ops can produce.

### 5B.5 A worked client

```
connect(); HELLO                 mandatory (§3)
  check the opcode_bitmap bits you intend to use
KEY_TAP 30                       'a', if 30 is in the policy file
KEY_SEQUENCE [29↓ 30↓ 30↑ 29↑]   Ctrl+A, one frame, balanced
KEY_DOWN 42                      hold Shift...
MOVE_REL 50 0                    ...across other requests
KEY_UP 42                        release it — never refused for policy
close()                          anything still held is released here
```

On a fresh machine every keyboard line above returns
`ERR_KEY_NOT_ALLOWED` until `~/.config/uictl/policy` exists. That is
§5B.0 working, not a fault.

---

# 6. Held state

Most opcodes finish where they started: the request is validated, an
event frame goes to the device, the response comes back, and nothing
remains. Four do not. `BUTTON` with `down = 1` (§5A.4) and `KEY_DOWN`
(§5B) leave a key or button **physically down** on a virtual device that
the compositor believes is real hardware, and `BUTTON` with `down = 0`
and `KEY_UP` are how it comes back up.

That asymmetry is the whole subject of this section, and it is why these
opcodes shipped a milestone after the rest: **a protocol that can press
a key must guarantee the key comes back up, including when the client
that pressed it stops existing.** Everything below is that guarantee.

## 6.1 The hold set

Every connection owns a set of the codes it currently holds. A code is
in exactly one connection's set or in none.

- **Keys and buttons share one set.** `BTN_LEFT` is keycode 272 and
  lives in the same numeric space as `KEY_A`, so the set is indexed by
  keycode over `0 .. 767` (`KEY_MAX`) rather than by any count of keys.
  Everything in this section therefore applies to buttons and keys
  identically, and where §5A referred here for `BUTTON`, this is what it
  meant.
- **It is owned by the connection, not the process.** A peer with four
  connections has four independent hold sets, and closing one releases
  only what that one held. Keying it on the pid could not answer the
  question the release path actually asks — "what does *this* dying file
  descriptor hold" — while the peer's other connections stay alive.
- **It does not survive the connection** (§8.2), and nothing resumes it.

### 6.1.1 The cap

A connection may hold at most **16** codes at once. The 17th returns
`ERR_TOO_MANY_HELD`, and the refusal disturbs nothing already held.

The bound exists for two reasons, and the second is the load-bearing
one. No real gesture needs more than a handful of codes down, so it is a
cheap bound on untrusted input in the same spirit as the payload cap.
More importantly it keeps the **synthesized release burst small and
predictable**: whatever the daemon has to emit when a connection dies is
bounded by this number, so the release path has a known worst case
rather than one that scales with how badly a client misbehaved.

The cap is on the shared set, not per device. Twelve held keys and four
held buttons is sixteen.

## 6.2 One holder per code

A code may be held by at most one connection at a time, across the whole
daemon.

- A press for a code **this** connection already holds →
  `ERR_KEY_ALREADY_HELD`. This is a client bug: the client lost track of
  its own state. Retrying identically fails; the fix is to send the
  release it owes, or to stop sending the duplicate press.
- A press for a code **another** connection holds →
  `ERR_KEY_HELD_BY_OTHER`. Nothing about the request was wrong and it
  may well succeed shortly. Retryable — but a client SHOULD back off,
  because the holder is by definition mid-gesture.

The two are separate codes rather than one refusal because the right
response differs completely, and a client that cannot tell them apart
can only give up. One says "fix your bookkeeping"; the other says "wait".

The motivating case is concrete: two clients dragging with `BTN_LEFT` at
the same time. Without arbitration, whichever releases first releases it
for both, and the other client is left in a drag that never ends and
that it has no way to notice.

## 6.3 A release is never refused for a policy reason

**The release path is the thinnest gate in the daemon**: payload size,
range, "do you hold it", write. In particular it is:

- **not rate limited.** `KEY_DOWN` and `BUTTON` down are charged against
  the client's budget; `KEY_UP` and `BUTTON` up are not.
- **not subject to the key allowlist or the deny-list.**
- **not subject to confirmation** (§7).

This is a safety property, not a generosity, and it follows from one
observation: **policy already had its say on the press.** Nothing can be
held that was not allowed through the full gate. Re-asking any of those
questions on the way up can therefore only ever *create* a stuck key —
never prevent one.

Stated as a rule for implementers: **never make the escape hatch depend
on the resource that ran out.** A client that spent its budget holding
keys down must still be able to put them up; charging the release means
the way to produce a stuck key is to be slightly too fast. The same
shape exempts `PING` and `HELLO` from the rate limit, so that a
throttled client can still ask why it is being throttled.

There is deliberately **no result code for "the release was refused by
policy"**. Any such code would be a stuck key with a number attached.

The one refusal a release can produce is `ERR_KEY_NOT_HELD`, which is
bookkeeping rather than policy — and §8.3.1 forgives even that on a
connection that has never held anything.

## 6.4 Everything comes back up. Four independent guarantees.

The client is not trusted to release what it holds. It usually will;
these exist for when it does not.

### 6.4.1 Release on disconnect

When a connection ends by **any** means — orderly close, `close()`
without warning, client crash, `SIGKILL`, daemon shutdown, admission
eviction, the reaper, the dead-man timer — the daemon synthesizes a
release for everything that connection holds. §8.3 states this from the
client's side; here is what it does.

**Codes are released in descending order.** That is not cosmetic. A
modifier has a low keycode (`KEY_LEFTCTRL` is 29) and the key it
modifies is usually higher, so descending order releases the modified
key *before* the modifier — the order a human's hand uses, and the order
a compositor's key-repeat and shortcut matching expect. Releasing Ctrl
first can turn the trailing release into a different chord.

**Releases are routed per device.** A held button is released on the
pointer device and a held key on the keyboard. Releasing one through the
other writes an event the kernel silently drops, producing a stuck
button that the release path *believes* it released — worse than never
having tried, because nothing reports it.

**The set is cleared whether or not the writes succeeded.** A failed
write here means the device itself is broken, which the audit line
records; keeping the bits would look like caution but buys nothing,
since the connection is being destroyed and the slot reused.

### 6.4.2 The dead-man timer

A client can be perfectly alive and still stuck — an infinite loop after
`KEY_DOWN`, a deadlock, a debugger breakpoint. Its connection is open,
it is answering nothing, and none of §6.4.1 applies.

So: a connection that has been **continuously holding something for 30
seconds** has everything force-released.

The quantity bounded is the age of the connection's *oldest* hold, not
of any individual code. That is deliberate and it has a consequence
worth stating: a client that keeps one key down while tapping others is
correctly seen as stuck rather than busy. Everything goes up together —
a partial release would leave the client holding a set that neither side
agrees on, which is the divergence this whole section exists to prevent.

**The connection survives.** It is released, not reaped, and stays
usable. The client learns on its next `KEY_UP`, which returns
`ERR_KEY_NOT_HELD` — that error is the signal that its hold set and the
daemon's have diverged.

The timer fires on a one-second tick, so the real deadline is 30–31
seconds. A client MUST NOT rely on the exact value; it is a safety net,
not a schedule.

### 6.4.3 Bounded by the cap

§6.1.1's cap of 16 bounds the size of every release burst above.

### 6.4.4 Backstopped by the kernel

If the daemon dies so abruptly that none of the above runs — `SIGKILL`,
a segfault — the kernel's teardown of the `/dev/uinput` file descriptor
destroys both virtual devices outright. A destroyed device holds
nothing. There is no path by which a key stays down because the daemon
died, only paths by which it stays down for as long as the daemon takes
to notice.

## 6.5 What a client must do

- **Track what you hold, per connection**, and release it. The
  guarantees above are a safety net; a client that relies on them
  produces a 30-second stuck modifier every time.
- **After any disconnection, treat your hold set as empty** (§8.3). Do
  not send releases for what a previous connection held.
- **Treat `ERR_KEY_NOT_HELD` mid-connection as a real signal**, not
  noise. It means the daemon released something you believe you hold —
  almost always the dead-man timer — and your model is stale.
- **Do not use `KEY_DOWN`/`BUTTON` down from a one-shot process.** The
  release fires when your connection closes, so `key-down` from a
  program that then exits is an elaborate way to write `KEY_TAP`. This
  is why the CLI advertises both opcodes and offers no subcommand for
  them. They exist for long-lived clients that need a code held *across*
  other requests — a drag, or modifier-plus-motion — which is exactly
  what `KEY_SEQUENCE` (§5B) deliberately cannot express.

---

# 7. Confirmation

## 7.0 What this is, and what it is not

Confirmation puts a human between a **flagged client** and the user's
keyboard and pointer. A client whose registry entry carries the
`confirm` role has every device-touching request parked until a person
answers a prompt.

**It is a speed bump in front of a cooperative client, not a boundary
against a hostile one.** Client names are self-asserted at `HELLO`
(§3.5), so a hostile process of the same uid can claim the confirmer's
name and approve its own requests. An `AF_UNIX` socket authenticates a
**uid, not a binary**, which is the entire reason this broker exists.

§3.5's binary binding narrows this without closing it. Binding the
confirmer's name to its executable means a hostile process must *run
that binary* to claim the name rather than merely naming it — a
considerably higher bar, and one worth setting for the confirmer above
every other entry. It is still not a boundary: the binding is checked
once, at accept, and is evidence rather than proof. Design as though a
determined local attacker of the same uid can be the confirmer, because
they can. What bounds a hostile client is the
deny-list, the allowlist, and the rate limiter — see §5B.0 and §5A.0.

Stating that plainly is part of the specification. A reader who mistakes
this section for an authorization boundary will design something on top
of it that does not hold. Per-binary peer identity (`/proc/<pid>/exe`)
is a separate, later milestone, and it is what a real boundary would
need first.

The prompter is a **separate binary that connects like any other
client** — `uictl-confirm` in this tree. The daemon never `fork`s and
never `exec`s, so it cannot summon a prompter; the prompter comes to it.
That closes an entire branch of attack surface, and the cost is that
confirmation is unavailable when nobody is running one, which §7.6
resolves by failing closed.

## 7.1 Two roles, and they are different

Both come from `~/.config/uictl/clients` (§3.5), never from anything in
a frame:

| role word | meaning |
|---|---|
| `confirm` | this client's device requests are parked until a human answers |
| `confirmer` | this client may subscribe and answer prompts |

They are independent. A client with neither — the default for any
unregistered name — is not gated and cannot subscribe.

Nothing stops one entry carrying both, and the spec does not forbid it,
but a client that must confirm its own requests deadlocks the moment it
sends one: the prompt goes to a connection that is parked waiting for
the answer.

## 7.2 Subscribing — `OP_CONFIRM_SUBSCRIBE` (8)

Zero payload. `payload_len` MUST be 0; anything else is
`ERR_PAYLOAD_INVALID`. The request *is* the whole message — who may send
it is decided from the registry, not from anything in the frame.

Refused with `ERR_NOT_CONFIRMER` (19) in two cases:

1. The client's registry entry does not carry the `confirmer` role.
   Without this check any client could subscribe and then approve its own
   requests, which is not a gate but a formality.
2. **A confirmer is already subscribed.** First subscriber wins. The
   alternative — newest wins — lets any client that can claim the name
   silently displace a live confirmer, and the displaced one would have
   no way to know it had stopped being asked.

`ERR_NOT_CONFIRMER` does not distinguish the two on the wire, and that
is deliberate: both mean "you are not the confirmer", and which one it
was is a local configuration question, answerable from the daemon's
stderr and the audit log.

Subscription is per connection and dies with it (§8.2).

## 7.3 What gets confirmed

A request is parked when **both** hold:

1. the opcode touches the device — `MOVE_ABS`, `MOVE_REL`, `SCROLL`,
   `BUTTON`, `KEY_TAP`, `KEY_SEQUENCE`, `KEY_DOWN`, `KEY_UP`, `BATCH`;
2. it is **not a release**.

There is no "pointer motion is harmless" exemption. A flagged client
that can move the pointer and click can do anything the user can.

### 7.3.1 A release is never parked

`KEY_UP`, and `BUTTON` with `down == 0`, are **never** confirmed. This
is the same rule §6.3 states for policy and the rate limiter, and it
arrived here late: until it was written down, a flagged client's
`KEY_UP` was parked for a human, and a denial, a timeout, or a missing
confirmer left the key **down**. Every one of those is a normal outcome
of this flow — it fails closed by design — so the gate turned "the user
said no" into a stuck modifier that only the 30-second dead-man timer
(§6.4.2) would clear.

The test is **payload-aware, not opcode-aware**, because `BUTTON`
carries both directions in one opcode. A malformed payload is NOT
treated as a release: it falls through to the gate and only then to the
size check, so a client cannot dodge confirmation by sending a short
frame.

### 7.3.2 Where the gate sits

After the handshake and after the rate limit, before the opcode switch
(§5A.0). After the rate limit so a flooding client is refused before a
human is bothered; after the handshake because the role is derived from
the name a `HELLO` established.

Note what is gated: the client's **role**, never its `source_tag`. The
original design keyed this on `source_tag & SRC_LLM`, which the client
writes itself — the LLM agent would simply not set the bit. §2.5 names a
confirmation prompt as one of the things that must never read that field.

## 7.4 The prompt — `OP_CONFIRM_REQUEST` (9)

**The only frame in this protocol the daemon sends unprompted**, and the
only exception to request/response (§2.7). It is pushed to the
subscribed confirmer's connection. A confirmer MUST be written to read
frames it did not ask for.

Header: `opcode = 9`, `version` = the confirmer's negotiated version,
`source_tag = 0`, and **`seq` carries the token** — so a confirmer can
correlate without decoding the payload. It is not a response, so nothing
is echoed; the header is built by the daemon.

```c
struct uictl_payload_confirm_req {   /* 48 bytes */
    uint32_t token;        /* the daemon's handle on the parked request */
    uint32_t peer_pid;     /* from SO_PEERCRED — unforgeable            */
    uint16_t opcode;       /* what is being asked for                   */
    uint16_t keycode;      /* the key, or 0 where not applicable        */
    uint16_t cl;           /* daemon-derived class, never source_tag    */
    uint16_t reserved;     /* MUST be zero                              */
    char     client_name[32];  /* what it said at HELLO                 */
};
```

Every field is something a person needs in order to answer.

**It deliberately does not carry the raw payload of the request being
confirmed.** Security rule 5 — the audit log records intent, not content
— applies to a confirmation prompt for the same reason: a prompt is a
second place the content would be exposed. The keycode is the single
exception, because "may this client press F13" is not answerable without
it.

`MOVE_ABS` therefore reports `keycode = 0` rather than coordinates. The
prompt says *this client wants to move the pointer*, which is the
decision being made; pixel values would be content, not intent.

`peer_pid` and `cl` come from the daemon's side of the socket.
`client_name` is the self-asserted label, and a confirmer displaying it
should treat it as such — §7.0.

## 7.5 The decision — `OP_CONFIRM_DECIDE` (10)

```c
struct uictl_payload_confirm_decide {  /* 8 bytes */
    uint32_t token;
    uint8_t  allow;         /* 1 = proceed. ANY other value = refuse    */
    uint8_t  reserved[3];   /* MUST be zero                             */
};
```

Exact size. Non-zero `reserved` is `ERR_PAYLOAD_INVALID`.

`allow` is `1` for yes and **anything else for no**, rather than a
boolean test. A garbled byte becomes a refusal, not an approval; the
value that means "proceed" is the one that has to be spelled correctly.

Refusals:

| condition | result |
|---|---|
| sender is not the subscribed confirmer | `ERR_NOT_CONFIRMER` (19) |
| wrong length, or non-zero `reserved` | `ERR_PAYLOAD_INVALID` (3) |
| no confirmation pending, or the token does not match | `ERR_PAYLOAD_INVALID` (3) |

**The token is what stops a slow "yes" from approving the wrong
request.** Tokens are issued in sequence and never reused while pending;
a decision carrying a stale one is dropped. A stale token is the normal
case rather than an alarming one — the request timed out, or its client
went away, while the human was deciding — and answering `OK` would tell
the confirmer its decision had been applied when nothing happened.

The daemon's `OK` to a `DECIDE` means **the decision was accepted**, not
that the confirmed request has completed. Those are two different
frames on two different connections. The requester's own reply arrives
on the requester's connection.

## 7.6 The five ways a parked request ends

| outcome | requester gets | |
|---|---|---|
| approved | the real result of the request | re-dispatched as if it had just arrived |
| denied by a human | `ERR_CONFIRM_DENIED` (17) | terminal — retrying is asking twice |
| nobody answered in 30 s | `ERR_CONFIRM_TIMEOUT` (18) | retryable, but assume the user is away |
| the confirmer disconnected while parked | `ERR_CONFIRM_UNAVAILABLE` (16) | fixable — start a confirmer |
| the requester disconnected | nothing | dropped silently; there is nobody to answer |

**Approval re-dispatches the frame exactly as it was validated**, and it
is dispatched as *resumed*: no second rate-limit charge, and no second
prompt. Charging twice would make confirmation cost a flagged client
double; parking twice would prompt forever. The audit line is written by
the handler with the real outcome, which is why parking writes none.

**Timeout denies, never approves.** A gate that opens when the user is
away from the keyboard is not a gate. The timeout is checked on the same
1 s tick as the stall reaper, so the effective deadline is 30–31 s —
coarse on purpose, like every other deadline in this document.

**A confirmer that disappears while a request is parked resolves it
immediately as `ERR_CONFIRM_UNAVAILABLE`**, rather than leaving it to
time out. The prompter vanishing is not consent, and the requester
should not wait 30 s to learn something the daemon already knows.

## 7.7 One at a time

**There is one pending confirmation daemon-wide. It is not a queue.** A
second confirmable request while one is pending gets `ERR_BUSY` (7).

Confirmations run at human speed. A queue of prompts is a worse
experience than a refusal, and it would let one client fill the daemon's
memory with parked requests. `ERR_BUSY` is already the "no room, try
again" code and needs no new meaning here.

`ERR_BUSY` is also returned when the confirmer has a reply still going
out: there is one output buffer per connection, and staging a prompt
over it would drop whichever frame lost the race. In practice this
lasts a millisecond.

### 7.7.1 The 128-byte parking limit

A parked payload is capped at **`CONFIRM_MAX_PAYLOAD = 128` bytes**.
Over that, the request is refused with `ERR_TOO_LARGE` (5) instead of
being parked — **a prompt that describes less than what would execute is
worse than no prompt**, so the payload is never truncated to fit.

Every confirmable payload fits except one: `KEY_*` is 2 bytes,
`MOVE_ABS`/`MOVE_REL`/`SCROLL` 8, `BUTTON` 4, a full 16-item
`KEY_SEQUENCE` 68 — but a full 16-item `BATCH` is 196 bytes (§5B.4). **A
flagged client cannot send a `BATCH` of more than 10 items.** That is a
sharp edge, and it is documented rather than papered over: the honest
answer for a flagged client is smaller batches, since the prompt has to
be able to describe what will happen.

## 7.8 What a confirmer must do

1. `HELLO` with a name the registry gives the `confirmer` role, then
   `OP_CONFIRM_SUBSCRIBE`. Check the `OK`.
2. Read frames it did not request. A confirmer's read loop is not
   request/response, and a client library built on "one read per write"
   cannot host one (§2.7).
3. Echo the token from `seq` or from the payload — they carry the same
   value — in `OP_CONFIRM_DECIDE`.
4. Treat `ERR_PAYLOAD_INVALID` on a decision as "too late", not as a bug.
   The human took longer than the request lived.
5. Default to refusing. Anything other than an explicit yes — a closed
   stdin, an unreadable prompt, a display that failed to open — MUST
   produce `allow != 1` or no decision at all. Both deny.
6. Not exit while a prompt is on screen if it can help it: disconnecting
   resolves the pending request as `ERR_CONFIRM_UNAVAILABLE`.

`uictl-confirm` is deliberately a terminal program reading `y`/`n` from
stdin. A desktop-notification version is a nicety writable later against
the same three frames; keeping the first one a TTY program means it is
scriptable and testable without a compositor.

## 7.9 What the audit log records

A park writes **no** audit line. Nothing has been decided yet, and a
line at park time would have to be amended by a second line at
resolution — two records for one event, with the first one wrong.

The resolution writes one line with the outcome: `confirmed by user`
(then the handler's own line for the real result), `confirmation timed
out`, `confirmer disconnected`, or the denial. The requester's pid, uid,
`source_tag`, opcode and `seq` are all taken from the **parked** header,
so the line describes the request the human actually saw.

`SIGUSR1` reports a pending confirmation — its token, the opcode, and
how many seconds it has been waiting — so an operator can tell "the
daemon is wedged" from "somebody is being asked a question" (§8.8).

---

# 8. Connection lifecycle and restart

## 8.1 Why this section exists at all

Under systemd socket activation the listening socket is owned by
`systemd`, not by `uictld`. A client's `connect()` therefore succeeds
whether or not the daemon is running: systemd accepts the connection and
starts the daemon on demand. **A successful `connect()` is not evidence
that a daemon is running, and a failed one is not evidence that none
is.** Every rule below follows from that.

Before socket activation, a dead daemon produced `ECONNREFUSED` and the
question answered itself. Implementations MUST NOT rely on that
behaviour.

## 8.2 A connection is the unit of all negotiated and held state

Everything the daemon knows about a client is scoped to one connection:

- the selected protocol version and the advertised `opcode_bitmap`
- the client's derived class and roles
- the rate-limit bucket
- the set of keys and buttons the connection holds
- confirmer subscription

None of it survives the connection. There is no session identifier, no
resumption token, and no continuity of identity between two connections
from the same peer. This is deliberate: the daemon cannot verify that a
new connection is "the same client" as an old one — `client_name` is
self-asserted (§3) and a PID is reused — so a protocol that pretended
otherwise would be asserting something it cannot check.

## 8.3 Disconnection releases everything, always

When a connection ends by **any** means — orderly close, client crash,
daemon crash, daemon restart, admission eviction, dead-man timeout — the
daemon synthesizes a release for every key and button that connection
holds, and emits the corresponding `EV_KEY` value-0 events plus
`SYN_REPORT`.

Consequently:

- A client MUST treat its own held set as **empty** after any
  disconnection, without being told.
- A client MUST NOT send a release for something it held on a previous
  connection. The key is already up; the request is meaningless.
- The daemon MUST NOT require such a release in order to make the key
  up. Correctness here does not depend on client cooperation.

If a daemon crashes so hard that the release does not run, the kernel's
teardown of the `/dev/uinput` fd destroys the virtual devices entirely,
which also ends any held state. There is no path by which a key stays
down because a daemon died.

### 8.3.1 The first release on a connection is forgiving

An honest client that reconnects mid-gesture will still, in practice,
have code in flight that sends the release it believes it owes. To keep
that from being an error path:

- A release (`OP_KEY_UP`, or `OP_BUTTON` with `down = 0`) for a code
  that this connection has never held, sent **before this connection has
  successfully held anything**, MUST return `OK` and MUST NOT write any
  event to the device.
- A release for a code this connection does not hold, sent **after** the
  connection has held at least one code, MUST return
  `ERR_KEY_NOT_HELD`.
- The forgiven case MUST be distinguishable in the audit log from an
  ordinary release. It is otherwise invisible: see below.

The "MUST NOT write" above is defence in depth rather than an observable
guarantee. The kernel's input core discards a value-0 `EV_KEY` for a
code the device does not have down, and discards the resulting empty
frame with it, so a daemon that wrongly wrote the event would look
identical at the event node — no `EV_KEY`, no `SYN_REPORT`. Implementers
MUST NOT rely on that filtering, and MUST NOT treat "no event appeared"
as evidence the rule is being followed; the audit line is the only
external evidence of which branch ran.

The forgiving window applies to standalone `OP_KEY_UP` and `OP_BUTTON`
only. A release inside `OP_BATCH` that the batch's own bookkeeping does
not account for MUST still return `ERR_KEY_NOT_HELD` and fail the whole
batch: a batch is one unit the client composed, so a stray release
inside it is a composition error, not a reconnect artifact — and §8.5
forbids resending a batch across a reconnect in the first place.

The asymmetry is the point. The first case is indistinguishable from a
restart the client did not cause and there is nothing for it to fix; the
second is a client that lost track of its own state within a single
connection, which is a bug worth reporting. A client MUST NOT rely on
the forgiving case as a way to "clear" state — there is no state to
clear (§8.3).

## 8.4 Reconnection requires a fresh handshake

A client that reconnects:

- MUST send `OP_HELLO` on the new connection before any other opcode.
  Every other opcode returns `ERR_HANDSHAKE_REQUIRED` until it does.
- MUST use the `proto_selected`, `device_caps`, `abs_range_max` and
  `opcode_bitmap` from the **new** HELLO response.
- MUST NOT cache any of those values across connections.

The caching prohibition is not pedantry. The gap between a disconnection
and the next connection is exactly when the daemon binary was upgraded —
that is what socket activation is *for*. A client reusing a bitmap from
before the upgrade has a stale idea of which opcodes exist, and will
discover this by sending one that does not.

## 8.5 Requests are never replayed

**A request whose response was not received has an undefined outcome and
MUST NOT be resent on a new connection.**

There is no idempotency key, no request deduplication, and no way to ask
the daemon what it did. Injection is not idempotent: a replayed
`OP_KEY_DOWN` is a second keypress the user did not ask for, and the
client cannot distinguish "the daemon died before writing" from "the
daemon wrote and died before replying."

This is not a special case for un-acknowledged requests. It generalises:

| Request in flight when the connection dropped | On reconnect |
|---|---|
| `MOVE_ABS`, `MOVE_REL`, `SCROLL` | discard — the pointer state it assumed is gone |
| `BUTTON` down, `KEY_DOWN`, `KEY_TAP`, `KEY_SEQUENCE` | discard — a late click lands in whatever window is focused *now* |
| `BUTTON` up, `KEY_UP` | discard — already released by §8.3 |
| `BATCH` | discard — partially applied batches are not distinguishable from unapplied ones |
| `PING`, `HELLO` | reissue freely — no device effect |
| `CONFIRM_DECIDE` | discard — the token is bound to the dead connection |

So: **nothing with a device effect is ever replayed.** A client that
queues requests while disconnected is a client that will eventually
click in the wrong place. Implementations SHOULD drop the queue rather
than drain it.

## 8.6 Reconnect behaviour is advertised, not enforced

Whether a client reconnects, and how patiently, cannot be enforced by
the daemon: the decision is made in the client's process, frequently at
a moment when the daemon is not running. The protocol therefore treats
it as **advice issued at handshake time**, which the client caches for
use during the *next* outage.

The advice originates in the daemon's client registry
(`~/.config/uictl/clients`), so a human expresses it per client, in the
one file that already governs per-client behaviour.

The HELLO response gains two appended fields (§3, append-only growth
rule):

```c
uint8_t  reconnect_mode;      /* 0 unspecified, 1 never, 2 backoff       */
uint8_t  reconnect_max_tries; /* 0 = unbounded; only if mode == 2        */
uint16_t reconnect_base_ms;   /* first delay, doubling each attempt      */
uint32_t reserved2;           /* MUST be zero */
```

The advice comes from the daemon's client registry
(`~/.config/uictl/clients`), as an optional trailing token alongside the
existing role words:

```
muvor      interactive  reconnect=backoff:250:7
oneshot    standard     reconnect=never
agent      untrusted    confirm  reconnect=backoff
```

`reconnect=backoff` with no numbers means 100 ms base, unbounded tries.
A malformed token drops the **whole entry** and is reported at startup —
the same all-or-nothing the role words use, because a typo that left a
half-applied entry would be a config that silently does something other
than what it says.

`reserved2` is named rather than left to the compiler for the same
reason `reserved` is: this struct is copied straight onto a socket, and
implicit tail padding would put uninitialised stack bytes on the wire.

Rules:

- A daemon that has no advice for a client MUST send
  `reconnect_mode = 0`. A client receiving `0` MUST apply the default
  for its own shape: **one-shot clients fail fast; long-lived clients
  use bounded exponential backoff** with a base of 100 ms, doubling,
  capped at 30 s.
- A client SHOULD honour a non-zero `reconnect_mode`.
- A daemon MUST NOT assume any client honours it. §8.7 is what actually
  holds the line.
- A client MUST tolerate a HELLO response shorter than 32 bytes: an
  older daemon does not send these fields, and their absence means
  `reconnect_mode = 0`.

## 8.7 The daemon's backstop against reconnect storms

Because §8.6 is advisory, the daemon MUST bound reconnection independent
of client cooperation:

- A daemon MUST track connection attempts per peer PID over a sliding
  window and refuse admission beyond a threshold, returning `ERR_BUSY`
  and closing.
- Such a refusal MUST be recorded in the audit log, with the peer PID,
  UID and asserted client name.
- `ERR_BUSY` remains classed **retryable** (§4). A client that answers a
  storm backstop with an immediate retry is the exact failure the
  backstop exists to bound, so a client receiving `ERR_BUSY` at
  admission SHOULD back off at least as far as its `reconnect_base_ms`.

This is the only rule in §8 that does not depend on the client behaving.

## 8.8 Visibility requirements

A restart that nobody notices is a restart that gets diagnosed as a
compositor bug. Implementations MUST make it visible:

- **The daemon** MUST log to stderr (hence the journal, under
  `Type=notify`) when it starts, when it is socket-activated, and when
  it releases held state on behalf of a connection that ended
  unexpectedly, naming the peer PID and the number of codes released.
- **A client library** MUST expose a connection-state callback that
  fires on disconnection *and* on successful reconnection, so a
  long-running consumer can surface it in its own interface. Silently
  reconnecting is not acceptable: the user's held keys were released and
  their queued requests were dropped, and they are entitled to know.
- **A command-line client** MUST print a distinct message to stderr and
  MUST use distinct exit codes for: daemon unreachable, request refused
  by the daemon, and request dropped without being sent. Reporting `OK`
  when nothing was sent is a defect.

## 8.9 Implementation status

This section is normative for protocol version 1. Everything in it is
implemented in daemon 0.3.0 except where noted.

| Rule | Status |
|---|---|
| 8.2 per-connection state | shipped |
| 8.3 release on every disconnect path | shipped (`conn_release_held`) |
| 8.3.1 forgiving first release | shipped (`conn.held_ever`); `tests/test_wire831_forgive.py` |
| 8.4 mandatory re-HELLO | shipped (`ERR_HANDSHAKE_REQUIRED`) |
| 8.5 no replay | client-side rule; no daemon change needed |
| 8.6 advertised reconnect policy | shipped — HELLO response is 32 bytes; `tests/test_m36_identity.py` GG |
| 8.7 admission backstop | shipped (`attempt_admit`, 60 attempts / 10 s per pid); `tests/test_wire87_storm.py` |
| 8.8 daemon logging | shipped — start, release, **and socket activation** (M6); `tests/test_m6_activation.py` AB |
| 8.8 CLI exit codes | shipped — 1 usage, 2 unreachable, 3 refused, 4 dropped |
| 8.8 library callback | shipped — `uictl_on_state()`; `tests/test_mlib_lib.py` LH |

**Every rule in §8 is now implemented.** The two entries that were
blocked when this section was written have since landed, and both landed
as the rule described rather than as a retrofit — which is what writing
§8 before M6 and before `libuictl` was for.

Two consequences of socket activation are worth stating here rather than
leaving to be discovered.

**The daemon may not be running between your connections.** Under
activation it is started by the first `connect()`, and it MAY be
configured to exit again once no connections remain. A client therefore
cannot assume that the pid it talked to last time is the pid it is
talking to now, and MUST NOT treat a changed pid as an error. Nothing in
§8 changes: the daemon only exits with an empty connection table, so it
never disappears out from under a held key, and everything a client
needs to re-establish is already covered by §8.4's mandatory re-HELLO.
The observable cost is latency — the first request after an idle exit
pays for the virtual devices being registered again.

**The socket file belongs to the `.socket` unit**, and the daemon does
not remove it on shutdown. A daemon that unlinked it would leave the
unit listening on an inode nothing can reach, so every later `connect()` would fail with
`ECONNREFUSED` and no restart of the *service* would fix it. A client
seeing that should report it as an operator problem — the socket unit
needs restarting — and not as a reason to retry forever.

---

# 9. Conformance vectors

## 9.0 How to use these

Byte-exact frames, little-endian, with the offset in hex at the left of
each line. An implementation in any language can check itself against
them without a running daemon — which is the point: the first external
consumer is written in Rust, will not link `libuictl`, and needs
something better than prose to test against.

**Machine-readable form: `vectors.json`**, installed to
`$datadir/uictl/vectors.json`. Same vectors, emitted by the same
generator (`gen_vectors --json`, `make vectors.json`), carrying for each
one its id, kind, byte string, the vector a response answers, the result
code a rejected frame MUST produce, and the byte ranges marked
**[varies]** below as explicit `{offset, len}` pairs. Use it for the
assertions and read this section for the reasons — a consumer that has to
regex a markdown table is a consumer that will ship a second copy of the
frames, which is what §9 exists to prevent.
`tests/test_wire9_vectors.py` fails if the JSON and this document ever
carry different bytes.

**These vectors are generated, not typed.** `tests/gen_vectors.c` emits
this section from `src/proto.h`, so every offset, size and enum value
comes from the same header the daemon compiles against.
`tests/test_wire9_vectors.py` regenerates them and diffs against this
file, so a field that moves in the header and not in the document is a
test failure rather than something a reader might notice. Regenerate
with:

```
make gen-vectors        # prints the section body to stdout
```

`plan-multiclient.md` open question 5 asked whether the vectors should
be hex frames plus an expected decode, or a replay mode inside the
daemon that a test harness could drive. **Hex, and the question is now
closed.** A test mode in a security binary is a code path that exists in
production for the benefit of tests, and this broker's whole claim is
that it has no such paths. A hex file also serves the implementor who
has not built the daemon yet.

Fields marked **[varies]** are not part of the vector: an implementation
MUST read them from the frame rather than assert them. They depend on
the device that came up, the opcodes this build implements, or the
daemon's version.

Vector ids are stable. **R** = request, **S** = response, **P** = pushed
by the daemon, **N** = a frame that MUST be rejected.

<!-- BEGIN GENERATED VECTORS -->
## 9.1 Requests

Every request below is stamped `version = 1` and
`source_tag = SRC_CLI` (1). `seq` is the client's own counter and
is echoed untouched (§2.7); the values here are arbitrary.

#### R1 — `HELLO`

| field | value |
|---|---|
| `opcode` | `OP_HELLO` (3) |
| `payload_len` | 36 |
| `proto_min / proto_max` | 1 / 1 |
| `client_name` | `"uictl"`, NUL-padded to 32 bytes |

```
0000  01 00 03 00 01 00 00 00  01 00 00 00 24 00 00 00
0010  01 00 01 00 75 69 63 74  6c 00 00 00 00 00 00 00
0020  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
0030  00 00 00 00
```

The 27 trailing zero bytes are not optional padding a client
may omit: `client_name` is a fixed 32-byte field and every byte
after the NUL MUST be zero (§3.5).

#### R2 — `PING` — the whole frame is the header

| field | value |
|---|---|
| `opcode` | `OP_PING` (1) |
| `payload_len` | 0 |

```
0000  01 00 01 00 01 00 00 00  02 00 00 00 00 00 00 00
```

#### R3 — absolute motion

| field | value |
|---|---|
| `opcode` | `OP_MOVE_ABS` (2) |
| `x / y` | 100 / 200, device units (§3.4) |

```
0000  01 00 02 00 01 00 00 00  03 00 00 00 08 00 00 00
0010  64 00 00 00 c8 00 00 00
```

#### R4 — relative motion, negative delta

| field | value |
|---|---|
| `opcode` | `OP_MOVE_REL` (12) |
| `dx / dy` | -5 / 3 |

```
0000  01 00 0c 00 01 00 00 00  04 00 00 00 08 00 00 00
0010  fb ff ff ff 03 00 00 00
```

`dx = -5` is `fb ff ff ff`: two's complement, little-endian.
An implementation that encodes signed fields as sign-and-
magnitude, or that byte-swaps, fails here and nowhere else —
which is why this vector uses a negative number.

#### R5 — scroll

| field | value |
|---|---|
| `opcode` | `OP_SCROLL` (13) |
| `notches_v / notches_h` | 1 / 0 — one detent up |

```
0000  01 00 0d 00 01 00 00 00  05 00 00 00 08 00 00 00
0010  01 00 00 00 00 00 00 00
```

#### R6 — button press

| field | value |
|---|---|
| `opcode` | `OP_BUTTON` (11) |
| `code` | `BTN_LEFT` = 272 (0x110) |
| `down` | 1 — press |
| `reserved` | 0, and MUST be |

```
0000  01 00 0b 00 01 00 00 00  06 00 00 00 04 00 00 00
0010  10 01 01 00
```

#### R7 — button release — never confirmed, never rate-charged

```
0000  01 00 0b 00 01 00 00 00  07 00 00 00 04 00 00 00
0010  10 01 00 00
```

#### R8 — key tap

| field | value |
|---|---|
| `opcode` | `OP_KEY_TAP` (4) |
| `keycode` | 183 (`KEY_F13`) |

```
0000  01 00 04 00 01 00 00 00  08 00 00 00 02 00 00 00
0010  b7 00
```

#### R9 — `KEY_SEQUENCE` — balanced Ctrl+A

| field | value |
|---|---|
| `opcode` | `OP_KEY_SEQUENCE` (5) |
| `count` | 4 |
| `items` | down 29, down 30, up 30, up 29 — Ctrl+A |
| `payload_len` | 20 = 4 + 4 x 4 |

```
0000  01 00 05 00 01 00 00 00  09 00 00 00 14 00 00 00
0010  04 00 00 00 1d 00 01 00  1e 00 01 00 1e 00 00 00
0020  1d 00 00 00
```

Balance is tracked per key, not counted: `down 29, down 29,
up 29, up 29` sums to zero and is still refused (§5B.2).

#### R10 — `KEY_DOWN` — same 2-byte payload as `KEY_TAP`

```
0000  01 00 06 00 01 00 00 00  0a 00 00 00 02 00 00 00
0010  b7 00
```

#### R11 — `KEY_UP` — the frame that is never refused for policy

```
0000  01 00 07 00 01 00 00 00  0b 00 00 00 02 00 00 00
0010  b7 00
```

#### R12 — `BATCH` — nudge then click, one device, one report

| field | value |
|---|---|
| `opcode` | `OP_BATCH` (14) |
| `count` | 2 |
| `item 0` | `MOVE_REL` dx=10 dy=0 |
| `item 1` | `BUTTON` code=272 down=1 |
| `payload_len` | 28 = 4 + 2 x 12 |

```
0000  01 00 0e 00 01 00 00 00  0c 00 00 00 1c 00 00 00
0010  02 00 00 00 0c 00 00 00  0a 00 00 00 00 00 00 00
0020  0b 00 00 00 10 01 00 00  01 00 00 00
```

Both items land on the pointer, so this is one `SYN_REPORT`.
Adding a key item would make it two — atomic per device, and
nothing below the kernel joins them (§5B.4).

#### R13 — subscribe as the confirmer

| field | value |
|---|---|
| `opcode` | `OP_CONFIRM_SUBSCRIBE` (8) |
| `payload_len` | 0 — the request is the whole message |

```
0000  01 00 08 00 01 00 00 00  0d 00 00 00 00 00 00 00
```

#### R14 — approve a parked request

| field | value |
|---|---|
| `opcode` | `OP_CONFIRM_DECIDE` (10) |
| `token` | 1 — echoed from the prompt |
| `allow` | 1. **Any other value denies** (§7.5) |

```
0000  01 00 0a 00 01 00 00 00  0e 00 00 00 08 00 00 00
0010  01 00 00 00 01 00 00 00
```

---

## 9.2 Responses

A response echoes the request's header with `payload_len`
rewritten, then `u16 result`, then opcode-specific data (§2.4).
Each vector below names the request it answers.

#### S1 — `PING` answered

| field | value |
|---|---|
| `answers` | R2 |
| `payload_len` | 2 — the result and nothing else |
| `result` | `OK` (0) |

```
0000  01 00 01 00 01 00 00 00  02 00 00 00 02 00 00 00
0010  00 00
```

Note the echo: `opcode` is still 1 and `seq` is still 2. A
client matches on those, not on arrival order alone.

#### S2 — `HELLO` answered — the capability set

| field | value |
|---|---|
| `answers` | R1 |
| `payload_len` | 34 = 2 + 32 |
| `proto_selected` | 1 |
| `device_caps` | 0x000f — all four bits **[varies]** |
| `abs_range_max` | 32767 |
| `opcode_bitmap` | 0x0000000000007ffe **[varies]** |
| `daemon_version` | 0x000300 = 0.3.0 **[varies]** |
| `reconnect_*` | 0 = `RECONNECT_UNSPEC`, no registry advice |

```
0000  01 00 03 00 01 00 00 00  01 00 00 00 22 00 00 00
0010  00 00 01 00 0f 00 ff 7f  00 00 fe 7f 00 00 00 00
0020  00 00 00 03 00 00 00 00  00 00 00 00 00 00 00 00
0030  00 00
```

**[varies]** marks a field an implementation MUST read rather
than assert. `device_caps` is whatever the device came up
with, `opcode_bitmap` is what this build implements, and
`daemon_version` is informational — branching on it is the
feature-sniffing §2.2 forbids. The three reconnect bytes and
`reserved2` are the §8.6 tail: a client built against the
24-byte prefix reads this same frame and ignores them.

#### S3 — a command acknowledged

| field | value |
|---|---|
| `answers` | R3 |
| `result` | `OK` (0) |

```
0000  01 00 02 00 01 00 00 00  03 00 00 00 02 00 00 00
0010  00 00
```

#### S4 — the correctable refusal

| field | value |
|---|---|
| `answers` | R3, sent before any `HELLO` |
| `result` | `ERR_HANDSHAKE_REQUIRED` (8) |

```
0000  01 00 02 00 01 00 00 00  03 00 00 00 02 00 00 00
0010  08 00
```

Per-frame, not fatal: the payload was consumed, so the next
frame boundary is known. Send `HELLO` on this same connection
and retry (§4.2).

#### S5 — an admission refusal (§1.2)

| field | value |
|---|---|
| `answers` | nothing — sent before the peer is a connection |
| `opcode` | 0 (`OP_INVALID`) |
| `seq` | 0 |
| `result` | `ERR_BUSY` (7) |

```
0000  01 00 00 00 00 00 00 00  00 00 00 00 02 00 00 00
0010  07 00
```

This frame matches no request. A client that reads it as a
reply to something it sent will mis-attribute it; a client that
does not read it at all reports a refusal as a mysterious EOF.
The same shape carries `ERR_DENIED_BY_POLICY` (4) when the peer
uid does not match.

---

## 9.3 The frame the daemon sends unprompted

#### P1 — a prompt pushed to the subscribed confirmer

| field | value |
|---|---|
| `opcode` | `OP_CONFIRM_REQUEST` (9) |
| `seq` | **the token**, not a client counter (§7.4) |
| `source_tag` | 0 — the daemon sets none |
| `token / peer_pid` | 1 / 4242 |
| `opcode (payload)` | 4 = `KEY_TAP` |
| `keycode` | 183 |
| `cl` | 0 = `untrusted`, daemon-derived |
| `client_name` | `"agent"` — self-asserted (§7.0) |
| `payload_len` | 48 |

```
0000  01 00 09 00 00 00 00 00  01 00 00 00 30 00 00 00
0010  01 00 00 00 92 10 00 00  04 00 b7 00 00 00 00 00
0020  61 67 65 6e 74 00 00 00  00 00 00 00 00 00 00 00
0030  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
```

Not a response: nothing is echoed, because there was no
request. A client library that assumes one read per write
cannot host a confirmer (§2.7).

---

## 9.4 Frames a conforming daemon MUST reject

These are the negative vectors. An implementation that accepts
any of them is not conforming, and each one is a bug class rather
than a typo.

#### N1 — oversized payload — header only, no payload follows

| field | value |
|---|---|
| `payload_len` | 4097 — one over `UICTL_MAX_PAYLOAD` |
| `expected` | `ERR_TOO_LARGE` (5), **then close** |

```
0000  01 00 02 00 01 00 00 00  64 00 00 00 01 10 00 00
```

Fatal to the stream (§2.6): the daemon cannot know where the
next frame starts. It MUST answer before closing, and it MUST
NOT attempt to read 4097 bytes into a 4096-byte buffer — this
is the vector that catches the one field an attacker fully
controls.

#### N2 — wrong payload size — the first 19 bytes on the wire

| field | value |
|---|---|
| `payload_len` | 3, where `KEY_TAP` is exactly 2 |
| `expected` | `ERR_PAYLOAD_INVALID` (3), per-frame |

```
0000  01 00 04 00 01 00 00 00  65 00 00 00 03 00 00 00
0010  b7 00 00
```

Command payloads are exact-size, never `>=` (§2.3). The
connection survives: the payload was consumed, so the next
boundary is known.

#### N3 — non-zero reserved field

| field | value |
|---|---|
| `reserved` | 1 |
| `expected` | `ERR_PAYLOAD_INVALID` (3) |

```
0000  01 00 05 00 01 00 00 00  66 00 00 00 08 00 00 00
0010  01 00 01 00 b7 00 01 00
```

Reserved bytes are read and rejected, not ignored (§2.3), so a
future field cannot collide with junk an old client left there.
This sequence is also unbalanced, which would refuse it anyway —
a conforming daemon MAY report either, and the reserved check
comes first.

#### N4 — a client name that would forge audit lines

| field | value |
|---|---|
| `client_name` | `"ui\nctl"` — a newline at offset 2 |
| `expected` | `ERR_PAYLOAD_INVALID` (3), and the name is **not** echoed |

```
0000  01 00 03 00 01 00 00 00  67 00 00 00 24 00 00 00
0010  01 00 01 00 75 69 0a 63  74 6c 00 00 00 00 00 00
0020  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
0030  00 00 00 00
```

The audit log is newline-delimited (§3.5). A daemon that
accepts this hands the client the ability to write invented
denials into the record that exists to hold it accountable.

#### N5 — version hopping after the handshake

| field | value |
|---|---|
| `version` | 2, on a connection that negotiated 1 |
| `expected` | `ERR_VERSION` (1), **then close** |

```
0000  02 00 04 00 01 00 00 00  68 00 00 00 02 00 00 00
0010  b7 00
```

The version is pinned for the life of the connection (§3.3).
Fatal, because a rejected version means `payload_len` is not
trustworthy either. Sent *before* a `HELLO`, this same frame is
`ERR_HANDSHAKE_REQUIRED` instead — the pin does not exist yet.

<!-- END GENERATED VECTORS -->

## 9.5 What these vectors do not cover

They are a decoder test, not a daemon test. They say nothing about
timing, about the order two connections are served in, or about
anything with a device effect — asserting that `KEY_TAP` reaches
`/dev/uinput` needs a real device and an `EVIOCGRAB`, which is what the
Python suites in `tests/` are for.

Nor are they exhaustive: there is one vector per *class* of mistake, not
one per opcode-and-field combination. The five negative vectors in §9.4
are the ones worth having — an unbounded length, a wrong size, a
non-zero reserved field, a name that forges log lines, and a version
hop — because each is a bug an implementation can ship without ever
noticing.
