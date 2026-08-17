# uictl wire protocol

**Status:** draft. **Protocol version:** 1. **Daemon:** 0.3.0.

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
| 1 | Transport | *not yet written* |
| 2 | Frame format | *not yet written* |
| 3 | Handshake | *not yet written* |
| 4 | Result codes and response classes | *not yet written* |
| 5A | **Opcodes — the pointer** | **normative** |
| 5B | Opcodes — the keyboard, and `BATCH` | *not yet written* |
| 6 | Held state | *not yet written* |
| 7 | Confirmation | *not yet written* |
| 8 | **Connection lifecycle and restart** | **normative** |
| 9 | Conformance vectors | *not yet written* |

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
| 8.8 daemon logging | shipped for start and release; socket activation lands with M6 |
| 8.8 CLI exit codes | shipped — 1 usage, 2 unreachable, 3 refused, 4 reserved for dropped |
| 8.8 library callback | **blocked** — there is no `libuictl` yet (M-lib 2) |

Two entries are not "shipped" and neither is a gap in §8:

- **Socket activation logging** has nothing to log until M6 introduces
  `uictld.socket`. The start line it would extend already exists.
- **The library callback** cannot be written before `libuictl` exists
  (M-lib 2). The rule stays normative so that the library is built to it
  rather than having it retrofitted, which is the same reason §8 was
  written before M6 rather than during it.
