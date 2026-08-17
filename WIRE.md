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
| 5 | Opcodes | *not yet written* |
| 6 | Held state | *not yet written* |
| 7 | Confirmation | *not yet written* |
| 8 | **Connection lifecycle and restart** | **normative** |
| 9 | Conformance vectors | *not yet written* |

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
