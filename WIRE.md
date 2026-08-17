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
| 5B | **Opcodes — the keyboard, and `BATCH`** | **normative** |
| 6 | **Held state** | **normative** |
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
