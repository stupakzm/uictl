// never use htonl/htons/ntohl/ntohs, that is for TCP/IP
#pragma once

#include <endian.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

/* The protocol range this build speaks (M3.6 task 4). The daemon
   commits to understanding every version in [MIN, MAX]; a client
   declares its own range in HELLO and the two are intersected.

   When to move these: bump MAX for a change that *breaks* an existing
   decoder — a field resized, reordered, or given a new meaning. Do NOT
   bump for additions: a new opcode is discovered through
   `opcode_bitmap`, a new device ability through `device_caps`, and a new
   trailing field through the append-only response rule. That is the
   whole point of shipping a capability map, and it is why adding
   OP_HELLO itself needed no bump. Raise MIN only to drop support for an
   old version, which is a deliberate compatibility break. */
#define UICTL_PROTO_MIN 1u
#define UICTL_PROTO_MAX 1u
/* What a client puts in a frame header by default: the newest it speaks. */
#define UICTL_PROTO_VERSION UICTL_PROTO_MAX
#define UICTL_MAX_PAYLOAD 4096

/* Opcodes are on the wire: append only, never renumber. A client built
   against an older header must keep meaning the same thing by the same
   number.

   OP_KEY_TAP exists here from M4 step 3 but is NOT advertised in
   `opcode_bitmap` and NOT answered by the daemon until step 7, when real
   injection is connected behind the deny-list. Defining the shape early
   is deliberate — the payload layout and the client encoder can be
   settled while the handler is still a stub — but the bitmap is the
   contract, and it must not claim a key can be pressed before one can.
   See plan.md §"v0.2 Milestone 4" for why policy lands before the
   injection path rather than after. */
enum uictl_op {
  OP_INVALID = 0,
  OP_PING,
  OP_MOVE_ABS,
  OP_HELLO,
  OP_KEY_TAP,
  OP_KEY_SEQUENCE,

  /* M4 step 9, unblocked by M4.5. These are the only opcodes that leave
     kernel state behind when the request finishes, which is why they
     waited for the machinery that guarantees it comes back:
     per-connection ownership (task 1), a synthesized release on every
     way a connection can end (task 2), arbitration between connections
     (task 3), and a dead-man timer for a client that is alive but stuck
     (task 4). Shipping them earlier would have meant a socket could
     press a key with nothing able to promise it would ever come up.

     Both take struct uictl_payload_key — the same 2-byte payload as
     OP_KEY_TAP, because the question ("which key?") is the same.

     A one-shot client has no use for these: the release fires when its
     connection closes, so `key-down` from a CLI that then exits is an
     elaborate way to write KEY_TAP. They exist for long-lived clients
     that need a key held *across* other requests — drag, modifier+move
     — which is exactly what OP_KEY_SEQUENCE deliberately cannot
     express. */
  OP_KEY_DOWN,
  OP_KEY_UP
};

/* Result codes are ON THE WIRE. Append only — never insert, never
   reorder. A client built against an older header must keep decoding
   every code it already knows to the same meaning.

   Three classes, and a client library needs to tell them apart to have
   a sane reconnect policy (M3.7 task 3 / G8):
     terminal    — retrying changes nothing. ERR_DENIED_BY_POLICY (your
                   uid is wrong), ERR_VERSION, ERR_OPCODE_UNKNOWN,
                   ERR_PAYLOAD_INVALID, ERR_TOO_LARGE,
                   ERR_KEY_DENYLISTED (never, by design).
     fixable     — retrying identically fails, but a stated change to
                   local configuration makes it work.
                   ERR_KEY_NOT_ALLOWED: add the keycode to
                   ~/.config/uictl/policy and restart the daemon.
     retryable   — the daemon is momentarily out of room, or another
                   connection is mid-gesture. ERR_BUSY,
                   ERR_KEY_HELD_BY_OTHER, ERR_RATE_LIMITED (after a
                   wait — see its note).
     client bug  — the request contradicts state the client itself
                   established. ERR_KEY_ALREADY_HELD, ERR_KEY_NOT_HELD,
                   ERR_TOO_MANY_HELD. Retrying identically fails; the
                   client has to reconcile its own held set first.
     correctable — the request was fine, the connection wasn't ready.
                   ERR_HANDSHAKE_REQUIRED: send OP_HELLO on this same
                   connection and the retry succeeds.
   Before ERR_BUSY existed, "table full" and "wrong uid" were the same
   code, so a client had to either hammer a daemon that told it to go
   away or give up on a condition that clears in milliseconds. */
enum uictl_result {
  OK = 0,
  ERR_VERSION,
  ERR_OPCODE_UNKNOWN,
  ERR_PAYLOAD_INVALID,
  ERR_DENIED_BY_POLICY,
  ERR_TOO_LARGE,
  ERR_INTERNAL,
  ERR_BUSY,                /* retryable: no connection slot right now */
  ERR_HANDSHAKE_REQUIRED,  /* correctable: send OP_HELLO, then retry */

  /* The two key refusals are separate codes, not one, because they call
     for opposite responses from whoever hit them:

       ERR_KEY_DENYLISTED  — a destructive key. Static, in the daemon,
                             NOT overridable by configuration. Telling a
                             user "edit your policy file" here would send
                             them to do something that cannot work.
       ERR_KEY_NOT_ALLOWED — simply absent from ~/.config/uictl/policy.
                             One line of config away from working.

     A client that cannot distinguish them can only print "denied", which
     leaves the user to guess which of the two situations they are in.
     That guess is the whole difference between "add a line to a file"
     and "this will never work, do something else". */
  ERR_KEY_DENYLISTED,
  ERR_KEY_NOT_ALLOWED,

  /* Separate from ERR_BUSY on purpose. ERR_BUSY says the daemon has no
     room and the client should retry shortly — nothing about the client
     was wrong. This says the client is going faster than its class
     allows, and the fix is to *pace itself*, not to retry harder.
     A library that conflated them would answer a rate limit with a
     retry storm, which is the one response guaranteed to make it
     worse. Retryable, after a wait. */
  ERR_RATE_LIMITED,

  /* Held-state arbitration (M4.5 task 3). Three codes and not one,
     because the right response differs in each case and a client that
     cannot tell them apart can only give up:

       ERR_KEY_ALREADY_HELD  — *you* hold this key. Client bug: you lost
                               track of your own state. Retrying will
                               fail identically; the fix is to send the
                               UP you owe, or to stop sending the
                               duplicate DOWN.
       ERR_KEY_HELD_BY_OTHER — another connection holds it. Nothing
                               about this request was wrong and it may
                               well succeed later. Retryable, after a
                               wait — but back off, because the other
                               client is mid-gesture.
       ERR_KEY_NOT_HELD      — an UP for a key this connection does not
                               hold. Client bug, and usually a benign
                               one: the daemon may have force-released
                               it (dead-man timer) or the client is
                               double-releasing. Terminal for this
                               request; the key is up either way, which
                               is what the client wanted.

     Note what is deliberately absent: there is no code for "an UP was
     refused by policy". A client that holds a key must ALWAYS be able
     to release it, so the release path is not policy-gated and not
     rate-limited. Any refusal of an UP is a stuck key. */
  ERR_KEY_ALREADY_HELD,
  ERR_KEY_HELD_BY_OTHER,
  ERR_KEY_NOT_HELD,

  /* Too many keys held at once on one connection. A bound on untrusted
     input, in the same spirit as the payload cap: no real gesture needs
     more than a handful of keys down, and the bound keeps the
     synthesized release burst on disconnect small and predictable.
     Fixable by the client releasing what it holds. */
  ERR_TOO_MANY_HELD
};

/* ---- source_tag: ADVISORY METADATA ONLY (M3.6 task 6) ---------------
   The client writes this field itself, in every frame, unauthenticated.
   It therefore MUST NOT be an input to any decision. Its only legitimate
   consumer is the audit log, where it is a hint about what the client
   *says* it was doing.

   **Do not key a rate limit, a deny-list, an allowlist, a confirmation
   prompt, or any other policy on it.** That was the original M4 plan —
   a token bucket keyed on source_tag, CLI 50/s vs LLM 5/s — and it does
   not work: the LLM agent, the exact case the tier exists for, sends
   SRC_CLI and gets 50/s. A client choosing its own limit is not a limit.
   (Gap G2; the daemon-derived alternative is M3.6 task 5.)

   Policy inputs are, and remain: the peer pid/uid from SO_PEERCRED
   (kernel-filled, unforgeable) and the client class the daemon derives
   at HELLO from its own local registry. Both live on the daemon side of
   the socket. If you are about to read source_tag anywhere other than
   an audit line, you are reintroducing G2. */
#define SRC_CLI (1u << 0)
#define SRC_HOTKEY (1u << 1)
#define SRC_LLM (1u << 2)

struct uictl_frame_header {
  uint16_t version;
  uint16_t opcode;
  uint32_t source_tag;
  uint32_t seq;
  uint32_t payload_len;
};

/* Response framing (M3.6 task 1). A response is the request's header
   echoed — version, opcode, source_tag, seq — with payload_len rewritten,
   followed by:

     uint16_t result;          always present, always first
     uint8_t  data[...];       opcode-specific, may be empty

   so payload_len >= UICTL_RESULT_SIZE on every response, and
   payload_len - UICTL_RESULT_SIZE is the answer's length.

   Before this the daemon hardcoded payload_len = 2 and could only ever
   acknowledge a command, never answer a question — which is why
   OP_HELLO had nowhere to return a capability set. Putting `result`
   first (rather than a separate reply header) means an old decoder that
   reads two bytes and stops still reads the right two bytes; only the
   payload_len equality check has to become >=. */
#define UICTL_RESULT_SIZE (sizeof(uint16_t))
#define UICTL_MAX_RESP_DATA (UICTL_MAX_PAYLOAD - UICTL_RESULT_SIZE)

_Static_assert(sizeof(struct uictl_frame_header) == 16,
               "frame header must be exactly 16 bytes");

struct uictl_payload_move_abs {
  int32_t x;
  int32_t y;
};

_Static_assert(sizeof(struct uictl_payload_move_abs) == 8,
               "MOVE_ABS payload must be exactly 8 bytes");

/* HELLO — the handshake frame (M3.6 task 2). The client states the
   protocol range it can speak and names itself; the daemon answers with
   what it selected and what it can do (task 3).

   **HELLO is the version-invariant bootstrap frame.** Its envelope and
   the prefix of its payload are fixed for all protocol versions, and a
   daemon accepts one stamped with *any* version — otherwise negotiation
   is impossible for exactly the clients that need it: a v9 client
   talking to a v1 daemon cannot send a v9-stamped frame the daemon will
   admit, and cannot know to send a v1-stamped one until it has asked.
   The bootstrap frame has to be readable before agreement exists.

   Its payload follows the same append-only growth rule as the response,
   so an older daemon reads the prefix of a newer client's HELLO, answers
   with its own range, and the client can retry inside it. Every *other*
   opcode is gated on the negotiated version.

   `client_name` is fixed-width and NUL-terminated rather than
   length-prefixed: at 32 bytes the waste is irrelevant, and a fixed
   width means the payload has exactly one legal size, which is one
   fewer thing for the decoder to get wrong.

   The name is **self-asserted and always will be** — it is a label, not
   a credential. Its value is that it is asserted once, at a checkpoint,
   where an unknown name can default to the most restrictive class,
   instead of per-frame like `source_tag`. Anything that must not be
   forgeable comes from `SO_PEERCRED` instead. */
#define UICTL_CLIENT_NAME_MAX 32

struct uictl_payload_hello {
  uint16_t proto_min;
  uint16_t proto_max;
  char client_name[UICTL_CLIENT_NAME_MAX];
};

_Static_assert(sizeof(struct uictl_payload_hello) == 36,
               "HELLO payload must be exactly 36 bytes");

/* KEY_TAP payload (M4 step 3): one keycode, pressed and released.

   Numeric keycodes only for now — a symbolic `KEY_A` name table belongs
   in the client and is a later nicety. Keeping the first keyboard RPC
   numeric is honest about what the wire actually carries.

   `uint16_t` because that is what `input_event.code` is; a wider field
   would invite values the kernel cannot represent, and a narrower one
   could not reach KEY_MAX (767). The daemon still range-checks it: the
   type bounds what is *expressible*, not what is *acceptable*.

   Exactly 2 bytes, no padding, so `payload_len == 2` is the only legal
   size for this opcode. Deliberately NOT append-only like HELLO's:
   HELLO is the bootstrap frame and must survive version skew, while a
   command frame is only ever sent after the version is negotiated and
   pinned, so an exact size is the stricter and better check. */
struct uictl_payload_key {
  uint16_t keycode;
};

_Static_assert(sizeof(struct uictl_payload_key) == 2,
               "KEY_TAP payload must be exactly 2 bytes");

/* KEY_SEQUENCE (M4 step 9): several key transitions applied atomically,
   under a single SYN_REPORT. This is what modifier+key needs — Ctrl+A is
   `down 29, down 30, up 30, up 29`, and a client that had to send four
   separate requests could be interrupted between any two of them.

   **Every sequence must be self-balancing**: each press has its matching
   release inside the same request, and the daemon refuses one that is
   not. That is what makes this shippable while OP_KEY_DOWN/OP_KEY_UP are
   still blocked on M4.5 — a request cannot leave a key held, so there is
   no orphaned kernel state for a dying client to strand. A stuck Ctrl
   when your input broker is the wedged thing is genuinely unpleasant to
   recover from; refusing to create the possibility is cheaper than
   cleaning it up.

   Layout: `{u16 count, u16 reserved}` then exactly `count` items of
   `{u16 keycode, u8 value, u8 reserved}`, so payload_len is exactly
   4 + 4*count. Both reserved fields MUST be zero — they are wire space
   the daemon reads and rejects rather than ignores, so a future field
   cannot collide with junk an old client happened to send. */
#define UICTL_SEQ_MAX 16

struct uictl_seq_item {
  uint16_t keycode;
  uint8_t value; /* 1 = press, 0 = release. nothing else. */
  uint8_t reserved;
};

struct uictl_payload_key_seq {
  uint16_t count;
  uint16_t reserved;
};

_Static_assert(sizeof(struct uictl_seq_item) == 4,
               "sequence item must be exactly 4 bytes");
_Static_assert(sizeof(struct uictl_payload_key_seq) == 4,
               "sequence header must be exactly 4 bytes");

static inline size_t uictl_seq_payload_len(uint16_t count) {
  return sizeof(struct uictl_payload_key_seq) +
         (size_t)count * sizeof(struct uictl_seq_item);
}

/* What the daemon can do, answered in the HELLO response (M3.6 task 3).
   Capability bits describe the *device*, opcode bits describe the
   *protocol*; they are separate because M4 registers every keycode on
   the device while the RPC layer still refuses most of them —
   capability is not permission. */
#define CAP_POINTER_ABS (1u << 0) /* EV_ABS ABS_X/ABS_Y — M3 */
#define CAP_KEYBOARD (1u << 1)    /* EV_KEY — M4 */
#define CAP_POINTER_REL (1u << 2) /* REL_X/REL_Y, wheels — M5.5 */
#define CAP_BUTTONS (1u << 3)     /* BTN_LEFT/RIGHT/MIDDLE — M5.5 */

/* Informational only. A client must branch on `opcode_bitmap` and
   `device_caps`, never on this: feature-sniffing by version number is
   how a protocol acquires a compatibility matrix nobody can test. */
#define UICTL_DAEMON_VERSION 0x000300u /* 0.3.0, major<<16|minor<<8|patch */

/* HELLO response data — the bytes after `result` in the response frame.

   Growth rule: **append only, never reorder, never resize a field.** A
   client accepts any payload of at least this size and ignores the tail
   it does not understand, so adding a field costs no protocol version
   bump and no flag day. That is the concrete answer to G3, and it only
   works if the prefix stays byte-stable forever.

   `reserved` is explicit rather than left to the compiler. Without it
   the struct would still be 24 bytes — the u64 forces 8-byte alignment —
   but those 4 bytes would be *implicit tail padding*, and this struct is
   memcpy'd straight onto a socket. Uninitialised padding on the wire is
   a stack-content leak to whatever is listening. Naming the field means
   it gets zeroed like everything else. */
struct uictl_resp_hello {
  uint16_t proto_selected; /* version the daemon will speak on this conn */
  uint16_t device_caps;    /* CAP_* bits */
  uint32_t abs_range_max;  /* ABS_X/ABS_Y max in device space */
  uint64_t opcode_bitmap;  /* bit N set => opcode N is implemented */
  uint32_t daemon_version; /* UICTL_DAEMON_VERSION, informational */
  uint32_t reserved;       /* MUST be zero; not padding, see above */
};

_Static_assert(sizeof(struct uictl_resp_hello) == 24,
               "HELLO response must be exactly 24 bytes");

/* Bit N of opcode_bitmap is opcode N, so the map covers opcodes 0..63
   and bit 0 (OP_INVALID) is never set. 64 is not a limit worth worrying
   about yet — v0.1 through M5.5 define well under a dozen — and when it
   is, the append-only rule above means a second word is a field, not a
   redesign. */
#define UICTL_OP_BIT(op) (1ull << (op))

_Static_assert(
    __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__,
    "uictl wire format is little-endian. port encode/decode for big-endian");

static inline void encode_frame_header(const struct uictl_frame_header *h,
                                       void *buf) {
  memcpy(buf, h, sizeof(*h));
}
static inline void decode_frame_header(const void *buf,
                                       struct uictl_frame_header *h) {
  memcpy(h, buf, sizeof(*h));
}
static inline void encode_move_abs(const struct uictl_payload_move_abs *p,
                                   void *buf) {
  memcpy(buf, p, sizeof(*p));
}
static inline void decode_move_abs(const void *buf,
                                   struct uictl_payload_move_abs *p) {
  memcpy(p, buf, sizeof(*p));
}
static inline void encode_key(const struct uictl_payload_key *p, void *buf) {
  memcpy(buf, p, sizeof(*p));
}
static inline void decode_key(const void *buf, struct uictl_payload_key *p) {
  memcpy(p, buf, sizeof(*p));
}
static inline void encode_hello(const struct uictl_payload_hello *p,
                                void *buf) {
  memcpy(buf, p, sizeof(*p));
}
static inline void decode_hello(const void *buf,
                                struct uictl_payload_hello *p) {
  memcpy(p, buf, sizeof(*p));
}
static inline void encode_resp_hello(const struct uictl_resp_hello *p,
                                     void *buf) {
  memcpy(buf, p, sizeof(*p));
}
static inline void decode_resp_hello(const void *buf,
                                     struct uictl_resp_hello *p) {
  memcpy(p, buf, sizeof(*p));
}

/* Is this a name the daemon is willing to record? Shared by both
   binaries so the client can refuse its own bad name locally instead of
   learning it from a round trip.

   This is not cosmetic validation. The name's destination is the **audit
   log**, which is newline-delimited text: a name containing '\n' would
   let a client write forged audit lines — invented pids, invented
   opcodes, invented denials — into the one record that exists to hold it
   accountable. Restricting to a conservative character set kills that
   class outright, along with terminal escape sequences aimed at whoever
   reads the log with `cat`.

   The trailing check matters for a different reason: bytes after the NUL
   are invisible to every consumer, so allowing them would make two
   different payloads produce identical log lines, and hand a covert
   channel to a client whose whole point is to be observable. */
static inline int uictl_client_name_valid(const char client_name[static
                                          UICTL_CLIENT_NAME_MAX]) {
  size_t i = 0;
  while (i < UICTL_CLIENT_NAME_MAX && client_name[i] != '\0') {
    char ch = client_name[i];
    int ok = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
             (ch >= '0' && ch <= '9') || ch == '.' || ch == '_' || ch == '-';
    if (!ok)
      return 0;
    i++;
  }
  if (i == 0)                            /* empty: name yourself */
    return 0;
  if (i == UICTL_CLIENT_NAME_MAX)        /* unterminated */
    return 0;
  for (size_t j = i; j < UICTL_CLIENT_NAME_MAX; j++)
    if (client_name[j] != '\0')          /* junk hiding past the NUL */
      return 0;
  return 1;
}

static inline ssize_t read_full(int fd, void *buf, size_t n) {
  size_t total = 0;
  char *p = buf;
  while (total < n) {
    ssize_t r = read(fd, p + total, n - total);
    if (r < 0) {
      if (errno == EINTR)
        
        continue;
      return -1;
    }
    if (r == 0)
      break;
    total += (size_t)r;
  }
  return (ssize_t)total;
}

static inline ssize_t write_full(int fd, const void *buf, size_t n) {
  size_t total = 0;
  const char *p = buf;
  while (total < n) {
    ssize_t w = write(fd, p + total, n - total);
    if (w < 0) {
      if (errno == EINTR)
        continue;
      return -1;
    }
    total += (size_t)w;
  }
  return (ssize_t)n;
}
