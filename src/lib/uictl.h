/* libuictl — the C client library for uictld (M-lib task 2).
 *
 * WIRE.md is the contract; this is a convenience for C clients that do
 * not want to write a frame encoder. A consumer in Rust, Go or Zig
 * should implement the wire format directly against WIRE.md §9's
 * vectors — FFI for a 16-byte header and a length-prefixed payload
 * would be more work than the thing it wraps.
 *
 * Three rules this library is built around. Each one is a property the
 * CLI got right by being a one-shot process, and that a long-lived
 * library has to arrange deliberately.
 *
 * 1. THE LIBRARY NEVER PRINTS. Not to stderr, not on a fatal error, not
 *    "just this once" for something unexpected. A library that writes to
 *    a caller's stderr corrupts the output of any program that formats
 *    its own diagnostics — and the LLM agent that is the eventual
 *    consumer here formats structured output. Every failure comes back
 *    as a `struct uictl_error`, and uictl_strerror()/uictl_result_hint()
 *    turn one into text the CALLER decides where to put.
 *
 * 2. NOTHING WITH A DEVICE EFFECT IS EVER REPLAYED (WIRE.md §8.5). The
 *    library does not reconnect by itself and does not hold a queue
 *    across a reconnect. A request that was in flight when the
 *    connection died comes back as UICTL_E_DROPPED, forever, and the
 *    caller decides whether re-sending is safe. A library that silently
 *    retried a KEY_DOWN would be pressing a key the user never asked
 *    for, and it cannot distinguish "the daemon died before writing"
 *    from "the daemon wrote and died before replying".
 *
 * 3. A RECONNECT IS VISIBLE (WIRE.md §8.8). A long-lived consumer MUST
 *    be able to learn that its connection dropped and came back, because
 *    its held keys were released and its queued requests were dropped.
 *    uictl_on_state() is that callback, and it is not optional decoration
 *    — §8.8 says silently reconnecting is not acceptable.
 */
#ifndef UICTL_H
#define UICTL_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- errors ---------------------------------------------------------
   A *library* error is not a *wire* result, and conflating them is how a
   caller ends up retrying a socket that no longer exists. UICTL_E_REFUSED
   means the daemon answered and said no — `result` then carries the wire
   code and uictl_result_class() says whether retrying is sane. Every
   other value means the request did not get an answer at all. */
enum uictl_err {
  UICTL_OK = 0,
  UICTL_E_ENV,     /* XDG_RUNTIME_DIR unset, or the path does not fit  */
  UICTL_E_SOCKET,  /* socket()/connect() failed; see sys_errno         */
  UICTL_E_IO,      /* read/write failed, or the daemon closed on us    */
  UICTL_E_PROTO,   /* the daemon misframed: wrong opcode, seq or size  */
  UICTL_E_REFUSED, /* the daemon answered with a non-OK result         */
  UICTL_E_DROPPED, /* not sent, or in flight when the connection died  */
  UICTL_E_USAGE,   /* the caller passed something this API rejects     */
  UICTL_E_NOTSUP   /* this daemon does not implement that opcode       */
};

struct uictl_error {
  int err;         /* enum uictl_err                                   */
  int sys_errno;   /* errno at the point of failure, or 0              */
  uint16_t result; /* the wire result, when err == UICTL_E_REFUSED     */
};

/* What to DO about a wire result. Mirrors WIRE.md §4.2 exactly; a
   caller that switches on this instead of on individual codes keeps
   working when a code is appended. */
enum uictl_class {
  UICTL_CLASS_OK = 0,
  UICTL_CLASS_TERMINAL,    /* retrying changes nothing                 */
  UICTL_CLASS_FIXABLE,     /* a stated local change makes it work      */
  UICTL_CLASS_RETRYABLE,   /* back off and try again                   */
  UICTL_CLASS_CLIENT_BUG,  /* reconcile your own state first           */
  UICTL_CLASS_CORRECTABLE  /* handshake on this connection, then retry */
};

/* ---- the wire, as a consumer needs it -------------------------------
   Opcode numbers, result codes and capability bits are part of the
   protocol, so a consumer linking this library needs them: it cannot
   call uictl_has_op() or interpret uictl_error.result without them.

   They are declared HERE rather than by including the daemon's
   src/proto.h, because that header is the daemon's — full of its
   internal reasoning, its read_full/write_full helpers, and structs no
   consumer should be encoding by hand. Installing it as public API
   would make every one of those a compatibility surface.

   The duplication is checked, not trusted: libuictl.c carries a
   _Static_assert for every value below against proto.h, so a number
   that changes in one place and not the other fails the BUILD. Same
   guard-rail pattern the daemon uses where its platform capabilities
   become wire capabilities.

   The names are prefixed and the enums are named differently from
   proto.h's on purpose — libuictl.c includes both headers, and a
   collision there would be a compile error rather than a design. */

enum uictl_opcode {
  UICTL_OP_PING = 1,
  UICTL_OP_MOVE_ABS = 2,
  UICTL_OP_HELLO = 3,
  UICTL_OP_KEY_TAP = 4,
  UICTL_OP_KEY_SEQUENCE = 5,
  UICTL_OP_KEY_DOWN = 6,
  UICTL_OP_KEY_UP = 7,
  UICTL_OP_CONFIRM_SUBSCRIBE = 8,
  UICTL_OP_CONFIRM_REQUEST = 9, /* daemon -> client; see WIRE.md §7.4 */
  UICTL_OP_CONFIRM_DECIDE = 10,
  UICTL_OP_BUTTON = 11,
  UICTL_OP_MOVE_REL = 12,
  UICTL_OP_SCROLL = 13,
  UICTL_OP_BATCH = 14
};

/* WIRE.md §4.1. Append only; never renumber. */
enum uictl_wire_result {
  UICTL_RES_OK = 0,
  UICTL_RES_VERSION = 1,
  UICTL_RES_OPCODE_UNKNOWN = 2,
  UICTL_RES_PAYLOAD_INVALID = 3,
  UICTL_RES_DENIED_BY_POLICY = 4,
  UICTL_RES_TOO_LARGE = 5,
  UICTL_RES_INTERNAL = 6,
  UICTL_RES_BUSY = 7,
  UICTL_RES_HANDSHAKE_REQUIRED = 8,
  UICTL_RES_KEY_DENYLISTED = 9,
  UICTL_RES_KEY_NOT_ALLOWED = 10,
  UICTL_RES_RATE_LIMITED = 11,
  UICTL_RES_KEY_ALREADY_HELD = 12,
  UICTL_RES_KEY_HELD_BY_OTHER = 13,
  UICTL_RES_KEY_NOT_HELD = 14,
  UICTL_RES_TOO_MANY_HELD = 15,
  UICTL_RES_CONFIRM_UNAVAILABLE = 16,
  UICTL_RES_CONFIRM_DENIED = 17,
  UICTL_RES_CONFIRM_TIMEOUT = 18,
  UICTL_RES_NOT_CONFIRMER = 19
};

/* uictl_device_caps() bits. These describe the DEVICE; uictl_has_op()
   describes the PROTOCOL. Capability is not permission (WIRE.md §3.4). */
#define UICTL_CAP_POINTER_ABS 0x1u
#define UICTL_CAP_KEYBOARD 0x2u
#define UICTL_CAP_POINTER_REL 0x4u
#define UICTL_CAP_BUTTONS 0x8u

/* uictl_set_source_tag() values. Advisory. See §2.5 before using them
   for anything that looks like a decision. */
#define UICTL_SRC_CLI 0x1u
#define UICTL_SRC_HOTKEY 0x2u
#define UICTL_SRC_LLM 0x4u

/* Reconnect advice from §8.6, as uictl_reconnect_advice() reports it. */
#define UICTL_RECONNECT_UNSPEC 0u
#define UICTL_RECONNECT_NEVER 1u
#define UICTL_RECONNECT_BACKOFF 2u

#define UICTL_NAME_MAX 32       /* including the NUL */
#define UICTL_MAX_SEQ_STEPS 16
#define UICTL_MAX_BATCH_STEPS 16

/* ---- connection ----------------------------------------------------- */

typedef struct uictl_conn uictl_conn;

/* Skip the handshake. PING is the only opcode that works without one
   (WIRE.md §3.7), so this is for a pure liveness probe and nothing else.
   Every other call on such a connection returns ERR_HANDSHAKE_REQUIRED,
   which is UICTL_CLASS_CORRECTABLE — call uictl_hello() and retry. */
#define UICTL_NO_HELLO 0x1u

/* Connect and (unless UICTL_NO_HELLO) handshake. `name` is the
   self-asserted label from WIRE.md §3.5: 1-31 bytes of [A-Za-z0-9._-].
   It is a label, not a credential — what the daemon actually trusts is
   SO_PEERCRED — but it selects the class and roles the local registry
   gives it, so it is worth getting right.

   Returns NULL on failure with *e filled in. `e` may be NULL. */
uictl_conn *uictl_connect(const char *name, unsigned flags,
                          struct uictl_error *e);

/* Close and free. Every key this connection holds is released by the
   daemon as a consequence (WIRE.md §8.3) — that is the daemon's
   guarantee, not something this call arranges. */
void uictl_close(uictl_conn *c);

/* The socket, for a caller that wants to poll() it alongside its own
   fds. Do not read or write it: the library owns the framing, and a
   stolen byte desynchronises the stream permanently. -1 if the
   connection is dead. */
int uictl_fd(const uictl_conn *c);

/* Drop the current socket and connect again, with a fresh handshake
   (WIRE.md §8.4 — nothing negotiated survives a connection). Any
   outstanding pipelined request is answered UICTL_E_DROPPED and is NOT
   resent (§8.5). Fires the state callback on the way down and again on
   the way up. */
int uictl_reconnect(uictl_conn *c, struct uictl_error *e);

/* Send OP_HELLO on a connection made with UICTL_NO_HELLO, or after
   ERR_HANDSHAKE_REQUIRED. One per connection: a second is
   ERR_DENIED_BY_POLICY (§3.6). */
int uictl_hello(uictl_conn *c, struct uictl_error *e);

/* WIRE.md §8.8's requirement. `up` is 1 when a connection is
   established, 0 when one is lost. Called from inside library calls, on
   the caller's thread; do not call back into the library from it.

   It never fires for the FIRST connection: uictl_connect() is what
   returns the handle this is registered on, so that transition is its
   return value. The callback exists for the ones a caller cannot
   otherwise see. */
typedef void (*uictl_state_cb)(uictl_conn *c, int up, void *user);
void uictl_on_state(uictl_conn *c, uictl_state_cb cb, void *user);

/* Advisory metadata, audit-log only (WIRE.md §2.5). Setting it changes
   nothing about what the daemon permits — if you are reading this
   hoping to raise your own rate limit, that is exactly the design this
   field was demoted out of. Defaults to SRC_CLI. */
void uictl_set_source_tag(uictl_conn *c, uint32_t tag);

/* ---- what the daemon told us at HELLO -------------------------------
   All four are read from the HELLO response and are meaningless on a
   UICTL_NO_HELLO connection. */

/* The protocol range THIS BUILD of the library speaks, independent of
   any connection — what it puts in a HELLO's proto_min/proto_max.
   Exposed so a consumer can report the negotiation honestly: "1
   (asked 1-1)" says more than "1" when the two ever differ. */
void uictl_proto_range(uint16_t *min, uint16_t *max);

uint16_t uictl_proto_selected(const uictl_conn *c);
uint16_t uictl_device_caps(const uictl_conn *c);  /* CAP_* bits         */
uint32_t uictl_abs_range_max(const uictl_conn *c);/* MOVE_ABS clamp     */
uint32_t uictl_daemon_version(const uictl_conn *c);/* informational!    */

/* Does this daemon implement `opcode`? The ONLY correct way to
   feature-test (WIRE.md §2.2/§3.4): capability is not permission, and
   branching on uictl_daemon_version() is the feature-sniffing the
   capability map exists to prevent. */
int uictl_has_op(const uictl_conn *c, uint16_t opcode);

/* §8.6's advice, as the registry gave it for this client name. ADVISORY:
   the daemon cannot enforce any of it, because the decision is taken in
   this process at a moment when the daemon is usually not running. Any
   pointer may be NULL. */
void uictl_reconnect_advice(const uictl_conn *c, uint8_t *mode,
                            uint16_t *base_ms, uint8_t *max_tries);

/* ---- one call per opcode, synchronous -------------------------------
   Each sends one request and waits for its response. Return 0 on OK,
   -1 with *e filled in otherwise; a daemon refusal is UICTL_E_REFUSED
   with e->result carrying the wire code. */

int uictl_ping(uictl_conn *c, struct uictl_error *e);
int uictl_move_abs(uictl_conn *c, int32_t x, int32_t y,
                   struct uictl_error *e);
int uictl_move_rel(uictl_conn *c, int32_t dx, int32_t dy,
                   struct uictl_error *e);
int uictl_scroll(uictl_conn *c, int32_t notches_v, int32_t notches_h,
                 struct uictl_error *e);
int uictl_button(uictl_conn *c, uint16_t code, int down,
                 struct uictl_error *e);
int uictl_key_tap(uictl_conn *c, uint16_t keycode, struct uictl_error *e);
int uictl_key_down(uictl_conn *c, uint16_t keycode, struct uictl_error *e);
int uictl_key_up(uictl_conn *c, uint16_t keycode, struct uictl_error *e);

/* One item of a key sequence or a batch. Mirrors the wire structs
   rather than improving on them: a library type that reordered fields
   would make the vectors in WIRE.md §9 stop describing what this
   library sends. */
struct uictl_key_step {
  uint16_t keycode;
  uint8_t value; /* 1 = press, 0 = release. Nothing else. */
};

/* Atomic under one SYN_REPORT, and self-balancing: every press must have
   its release inside the same call, tracked per key rather than counted
   (§5B.2). Max UICTL_SEQ_MAX steps. */
int uictl_key_sequence(uictl_conn *c, const struct uictl_key_step *steps,
                       size_t n, struct uictl_error *e);

struct uictl_batch_step {
  uint16_t opcode; /* MOVE_ABS | MOVE_REL | SCROLL | BUTTON | KEY_DOWN | KEY_UP */
  int32_t a;       /* x  | dx | notches_v | button code | keycode */
  int32_t b;       /* y  | dy | notches_h | down flag    | unused  */
};

/* All-or-nothing, one SYN_REPORT **per device** — a batch touching both
   the pointer and the keyboard lands as two reports, exactly as the same
   gesture does on real hardware (§5B.4). Max UICTL_BATCH_MAX steps.

   A client whose registry entry carries the `confirm` role cannot send
   more than 10 items: the daemon parks at most 128 payload bytes, and a
   prompt that describes less than what would execute is worse than no
   prompt (§7.7.1). That comes back as ERR_TOO_LARGE. */
int uictl_batch(uictl_conn *c, const struct uictl_batch_step *steps,
                size_t n, struct uictl_error *e);

/* ---- pipelining -----------------------------------------------------
   Responses arrive in request order (WIRE.md §2.7), so submit() queues
   requests and await() collects them oldest-first. Worth it when the
   round trip dominates: 16 nudges pipelined is one round trip, not 16.

   Deliberately not "fire and forget": every submit MUST be matched by an
   await, because an un-awaited request whose connection then drops is
   exactly the undefined outcome §8.5 forbids replaying. Dropping the
   response on the floor is how a caller loses track of that. */

/* Queues one request. Returns its seq, or 0 on failure. */
uint32_t uictl_submit(uictl_conn *c, uint16_t opcode, const void *payload,
                      size_t len, struct uictl_error *e);

/* Collects the oldest outstanding response. `seq_out` may be NULL. */
int uictl_await(uictl_conn *c, uint32_t *seq_out, struct uictl_error *e);

/* Submitted and not yet awaited, including any lost to a reconnect --
   so `while (uictl_outstanding(c)) uictl_await(c, NULL, &e);` drains
   both, dropped ones first. */
size_t uictl_outstanding(const uictl_conn *c);

/* ---- turning failures into text -------------------------------------
   The library never prints; these produce the strings a caller may
   choose to. All return static storage and never NULL. */

const char *uictl_strerror(const struct uictl_error *e);
const char *uictl_result_name(uint16_t result);
enum uictl_class uictl_result_class(uint16_t result);

/* One line of what to DO. Empty string where there is nothing useful to
   say, never a lie like "try again" for a terminal code. */
const char *uictl_result_hint(uint16_t result);

#ifdef __cplusplus
}
#endif

#endif /* UICTL_H */
