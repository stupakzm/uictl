/* libuictl — implementation. See uictl.h for the three rules this is
   built around: never print, never replay, always make a reconnect
   visible. */
#include "uictl.h"

#include "../proto.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define HDR_SIZE (sizeof(struct uictl_frame_header))

/* The public header declares the wire constants so a consumer does not
   have to install the daemon's proto.h. This is where the duplication
   stops being a duplication: every value is checked against the header
   the daemon compiles against, and a number that moves in one place and
   not the other fails the BUILD rather than shipping a library that
   speaks a slightly different protocol. */
#define SAME(pub, priv) _Static_assert((int)(pub) == (int)(priv), #pub " drifted from " #priv)
SAME(UICTL_OP_PING, OP_PING);
SAME(UICTL_OP_MOVE_ABS, OP_MOVE_ABS);
SAME(UICTL_OP_HELLO, OP_HELLO);
SAME(UICTL_OP_KEY_TAP, OP_KEY_TAP);
SAME(UICTL_OP_KEY_SEQUENCE, OP_KEY_SEQUENCE);
SAME(UICTL_OP_KEY_DOWN, OP_KEY_DOWN);
SAME(UICTL_OP_KEY_UP, OP_KEY_UP);
SAME(UICTL_OP_CONFIRM_SUBSCRIBE, OP_CONFIRM_SUBSCRIBE);
SAME(UICTL_OP_CONFIRM_REQUEST, OP_CONFIRM_REQUEST);
SAME(UICTL_OP_CONFIRM_DECIDE, OP_CONFIRM_DECIDE);
SAME(UICTL_OP_BUTTON, OP_BUTTON);
SAME(UICTL_OP_MOVE_REL, OP_MOVE_REL);
SAME(UICTL_OP_SCROLL, OP_SCROLL);
SAME(UICTL_OP_BATCH, OP_BATCH);
SAME(UICTL_RES_OK, OK);
SAME(UICTL_RES_VERSION, ERR_VERSION);
SAME(UICTL_RES_OPCODE_UNKNOWN, ERR_OPCODE_UNKNOWN);
SAME(UICTL_RES_PAYLOAD_INVALID, ERR_PAYLOAD_INVALID);
SAME(UICTL_RES_DENIED_BY_POLICY, ERR_DENIED_BY_POLICY);
SAME(UICTL_RES_TOO_LARGE, ERR_TOO_LARGE);
SAME(UICTL_RES_INTERNAL, ERR_INTERNAL);
SAME(UICTL_RES_BUSY, ERR_BUSY);
SAME(UICTL_RES_HANDSHAKE_REQUIRED, ERR_HANDSHAKE_REQUIRED);
SAME(UICTL_RES_KEY_DENYLISTED, ERR_KEY_DENYLISTED);
SAME(UICTL_RES_KEY_NOT_ALLOWED, ERR_KEY_NOT_ALLOWED);
SAME(UICTL_RES_RATE_LIMITED, ERR_RATE_LIMITED);
SAME(UICTL_RES_KEY_ALREADY_HELD, ERR_KEY_ALREADY_HELD);
SAME(UICTL_RES_KEY_HELD_BY_OTHER, ERR_KEY_HELD_BY_OTHER);
SAME(UICTL_RES_KEY_NOT_HELD, ERR_KEY_NOT_HELD);
SAME(UICTL_RES_TOO_MANY_HELD, ERR_TOO_MANY_HELD);
SAME(UICTL_RES_CONFIRM_UNAVAILABLE, ERR_CONFIRM_UNAVAILABLE);
SAME(UICTL_RES_CONFIRM_DENIED, ERR_CONFIRM_DENIED);
SAME(UICTL_RES_CONFIRM_TIMEOUT, ERR_CONFIRM_TIMEOUT);
SAME(UICTL_RES_NOT_CONFIRMER, ERR_NOT_CONFIRMER);
SAME(UICTL_CAP_POINTER_ABS, CAP_POINTER_ABS);
SAME(UICTL_CAP_KEYBOARD, CAP_KEYBOARD);
SAME(UICTL_CAP_POINTER_REL, CAP_POINTER_REL);
SAME(UICTL_CAP_BUTTONS, CAP_BUTTONS);
SAME(UICTL_SRC_CLI, SRC_CLI);
SAME(UICTL_SRC_HOTKEY, SRC_HOTKEY);
SAME(UICTL_SRC_LLM, SRC_LLM);
SAME(UICTL_RECONNECT_UNSPEC, RECONNECT_UNSPEC);
SAME(UICTL_RECONNECT_NEVER, RECONNECT_NEVER);
SAME(UICTL_RECONNECT_BACKOFF, RECONNECT_BACKOFF);
SAME(UICTL_NAME_MAX, UICTL_CLIENT_NAME_MAX);
SAME(UICTL_MAX_SEQ_STEPS, UICTL_SEQ_MAX);
SAME(UICTL_MAX_BATCH_STEPS, UICTL_BATCH_MAX);
#undef SAME


/* How many requests may be in flight at once. Not a protocol limit --
   the daemon dispatches up to 32 frames per epoll turn (WIRE.md §1.6)
   and does not track how many a client has outstanding -- but a bound
   here keeps the pending ring a fixed-size array in the connection
   rather than an allocation that grows under a caller's loop. 64 is two
   of the daemon's turns, which is already more than a round-trip-bound
   caller can profit from. */
#define UICTL_PIPELINE_MAX 64

struct uictl_conn {
  int fd; /* < 0 once the connection is dead. The only dead marker. */
  unsigned flags;
  char name[UICTL_CLIENT_NAME_MAX];
  uint32_t source_tag;
  uint32_t seq_next;

  struct uictl_resp_hello caps;
  int have_caps;

  uictl_state_cb cb;
  void *cb_user;

  /* Outstanding pipelined requests, oldest first. Responses arrive in
     request order (§2.7), so a ring of seqs is the whole bookkeeping:
     await() compares the head against what actually came back, and a
     mismatch is a daemon that misframed, not something to resynchronise
     from. */
  uint32_t pending[UICTL_PIPELINE_MAX];
  size_t pend_head;
  size_t pend_count;
  /* Requests that were in flight across a reconnect. They are not
     cancelled and not resent -- their outcome is UNDEFINED (§8.5) --
     so they stay countable until the caller drains them and each one
     comes back as UICTL_E_DROPPED. Dropping the count instead would let
     a caller mistake "never answered" for "nothing was pending". */
  size_t dropped;
};

/* ---- errors ---------------------------------------------------------- */

static int set_err(struct uictl_error *e, int err, int sys_errno,
                   uint16_t result) {
  if (e) {
    e->err = err;
    e->sys_errno = sys_errno;
    e->result = result;
  }
  return -1;
}

static void clear_err(struct uictl_error *e) {
  if (e) {
    e->err = UICTL_OK;
    e->sys_errno = 0;
    e->result = OK;
  }
}

/* The connection is gone. Close the fd, tell the caller (§8.8), and
   leave `pending` alone: those requests are not cancelled, they are
   *undefined*, and await() has to keep handing back UICTL_E_DROPPED for
   each one so a caller cannot mistake silence for success. */
static void conn_died(uictl_conn *c) {
  if (c->fd >= 0) {
    close(c->fd);
    c->fd = -1;
    if (c->cb)
      c->cb(c, 0, c->cb_user);
  }
}

/* ---- transport ------------------------------------------------------- */

static int dial(struct uictl_error *e) {
  const char *xdg = getenv("XDG_RUNTIME_DIR");
  if (!xdg)
    return set_err(e, UICTL_E_ENV, 0, OK);

  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  int n = snprintf(addr.sun_path, sizeof(addr.sun_path), "%s/uictld.sock",
                   xdg);
  if (n < 0 || (size_t)n >= sizeof(addr.sun_path))
    return set_err(e, UICTL_E_ENV, 0, OK);

  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0)
    return set_err(e, UICTL_E_SOCKET, errno, OK);

  if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    int saved = errno;
    close(fd);
    return set_err(e, UICTL_E_SOCKET, saved, OK);
  }
  return fd;
}

static int send_frame(uictl_conn *c, uint16_t opcode, uint32_t seq,
                      const void *payload, size_t len,
                      struct uictl_error *e) {
  if (len > UICTL_MAX_PAYLOAD)
    return set_err(e, UICTL_E_USAGE, 0, OK);

  char buf[HDR_SIZE + UICTL_MAX_PAYLOAD];
  struct uictl_frame_header h = {
      .version = c->have_caps ? c->caps.proto_selected : UICTL_PROTO_VERSION,
      .opcode = opcode,
      .source_tag = c->source_tag,
      .seq = seq,
      .payload_len = (uint32_t)len};
  encode_frame_header(&h, buf);
  if (len)
    memcpy(buf + HDR_SIZE, payload, len);

  if (write_full(c->fd, buf, HDR_SIZE + len) < 0) {
    int saved = errno;
    conn_died(c);
    return set_err(e, UICTL_E_IO, saved, OK);
  }
  return 0;
}

/* Read one response. Everything that returns -1 here also kills the
   connection, and that is deliberate: a frame we could not decode leaves
   the stream at an unknown offset, and reading on to "recover" only
   invites a hostile daemon to keep us there. The one-shot CLI already
   worked this way; a library must not pretend to do better. */
static int recv_frame(uictl_conn *c, uint16_t *opcode_out, uint32_t *seq_out,
                      uint16_t *result_out, void *data, size_t data_cap,
                      size_t *data_len_out, struct uictl_error *e) {
  char hdr_buf[HDR_SIZE];
  ssize_t r = read_full(c->fd, hdr_buf, sizeof(hdr_buf));
  if (r < 0) {
    int saved = errno;
    conn_died(c);
    return set_err(e, UICTL_E_IO, saved, OK);
  }
  if ((size_t)r != sizeof(hdr_buf)) {
    conn_died(c);
    return set_err(e, UICTL_E_IO, 0, OK); /* closed mid-header */
  }

  struct uictl_frame_header h;
  decode_frame_header(hdr_buf, &h);

  if (h.payload_len < UICTL_RESULT_SIZE || h.payload_len > UICTL_MAX_PAYLOAD) {
    conn_died(c);
    return set_err(e, UICTL_E_PROTO, 0, OK);
  }

  char result_buf[UICTL_RESULT_SIZE];
  r = read_full(c->fd, result_buf, sizeof(result_buf));
  if (r != (ssize_t)sizeof(result_buf)) {
    int saved = r < 0 ? errno : 0;
    conn_died(c);
    return set_err(e, UICTL_E_IO, saved, OK);
  }
  uint16_t result;
  memcpy(&result, result_buf, sizeof(result));

  size_t dlen = h.payload_len - UICTL_RESULT_SIZE;
  /* A response longer than the caller's buffer is not truncated and not
     skipped: §2.4's growth rule means a longer tail is *expected* from a
     newer daemon, but only for opcodes whose answer the caller asked
     for. Reading the excess into a scratch buffer keeps the stream
     aligned so the connection survives; silently discarding a tail the
     caller does not understand is precisely what the rule asks for. */
  size_t copy = dlen < data_cap ? dlen : data_cap;
  if (copy && data) {
    r = read_full(c->fd, data, copy);
    if (r != (ssize_t)copy) {
      int saved = r < 0 ? errno : 0;
      conn_died(c);
      return set_err(e, UICTL_E_IO, saved, OK);
    }
  }
  for (size_t left = dlen - copy; left > 0;) {
    char scratch[256];
    size_t want = left < sizeof(scratch) ? left : sizeof(scratch);
    r = read_full(c->fd, scratch, want);
    if (r != (ssize_t)want) {
      int saved = r < 0 ? errno : 0;
      conn_died(c);
      return set_err(e, UICTL_E_IO, saved, OK);
    }
    left -= want;
  }

  if (opcode_out)
    *opcode_out = h.opcode;
  if (seq_out)
    *seq_out = h.seq;
  if (result_out)
    *result_out = result;
  if (data_len_out)
    *data_len_out = copy;
  clear_err(e);
  return 0;
}

/* ---- handshake ------------------------------------------------------- */

int uictl_hello(uictl_conn *c, struct uictl_error *e) {
  if (!c)
    return set_err(e, UICTL_E_USAGE, 0, OK);
  if (c->fd < 0)
    return set_err(e, UICTL_E_DROPPED, 0, OK);
  if (c->pend_count)
    return set_err(e, UICTL_E_USAGE, 0, OK);

  struct uictl_payload_hello p;
  memset(&p, 0, sizeof(p));
  p.proto_min = UICTL_PROTO_MIN;
  p.proto_max = UICTL_PROTO_MAX;
  memcpy(p.client_name, c->name, sizeof(p.client_name));

  uint32_t seq = c->seq_next++;
  if (send_frame(c, OP_HELLO, seq, &p, sizeof(p), e) < 0)
    return -1;

  uint16_t opcode = 0, result = 0;
  uint32_t got_seq = 0;
  struct uictl_resp_hello caps;
  memset(&caps, 0, sizeof(caps));
  size_t dlen = 0;
  if (recv_frame(c, &opcode, &got_seq, &result, &caps, sizeof(caps), &dlen,
                 e) < 0)
    return -1;
  if (opcode != OP_HELLO || got_seq != seq) {
    conn_died(c);
    return set_err(e, UICTL_E_PROTO, 0, OK);
  }
  if (result != OK)
    return set_err(e, UICTL_E_REFUSED, 0, result);
  /* §3.4: accept any response of at least the 24-byte prefix and ignore
     a tail we do not understand. Demanding sizeof(caps) here would break
     the growth rule for the next field the daemon appends -- and the
     first field it appended, the §8.6 reconnect advice, is already past
     that prefix. */
  if (dlen < UICTL_RESP_HELLO_V1_SIZE) {
    conn_died(c);
    return set_err(e, UICTL_E_PROTO, 0, OK);
  }
  c->caps = caps;
  c->have_caps = 1;
  clear_err(e);
  return 0;
}

/* ---- lifecycle ------------------------------------------------------- */

uictl_conn *uictl_connect(const char *name, unsigned flags,
                          struct uictl_error *e) {
  if (!name || !*name) {
    set_err(e, UICTL_E_USAGE, 0, OK);
    return NULL;
  }
  char padded[UICTL_CLIENT_NAME_MAX];
  memset(padded, 0, sizeof(padded));
  size_t nlen = strlen(name);
  if (nlen >= sizeof(padded)) {
    set_err(e, UICTL_E_USAGE, 0, OK);
    return NULL;
  }
  memcpy(padded, name, nlen);
  /* Validated here, before a socket exists, using the same predicate the
     daemon uses -- shared through proto.h precisely so a client can
     refuse its own bad name locally instead of learning it from a round
     trip (§3.5). */
  if (!uictl_client_name_valid(padded)) {
    set_err(e, UICTL_E_USAGE, 0, OK);
    return NULL;
  }

  uictl_conn *c = calloc(1, sizeof(*c));
  if (!c) {
    set_err(e, UICTL_E_SOCKET, ENOMEM, OK);
    return NULL;
  }
  memcpy(c->name, padded, sizeof(c->name));
  c->source_tag = SRC_CLI;
  c->seq_next = 1;
  c->flags = flags;

  int fd = dial(e);
  if (fd < 0) {
    free(c);
    return NULL;
  }
  c->fd = fd;
  /* No "up" callback here: the callback cannot have been registered yet
     -- this function is what returns the handle to register it on. The
     first connection's success IS this function's return value; the
     callback exists for the transitions a caller cannot see (§8.8). */

  if (!(flags & UICTL_NO_HELLO) && uictl_hello(c, e) < 0) {
    uictl_close(c);
    return NULL;
  }
  clear_err(e);
  return c;
}

void uictl_close(uictl_conn *c) {
  if (!c)
    return;
  if (c->fd >= 0) {
    close(c->fd);
    c->fd = -1;
  }
  /* The name is not secret, but the connection is the thing a caller
     might keep a stale pointer to; zeroing makes a use-after-free look
     like a use-after-free rather than a working connection. */
  explicit_bzero(c, sizeof(*c));
  free(c);
}

int uictl_fd(const uictl_conn *c) { return c ? c->fd : -1; }

void uictl_on_state(uictl_conn *c, uictl_state_cb cb, void *user) {
  if (!c)
    return;
  c->cb = cb;
  c->cb_user = user;
}

void uictl_set_source_tag(uictl_conn *c, uint32_t tag) {
  if (c)
    c->source_tag = tag;
}

int uictl_reconnect(uictl_conn *c, struct uictl_error *e) {
  if (!c)
    return set_err(e, UICTL_E_USAGE, 0, OK);

  conn_died(c);
  /* Everything in flight is discarded here rather than resent. §8.5:
     the outcome of a request whose response never arrived is UNDEFINED,
     and a replayed KEY_DOWN is a keypress the user did not ask for. The
     count is cleared because there is nobody left to answer for them --
     a caller that still holds seqs learns from this return value that
     they are gone. */
  c->dropped += c->pend_count;
  c->pend_head = 0;
  c->pend_count = 0;
  c->have_caps = 0;
  memset(&c->caps, 0, sizeof(c->caps));

  int fd = dial(e);
  if (fd < 0)
    return -1;
  c->fd = fd;
  if (c->cb)
    c->cb(c, 1, c->cb_user);

  if (!(c->flags & UICTL_NO_HELLO) && uictl_hello(c, e) < 0)
    return -1;
  clear_err(e);
  return 0;
}

/* ---- capability accessors -------------------------------------------- */

void uictl_proto_range(uint16_t *min, uint16_t *max) {
  if (min)
    *min = UICTL_PROTO_MIN;
  if (max)
    *max = UICTL_PROTO_MAX;
}

uint16_t uictl_proto_selected(const uictl_conn *c) {
  return c && c->have_caps ? c->caps.proto_selected : 0;
}
uint16_t uictl_device_caps(const uictl_conn *c) {
  return c && c->have_caps ? c->caps.device_caps : 0;
}
uint32_t uictl_abs_range_max(const uictl_conn *c) {
  return c && c->have_caps ? c->caps.abs_range_max : 0;
}
uint32_t uictl_daemon_version(const uictl_conn *c) {
  return c && c->have_caps ? c->caps.daemon_version : 0;
}

int uictl_has_op(const uictl_conn *c, uint16_t opcode) {
  if (!c || !c->have_caps || opcode >= 64)
    return 0;
  return (c->caps.opcode_bitmap & UICTL_OP_BIT(opcode)) != 0;
}

void uictl_reconnect_advice(const uictl_conn *c, uint8_t *mode,
                            uint16_t *base_ms, uint8_t *max_tries) {
  uint8_t m = RECONNECT_UNSPEC, t = 0;
  uint16_t b = 0;
  if (c && c->have_caps) {
    m = c->caps.reconnect_mode;
    b = c->caps.reconnect_base_ms;
    t = c->caps.reconnect_max_tries;
  }
  if (mode)
    *mode = m;
  if (base_ms)
    *base_ms = b;
  if (max_tries)
    *max_tries = t;
}

/* ---- pipelining ------------------------------------------------------ */

uint32_t uictl_submit(uictl_conn *c, uint16_t opcode, const void *payload,
                      size_t len, struct uictl_error *e) {
  if (!c) {
    set_err(e, UICTL_E_USAGE, 0, OK);
    return 0;
  }
  if (c->fd < 0) {
    set_err(e, UICTL_E_DROPPED, 0, OK);
    return 0;
  }
  if (c->pend_count >= UICTL_PIPELINE_MAX) {
    set_err(e, UICTL_E_USAGE, 0, OK);
    return 0;
  }
  /* The capability map is the contract (§2.2). Refusing locally saves a
     round trip AND a rate-limit charge -- the daemon charges before it
     validates, so a client that guesses at opcodes pays for the guess. */
  if (c->have_caps && !uictl_has_op(c, opcode)) {
    set_err(e, UICTL_E_NOTSUP, 0, OK);
    return 0;
  }

  uint32_t seq = c->seq_next++;
  if (c->seq_next == 0)
    c->seq_next = 1; /* 0 is unremarkable on the wire, but reserving it
                        lets this function report failure as 0 */
  if (send_frame(c, opcode, seq, payload, len, e) < 0)
    return 0;

  c->pending[(c->pend_head + c->pend_count) % UICTL_PIPELINE_MAX] = seq;
  c->pend_count++;
  clear_err(e);
  return seq;
}

int uictl_await(uictl_conn *c, uint32_t *seq_out, struct uictl_error *e) {
  if (!c)
    return set_err(e, UICTL_E_USAGE, 0, OK);
  /* Drained before anything new, because they are older. A caller that
     loops `while (uictl_outstanding(c)) uictl_await(...)` after a
     reconnect gets one UICTL_E_DROPPED per lost request and then its
     real answers, in order. */
  if (c->dropped) {
    c->dropped--;
    if (seq_out)
      *seq_out = 0; /* the seq is meaningless now; nothing will answer it */
    return set_err(e, UICTL_E_DROPPED, 0, OK);
  }
  if (c->pend_count == 0)
    return set_err(e, UICTL_E_USAGE, 0, OK);

  uint32_t want = c->pending[c->pend_head];
  c->pend_head = (c->pend_head + 1) % UICTL_PIPELINE_MAX;
  c->pend_count--;
  if (seq_out)
    *seq_out = want;

  /* The connection died while this was in flight. Not an I/O error to
     retry -- an UNDEFINED outcome (§8.5). The caller is told exactly
     that, and the library will not resend it. */
  if (c->fd < 0)
    return set_err(e, UICTL_E_DROPPED, 0, OK);

  uint16_t result = 0;
  uint32_t got = 0;
  if (recv_frame(c, NULL, &got, &result, NULL, 0, NULL, e) < 0)
    return -1;
  if (got != want) {
    /* Responses are in request order (§2.7). Out of order means the
       daemon misframed or something else is reading this socket, and
       neither is recoverable by reading further. */
    conn_died(c);
    return set_err(e, UICTL_E_PROTO, 0, OK);
  }
  if (result != OK)
    return set_err(e, UICTL_E_REFUSED, 0, result);
  clear_err(e);
  return 0;
}

size_t uictl_outstanding(const uictl_conn *c) {
  return c ? c->pend_count + c->dropped : 0;
}

/* One request, one response, no pipeline. Refuses to run while requests
   are outstanding rather than quietly stealing someone else's response:
   the two styles share one stream and mixing them silently would hand a
   caller the wrong answer to the right seq. */
static int request(uictl_conn *c, uint16_t opcode, const void *payload,
                   size_t len, struct uictl_error *e) {
  if (!c)
    return set_err(e, UICTL_E_USAGE, 0, OK);
  if (c->pend_count)
    return set_err(e, UICTL_E_USAGE, 0, OK);
  if (uictl_submit(c, opcode, payload, len, e) == 0)
    return -1;
  return uictl_await(c, NULL, e);
}

/* ---- one call per opcode --------------------------------------------- */

int uictl_ping(uictl_conn *c, struct uictl_error *e) {
  return request(c, OP_PING, NULL, 0, e);
}

int uictl_move_abs(uictl_conn *c, int32_t x, int32_t y,
                   struct uictl_error *e) {
  struct uictl_payload_move_abs p = {.x = x, .y = y};
  return request(c, OP_MOVE_ABS, &p, sizeof(p), e);
}

int uictl_move_rel(uictl_conn *c, int32_t dx, int32_t dy,
                   struct uictl_error *e) {
  struct uictl_payload_move_rel p = {.dx = dx, .dy = dy};
  return request(c, OP_MOVE_REL, &p, sizeof(p), e);
}

int uictl_scroll(uictl_conn *c, int32_t notches_v, int32_t notches_h,
                 struct uictl_error *e) {
  struct uictl_payload_scroll p = {.notches_v = notches_v,
                                   .notches_h = notches_h};
  return request(c, OP_SCROLL, &p, sizeof(p), e);
}

int uictl_button(uictl_conn *c, uint16_t code, int down,
                 struct uictl_error *e) {
  struct uictl_payload_button p = {
      .code = code, .down = down ? 1u : 0u, .reserved = 0};
  return request(c, OP_BUTTON, &p, sizeof(p), e);
}

static int key_op(uictl_conn *c, uint16_t opcode, uint16_t keycode,
                  struct uictl_error *e) {
  struct uictl_payload_key p = {.keycode = keycode};
  return request(c, opcode, &p, sizeof(p), e);
}

int uictl_key_tap(uictl_conn *c, uint16_t keycode, struct uictl_error *e) {
  return key_op(c, OP_KEY_TAP, keycode, e);
}
int uictl_key_down(uictl_conn *c, uint16_t keycode, struct uictl_error *e) {
  return key_op(c, OP_KEY_DOWN, keycode, e);
}
int uictl_key_up(uictl_conn *c, uint16_t keycode, struct uictl_error *e) {
  return key_op(c, OP_KEY_UP, keycode, e);
}

int uictl_key_sequence(uictl_conn *c, const struct uictl_key_step *steps,
                       size_t n, struct uictl_error *e) {
  if (!steps || n == 0 || n > UICTL_SEQ_MAX)
    return set_err(e, UICTL_E_USAGE, 0, OK);

  /* Self-balance checked locally (§5B.2). The daemon checks it too and
     is the authority, but it charges the rate limit BEFORE it validates
     -- so an unbalanced sequence caught here costs a caller nothing,
     and the same one caught there costs it budget it may need to
     release a key with. Tracked per key rather than counted, because
     down,down,up,up sums to zero and is still wrong. */
  /* A stack of what is currently held, not a bitset indexed by keycode.
     A bitset would need the keycode ceiling, which lives in
     src/platform/uinput.h -- the HAL header the library must not reach
     into, and whose value (767) is the daemon's business to enforce
     anyway. At UICTL_SEQ_MAX = 16 items the quadratic scan is free, and
     the library keeps knowing nothing about the kernel. Range-checking
     the keycode stays with the daemon, which owns the device. */
  uint16_t held[UICTL_SEQ_MAX];
  size_t nheld = 0;
  for (size_t i = 0; i < n; i++) {
    if (steps[i].value > 1 || steps[i].keycode == 0)
      return set_err(e, UICTL_E_USAGE, 0, OK);
    size_t at = nheld;
    for (size_t j = 0; j < nheld; j++)
      if (held[j] == steps[i].keycode) {
        at = j;
        break;
      }
    if (steps[i].value == 1) {
      if (at != nheld) /* already down: down,down is not balance */
        return set_err(e, UICTL_E_USAGE, 0, OK);
      held[nheld++] = steps[i].keycode;
    } else {
      if (at == nheld) /* up for something never pressed here */
        return set_err(e, UICTL_E_USAGE, 0, OK);
      held[at] = held[--nheld];
    }
  }
  if (nheld != 0) /* a press with no release inside this request */
    return set_err(e, UICTL_E_USAGE, 0, OK);

  char buf[sizeof(struct uictl_payload_key_seq) +
           UICTL_SEQ_MAX * sizeof(struct uictl_seq_item)];
  struct uictl_payload_key_seq hdr = {.count = (uint16_t)n, .reserved = 0};
  memcpy(buf, &hdr, sizeof(hdr));
  for (size_t i = 0; i < n; i++) {
    struct uictl_seq_item it = {.keycode = steps[i].keycode,
                                .value = steps[i].value,
                                .reserved = 0};
    memcpy(buf + sizeof(hdr) + i * sizeof(it), &it, sizeof(it));
  }
  return request(c, OP_KEY_SEQUENCE, buf, uictl_seq_payload_len((uint16_t)n),
                 e);
}

int uictl_batch(uictl_conn *c, const struct uictl_batch_step *steps, size_t n,
                struct uictl_error *e) {
  if (!steps || n == 0 || n > UICTL_BATCH_MAX)
    return set_err(e, UICTL_E_USAGE, 0, OK);

  char buf[sizeof(struct uictl_payload_batch) +
           UICTL_BATCH_MAX * sizeof(struct uictl_batch_item)];
  struct uictl_payload_batch hdr = {.count = (uint16_t)n, .reserved = 0};
  memcpy(buf, &hdr, sizeof(hdr));
  for (size_t i = 0; i < n; i++) {
    switch (steps[i].opcode) {
    case OP_MOVE_ABS:
    case OP_MOVE_REL:
    case OP_SCROLL:
    case OP_BUTTON:
    case OP_KEY_DOWN:
    case OP_KEY_UP:
      break;
    default:
      /* Caught here rather than sent: an opcode a batch cannot carry is
         a caller bug, and the daemon's answer would be an all-or-nothing
         refusal that says nothing about which item was wrong. */
      return set_err(e, UICTL_E_USAGE, 0, OK);
    }
    struct uictl_batch_item it = {.opcode = steps[i].opcode,
                                  .reserved = 0,
                                  .a = steps[i].a,
                                  .b = steps[i].b};
    memcpy(buf + sizeof(hdr) + i * sizeof(it), &it, sizeof(it));
  }
  return request(c, OP_BATCH, buf, uictl_batch_payload_len((uint16_t)n), e);
}

/* ---- text ------------------------------------------------------------ */

const char *uictl_result_name(uint16_t result) {
  switch (result) {
  case OK: return "OK";
  case ERR_VERSION: return "ERR_VERSION";
  case ERR_OPCODE_UNKNOWN: return "ERR_OPCODE_UNKNOWN";
  case ERR_PAYLOAD_INVALID: return "ERR_PAYLOAD_INVALID";
  case ERR_DENIED_BY_POLICY: return "ERR_DENIED_BY_POLICY";
  case ERR_TOO_LARGE: return "ERR_TOO_LARGE";
  case ERR_INTERNAL: return "ERR_INTERNAL";
  case ERR_BUSY: return "ERR_BUSY";
  case ERR_HANDSHAKE_REQUIRED: return "ERR_HANDSHAKE_REQUIRED";
  case ERR_KEY_DENYLISTED: return "ERR_KEY_DENYLISTED";
  case ERR_KEY_NOT_ALLOWED: return "ERR_KEY_NOT_ALLOWED";
  case ERR_RATE_LIMITED: return "ERR_RATE_LIMITED";
  case ERR_KEY_ALREADY_HELD: return "ERR_KEY_ALREADY_HELD";
  case ERR_KEY_HELD_BY_OTHER: return "ERR_KEY_HELD_BY_OTHER";
  case ERR_KEY_NOT_HELD: return "ERR_KEY_NOT_HELD";
  case ERR_TOO_MANY_HELD: return "ERR_TOO_MANY_HELD";
  case ERR_CONFIRM_UNAVAILABLE: return "ERR_CONFIRM_UNAVAILABLE";
  case ERR_CONFIRM_DENIED: return "ERR_CONFIRM_DENIED";
  case ERR_CONFIRM_TIMEOUT: return "ERR_CONFIRM_TIMEOUT";
  case ERR_NOT_CONFIRMER: return "ERR_NOT_CONFIRMER";
  default: return "unknown result";
  }
}

/* WIRE.md §4.2, transcribed. A caller switching on this keeps working
   when a code is appended; one switching on individual codes does not. */
enum uictl_class uictl_result_class(uint16_t result) {
  switch (result) {
  case OK:
    return UICTL_CLASS_OK;
  case ERR_BUSY:
  case ERR_RATE_LIMITED:
  case ERR_KEY_HELD_BY_OTHER:
  case ERR_CONFIRM_TIMEOUT:
    return UICTL_CLASS_RETRYABLE;
  case ERR_KEY_NOT_ALLOWED:
  case ERR_CONFIRM_UNAVAILABLE:
    return UICTL_CLASS_FIXABLE;
  case ERR_KEY_ALREADY_HELD:
  case ERR_KEY_NOT_HELD:
  case ERR_TOO_MANY_HELD:
    return UICTL_CLASS_CLIENT_BUG;
  case ERR_HANDSHAKE_REQUIRED:
    return UICTL_CLASS_CORRECTABLE;
  default:
    /* Terminal is the safe default for a code this build has never
       heard of: it makes an unknown refusal stop, where guessing
       "retryable" would make it into a loop. */
    return UICTL_CLASS_TERMINAL;
  }
}

const char *uictl_result_hint(uint16_t result) {
  switch (result) {
  case ERR_KEY_NOT_ALLOWED:
    return "add the keycode to ~/.config/uictl/policy and restart uictld";
  case ERR_KEY_DENYLISTED:
    return "this key is refused by the daemon and no configuration "
           "changes that";
  case ERR_CONFIRM_UNAVAILABLE:
    return "no confirmer is connected; run uictl-confirm";
  case ERR_CONFIRM_DENIED:
    return "a person refused this request";
  case ERR_CONFIRM_TIMEOUT:
    return "nobody answered; assume the user is away from the keyboard";
  case ERR_HANDSHAKE_REQUIRED:
    return "call uictl_hello() on this connection, then retry";
  case ERR_RATE_LIMITED:
    return "slow down; this is a pacing problem, not a retry problem";
  case ERR_BUSY:
    return "the daemon is momentarily full; retry shortly";
  case ERR_KEY_HELD_BY_OTHER:
    return "another connection is mid-gesture; back off";
  case ERR_KEY_ALREADY_HELD:
  case ERR_KEY_NOT_HELD:
  case ERR_TOO_MANY_HELD:
    return "reconcile your own held set before retrying";
  case ERR_DENIED_BY_POLICY:
    return "the daemon serves only its own uid";
  default:
    return "";
  }
}

const char *uictl_strerror(const struct uictl_error *e) {
  if (!e)
    return "no error";
  switch (e->err) {
  case UICTL_OK:
    return "ok";
  case UICTL_E_ENV:
    return "XDG_RUNTIME_DIR is not set, or the socket path does not fit";
  case UICTL_E_SOCKET:
    return "cannot reach uictld";
  case UICTL_E_IO:
    return "the connection to uictld failed";
  case UICTL_E_PROTO:
    return "uictld sent a frame this build cannot decode";
  case UICTL_E_REFUSED:
    return uictl_result_name(e->result);
  case UICTL_E_DROPPED:
    return "the request was not sent, or its outcome is undefined "
           "(WIRE.md 8.5)";
  case UICTL_E_USAGE:
    return "invalid argument";
  case UICTL_E_NOTSUP:
    return "this daemon does not implement that opcode";
  default:
    return "unknown error";
  }
}
