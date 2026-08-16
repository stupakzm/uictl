#include "platform/uinput.h"
#include "proto.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h> /* explicit_bzero */
#include <sys/epoll.h>
#include <sys/file.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

/* (the M1 `static volatile sig_atomic_t stop` died with signalfd — the
   loop's own local `stop` is the only one now) */

static const char *opname(uint16_t op) {
  switch (op) {
  case OP_PING:
    return "PING";
  case OP_MOVE_ABS:
    return "MOVE_ABS";
  case OP_HELLO:
    return "HELLO";
  default:
    return "UNKNOWN";
  }
}

static int prepare_state_dir(char *out, size_t outlen) {
  const char *home = getenv("HOME");
  if (!home) {
    fprintf(stderr, "uictld: HOME not set\n");
    return -1;
  }
  int n = snprintf(out, outlen, "%s/.local/state/uictl", home);
  if (n < 0 || (size_t)n >= outlen) {
    fprintf(stderr, "uictld: state dir path too long\n");
    return -1;
  }
  if (mkdir(out, 0700) < 0 && errno != EEXIST) {
    perror("uictld: mkdir state dir");
    return -1;
  }
  struct stat st;
  if (stat(out, &st) < 0) {
    perror("uictld: stat state dir");
    return -1;
  }
  if (st.st_uid != getuid()) {
    fprintf(stderr, "uictld: state dir not owned by current uid\n");
    return -1;
  }
  if (st.st_mode & 0077) {
    fprintf(stderr, "uictld: state dir has group/world bits\n");
    return -1;
  }
  return 0;
}

static int open_audit_log(const char *state_dir) {
  char path[256];
  int n = snprintf(path, sizeof(path), "%s/audit.log", state_dir);
  if (n < 0 || (size_t)n >= sizeof(path)) {
    fprintf(stderr, "uictld: audit log path too long\n");
    return -1;
  }
  int fd = open(path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0600);
  if (fd < 0) {
    perror("uictld: open audit.log");
    return -1;
  }
  struct stat st;
  if (fstat(fd, &st) < 0) {
    perror("uictld: fstat audit.log");
    close(fd);
    return -1;
  }
  if (st.st_uid != getuid()) {
    fprintf(stderr, "uictld: audit.log not owned by current uid\n");
    close(fd);
    return -1;
  }
  if (st.st_mode & 0077) {
    fprintf(stderr, "uictld: audit.log has group/world bits\n");
    close(fd);
    return -1;
  }
  return fd;
}

/* ---- client identity (M3.6 task 5) ----------------------------------
   Two halves, and keeping them straight is the whole point:

     pid   — from SO_PEERCRED, filled in by the kernel, unforgeable.
             Already the basis of the per-pid connection cap, and it is
             what a future rate-limit bucket must key on.
     name  — from HELLO, self-asserted, a label. It selects a *class*
             from a local registry the user writes.

   A name is not a credential and never becomes one. What makes the
   scheme worth having is the direction of the default: an unregistered
   name gets the most restrictive class, so asserting a name can only
   ever *raise* privilege by an explicit decision the user already wrote
   down, and asserting nothing (or lying) leaves you at the floor. That
   is strictly better than `source_tag`, where a client picks its own
   tier per frame (G2).

   What this does NOT defend against: every peer is the same uid
   (invariant 9), so a hostile local process can claim "muvor" and get
   muvor's class — it could equally just run the real muvor binary. If
   classes ever need to differ in *trust* rather than in blast radius,
   the answer is option C from the M3.6 notes (per-class socket paths,
   authenticated by filesystem permissions), not a stricter name check. */
enum client_class {
  /* 0 is the floor on purpose: a zeroed struct conn is untrusted, so
     forgetting to assign a class fails closed rather than open. */
  CLASS_UNTRUSTED = 0,
  CLASS_STANDARD,
  CLASS_INTERACTIVE,
  CLASS__COUNT
};

static const char *class_name(enum client_class cl) {
  switch (cl) {
  case CLASS_STANDARD:
    return "standard";
  case CLASS_INTERACTIVE:
    return "interactive";
  case CLASS_UNTRUSTED:
  default:
    return "untrusted";
  }
}

static int class_from_word(const char *word, enum client_class *out) {
  for (enum client_class cl = 0; cl < CLASS__COUNT; cl++) {
    if (strcmp(word, class_name(cl)) == 0) {
      *out = cl;
      return 0;
    }
  }
  return -1;
}

#define MAX_REGISTERED_CLIENTS 16
#define REGISTRY_MAX_BYTES 4096

struct client_reg {
  char name[UICTL_CLIENT_NAME_MAX];
  enum client_class cl;
};

static struct client_reg registry[MAX_REGISTERED_CLIENTS];
static int registry_len;

/* Read ~/.config/uictl/clients once at startup: one `name class` pair
   per line, `#` comments, blanks ignored.

   Startup and not per-HELLO, deliberately. Re-reading per request would
   put file I/O in the request path and make a client's class depend on
   whatever the file said at that instant — a config edit would take
   effect halfway through a session, for some connections and not
   others. Loaded once, the daemon's policy is whatever it started with,
   which is also what the audit log then means. A reload belongs on
   SIGHUP if it is ever wanted.

   Same ownership posture as the audit log (security rule 4): the file
   decides who gets elevated, so another user being able to write it
   would be the whole game. */
static void load_client_registry(void) {
  const char *home = getenv("HOME");
  if (!home)
    return;

  char path[256];
  int n = snprintf(path, sizeof(path), "%s/.config/uictl/clients", home);
  if (n < 0 || (size_t)n >= sizeof(path))
    return;

  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    if (errno != ENOENT)
      perror("uictld: open client registry");
    fprintf(stderr,
            "uictld: no client registry at %s — every client is '%s'\n", path,
            class_name(CLASS_UNTRUSTED));
    return;
  }

  struct stat st;
  if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) || st.st_uid != getuid() ||
      (st.st_mode & 0077)) {
    fprintf(stderr, "uictld: %s must be a regular file owned by this uid "
                    "with no group/world bits — ignoring it\n",
            path);
    close(fd);
    return;
  }

  char buf[REGISTRY_MAX_BYTES + 1];
  ssize_t got = read_full(fd, buf, REGISTRY_MAX_BYTES);
  close(fd);
  if (got < 0) {
    perror("uictld: read client registry");
    return;
  }
  buf[got] = '\0';

  /* Split lines by hand rather than with strtok_r: strtok collapses
     runs of delimiters, so two consecutive newlines are one separator
     and every blank line silently shifts the reported line number. A
     config error that points at the wrong line is worse than no line
     number at all. */
  int line_no = 0;
  for (char *p = buf; *p;) {
    char *line = p;
    char *eol = strchr(p, '\n');
    if (eol) {
      *eol = '\0';
      p = eol + 1;
    } else {
      p += strlen(p);
    }
    line_no++;

    char *hash = strchr(line, '#');
    if (hash)
      *hash = '\0';

    char *fsave = NULL;
    const char *name = strtok_r(line, " \t\r", &fsave);
    if (!name)
      continue; /* blank or comment-only */
    const char *word = strtok_r(NULL, " \t\r", &fsave);

    if (registry_len == MAX_REGISTERED_CLIENTS) {
      fprintf(stderr, "uictld: client registry line %d: more than %d entries, "
                      "ignoring the rest\n",
              line_no, MAX_REGISTERED_CLIENTS);
      break;
    }

    struct client_reg entry;
    memset(&entry, 0, sizeof(entry));
    size_t len = strlen(name);
    if (len >= sizeof(entry.name)) {
      fprintf(stderr, "uictld: client registry line %d: name too long\n",
              line_no);
      continue;
    }
    memcpy(entry.name, name, len);
    /* Same validation the wire gets. A registry entry that could never
       match a legal HELLO name is a typo, and saying so at startup beats
       silently never matching. */
    if (!uictl_client_name_valid(entry.name)) {
      fprintf(stderr, "uictld: client registry line %d: invalid name\n",
              line_no);
      continue;
    }
    if (!word || class_from_word(word, &entry.cl) < 0) {
      fprintf(stderr,
              "uictld: client registry line %d: expected 'NAME CLASS' with "
              "CLASS one of untrusted|standard|interactive\n",
              line_no);
      continue;
    }
    registry[registry_len++] = entry;
    fprintf(stderr, "uictld: client '%s' registered as '%s'\n", entry.name,
            class_name(entry.cl));
  }
}

/* Unregistered name -> the floor. Default-deny, same posture M4's
   keyboard allowlist will take. */
static enum client_class class_for_name(const char *name) {
  for (int i = 0; i < registry_len; i++)
    if (strcmp(registry[i].name, name) == 0)
      return registry[i].cl;
  return CLASS_UNTRUSTED;
}

static void audit_log(int fd, pid_t peer_pid, uid_t peer_uid, uint32_t src,
                      uint16_t op, uint32_t seq, uint16_t result,
                      const char *args) {
  struct timespec now;
  clock_gettime(CLOCK_REALTIME, &now);
  struct tm tm;
  gmtime_r(&now.tv_sec, &tm);
  char ts[32];
  strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tm);

  char line[512];
  int n = snprintf(line, sizeof(line),
                   "%s pid=%d uid=%u src=0x%x op=%s seq=%u result=%u args=%s\n",
                   ts, (int)peer_pid, (unsigned)peer_uid, src, opname(op), seq,
                   result, args ? args : "");
  if (n < 0)
    return;
  if ((size_t)n >= sizeof(line))
    n = (int)sizeof(line) - 1;
  (void)write(fd, line, (size_t)n);
}

/* ---- connection objects (M3.5) --------------------------------------
   A connection is no longer a function call inside the accept branch;
   it is an object registered in the epoll set with its own parse state.
   The daemon must never block on a client: a peer that sends 3 bytes of
   a 16-byte header and then sleeps used to park the whole daemon inside
   read_full().                                                          */

#define MAX_CONNS 32
#define HDR_SIZE (sizeof(struct uictl_frame_header))
#define CONN_BUF_SIZE UICTL_MAX_PAYLOAD /* header phase reuses this buffer */
#define CONN_OUT_SIZE (HDR_SIZE + UICTL_MAX_PAYLOAD)

/* How long a *half-delivered frame* may sit before the connection is
   reaped, and how often the reaper scans. The effective deadline is
   therefore 5–6 s, not exactly 5 — a frame that goes quiet just after a
   tick waits nearly a full extra tick for the next one. Do not tighten
   the tick to hide that; a coarse periodic scan is the point. */
#define CONN_PARTIAL_TIMEOUT_SEC 5
#define REAPER_TICK_SEC 1

/* ---- admission + fairness (M3.7) ------------------------------------
   How many frames one connection may have dispatched for it in a single
   epoll_wait turn (G6), and how many concurrent connections one peer pid
   may hold (G7).

   The budget is not a rate limit — it does not slow anyone down over
   time. It only bounds how long one connection can own the loop before
   the others are looked at: 32 frames is one uinput write and one audit
   write apiece, microseconds, while an unbounded drain of a 1000-frame
   pipeline is milliseconds and blows muvor's sub-50 ms budget.

   4 connections per pid is generous for every profile we know: the CLI
   opens one and exits, muvor and auto-c hold one long-lived each. It
   exists so a buggy or hostile peer cannot take all 32 slots. */
#define CONN_FRAMES_PER_TURN 32
#define MAX_CONNS_PER_PID 4

enum conn_phase { CONN_WANT_HEADER, CONN_WANT_PAYLOAD };

/* ---- epoll event keys ------------------------------------------------
   `epoll_event.data` is a union and the obvious choice, `.fd`, is a trap
   here. fd numbers are recycled: the kernel hands out the lowest free
   one, so the instant conn_close() closes fd 9, the very next accept4()
   in the SAME epoll_wait batch can be handed 9 again. A later event in
   that batch still says "fd 9" and would resolve to the brand-new
   connection — delivering a dead peer's EPOLLHUP, or an EPOLLIN, to a
   client that just connected.

   So an event key names the connection *object*, not its fd:

     bits 63..32  generation — 0 for the three static fds, >= 1 for conns
     bits 31..0   the fd for static sources, the conns[] slot for clients

   The generation is bumped on every conn_alloc, so a stale event for a
   reused slot fails the match and is dropped. Generation 0 is reserved
   for the static sources, which is what makes one decode cover both
   kinds without a separate tag field. Wraparound needs 2^32 accepts
   between two events of one batch — not reachable. */
#define EVKEY_STATIC(fd) ((uint64_t)(uint32_t)(fd))
#define EVKEY_CONN(slot, gen) (((uint64_t)(gen) << 32) | (uint32_t)(slot))
#define EVKEY_GEN(u) ((uint32_t)((u) >> 32))
#define EVKEY_LOW(u) ((uint32_t)((u) & 0xffffffffu))

struct conn {
  int fd;            /* < 0 => slot free. the ONLY free marker.        */
  struct ucred cred; /* captured once at accept; never re-read.        */

  /* --- read side --- invariant: have <= want <= sizeof(buf) --------- */
  enum conn_phase phase;
  size_t want;                   /* bytes this phase still needs total */
  size_t have;                   /* bytes currently in buf             */
  struct uictl_frame_header hdr; /* valid only in CONN_WANT_PAYLOAD    */
  char buf[CONN_BUF_SIZE];

  /* --- write side --- invariant: out_sent <= out_len <= sizeof(out).
     A response is pending iff out_sent < out_len. There is exactly ONE
     out buffer, so while a response is pending the connection must not
     parse another frame — the next reply would overwrite the one still
     going out. That is enforced by dropping EPOLLIN, see
     conn_update_events. --------------------------------------------- */
  char out[CONN_OUT_SIZE];
  size_t out_len;
  size_t out_sent;
  int close_after_flush; /* fatal frame: finish the reply, then close  */
  time_t out_since;      /* mono secs when the response first stalled  */

  /* What this fd is currently registered for in the epoll set. Cached so
     conn_update_events can skip a redundant EPOLL_CTL_MOD syscall on the
     common path where nothing changed. */
  uint32_t events;

  /* Bumped every time this slot is handed to a new peer. Makes a stale
     epoll event for a previous occupant identifiable. */
  uint32_t generation;

  /* CLOCK_MONOTONIC seconds when the current frame's first byte
     arrived. Valid only while a frame is in progress, i.e.
     (have > 0 || phase == CONN_WANT_PAYLOAD). Read by the M3.5 task 6
     reaper; nothing consumes it yet. */
  time_t frame_since;

  /* --- handshake state (M3.6 task 2) -------------------------------
     Set once by OP_HELLO and never again on this connection — see the
     duplicate-HELLO refusal in conn_handle_frame. Scoped to the
     connection, not the pid: two connections from one process may
     legitimately be different consumers of a future client library, and
     a pid is not an identity anyway (they recycle).

     proto_min/proto_max are recorded but not yet acted on; task 4 turns
     the header's version-equality check into a range intersection. */
  int hello_seen;
  uint16_t proto_min;
  uint16_t proto_max;
  /* 0 until a HELLO succeeds. Once set, every later frame on this
     connection must carry exactly this version — see conn_version_ok. */
  uint16_t proto_selected;
  char client_name[UICTL_CLIENT_NAME_MAX];
  /* Derived by the daemon, never sent by the peer. Starts at the floor
     at accept and is only ever raised by a successful HELLO whose name
     the local registry lists. M4's rate limiter reads this; it must
     never read source_tag. */
  enum client_class cl;

  /* Operator introspection only (M3.7 task 4 / SIGUSR1). Deliberately
     not policy inputs: a rate limit keyed on frames_served would be a
     policy decision made below the identity layer, which is the mistake
     G2 is about. accepted_at is CLOCK_MONOTONIC seconds. */
  time_t accepted_at;
  uint64_t frames_served;
};

static struct conn conns[MAX_CONNS];

static time_t mono_secs(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0)
    return 0;
  return ts.tv_sec;
}

static void conn_table_init(void) {
  for (int i = 0; i < MAX_CONNS; i++)
    conns[i].fd = -1;
}

/* Monotonic, never reset, never 0 for a live connection — see
   EVKEY_CONN. Starts at 1 so the first allocation is distinguishable
   from the zero-initialised `generation` of an untouched slot. */
static uint32_t conn_generation_next = 1;

static struct conn *conn_alloc(int fd, const struct ucred *cred) {
  for (int i = 0; i < MAX_CONNS; i++) {
    if (conns[i].fd >= 0)
      continue;
    struct conn *c = &conns[i];
    c->generation = conn_generation_next++;
    if (conn_generation_next == 0)
      conn_generation_next = 1; /* skip 0: reserved for static fds */
    c->fd = fd;
    c->cred = *cred;
    c->phase = CONN_WANT_HEADER;
    c->want = HDR_SIZE;
    c->have = 0;
    c->out_len = 0;
    c->out_sent = 0;
    c->close_after_flush = 0;
    c->out_since = 0;
    c->events = EPOLLIN; /* caller registers with exactly this */
    c->frame_since = 0;
    c->accepted_at = mono_secs();
    c->frames_served = 0;
    c->hello_seen = 0;
    c->proto_min = 0;
    c->proto_max = 0;
    c->proto_selected = 0;
    /* The floor is assigned at accept, before the peer has said
       anything at all — identity that starts permissive and gets
       narrowed later is how a race becomes a privilege. */
    c->cl = CLASS_UNTRUSTED;
    /* Not just [0] = '\0': the whole array is compared and printed, and
       a reused slot must not carry a previous peer's name in its tail. */
    memset(c->client_name, 0, sizeof(c->client_name));
    return c;
  }
  return NULL; /* table full — caller refuses the connection */
}

/* How many live connections this peer pid already holds (M3.7 task 2).
   Why *pid* and not uid: every peer is the same uid — that is invariant
   9 — so uid discriminates nothing between two processes of this user.
   pid comes from SO_PEERCRED, is captured by the kernel at accept, and
   cannot be forged by the client. It is not a stable identity (pids get
   recycled), but that does not matter for a cap on *concurrently open*
   connections: the only question is how many live conns share this pid
   right now, and a recycled pid means the old ones are long closed.

   pid 0 is not special-cased. SO_PEERCRED reports 0 when the peer lives
   in another pid namespace or has already exited, so all such peers do
   share one bucket of 4 — a real but tiny unfairness. The alternative,
   exempting pid 0 from the cap, is an unbounded hole reachable by any
   peer that can arrange to look unmappable. Prefer the unfairness. */
static int conn_count_pid(pid_t pid) {
  int n = 0;
  for (int i = 0; i < MAX_CONNS; i++)
    if (conns[i].fd >= 0 && conns[i].cred.pid == pid)
      n++;
  return n;
}

static uint64_t conn_evkey(const struct conn *c) {
  return EVKEY_CONN(c - conns, c->generation);
}

/* Resolve an epoll event back to the connection that registered it, or
   NULL if that connection is gone. Replaces the old conn_find(fd) scan:
   this cannot alias, because the key carries the generation the event
   was registered under. */
static struct conn *conn_from_evkey(uint64_t key) {
  uint32_t slot = EVKEY_LOW(key);
  if (slot >= MAX_CONNS)
    return NULL;
  struct conn *c = &conns[slot];
  if (c->fd < 0 || c->generation != EVKEY_GEN(key))
    return NULL; /* closed, or the slot has since been reused */
  return c;
}

static void conn_close(int epfd, struct conn *c) {
  if (!c || c->fd < 0)
    return;
  epoll_ctl(epfd, EPOLL_CTL_DEL, c->fd, NULL);
  close(c->fd);
  c->fd = -1;
  /* Security rule 6: the next client to land on this slot must not be
     able to read the previous one's payload. Today that's coordinates;
     at M4 it's keystrokes. explicit_bzero, not memset — memset on a
     buffer nothing reads afterwards is legal to optimise away. */
  explicit_bzero(c->buf, sizeof(c->buf));
  explicit_bzero(c->out, sizeof(c->out));
  c->have = 0;
  c->want = 0;
  c->out_len = 0;
  c->out_sent = 0;
  c->out_since = 0;
  c->events = 0;
}

/* Best-effort refusal for a peer that never becomes a conn (bad uid,
   table full). The fd is non-blocking, so one write attempt only —
   never loop, never block on a client we are rejecting. */
static void deny_and_close(int cfd, uint16_t result) {
  struct uictl_frame_header deny = {.version = UICTL_PROTO_VERSION,
                                    .opcode = OP_INVALID,
                                    .source_tag = 0,
                                    .seq = 0,
                                    .payload_len = sizeof(uint16_t)};
  char deny_buf[HDR_SIZE + sizeof(uint16_t)];
  encode_frame_header(&deny, deny_buf);
  memcpy(deny_buf + HDR_SIZE, &result, sizeof(result));
  (void)write(cfd, deny_buf, sizeof(deny_buf));
  close(cfd);
}

/* Stage a response into the connection's out buffer. The request header
   is echoed (version, opcode, source_tag, seq) so the client can match
   the reply to its request; only payload_len is rewritten.

   `data` is the opcode-specific answer that follows the result code, and
   may be NULL/0 — which is every opcode today, and stays the shape of
   every pure command. OP_HELLO is what this exists for.

   Callers must not be able to overflow the out buffer by handing over a
   long answer, so an oversized one is refused rather than truncated: a
   truncated frame is worse than an error, because the length prefix
   would no longer describe the bytes and the stream would desync. This
   is a daemon bug if it ever fires, hence ERR_INTERNAL. */
static void conn_reply_data(struct conn *c, uint16_t result, const void *data,
                            size_t len) {
  if (len > UICTL_MAX_RESP_DATA) {
    fprintf(stderr, "uictld: reply payload %zu too large for op %u\n", len,
            c->hdr.opcode);
    result = ERR_INTERNAL;
    data = NULL;
    len = 0;
  }

  struct uictl_frame_header resp = c->hdr;
  resp.payload_len = (uint32_t)(UICTL_RESULT_SIZE + len);
  encode_frame_header(&resp, c->out);
  memcpy(c->out + HDR_SIZE, &result, UICTL_RESULT_SIZE);
  if (len)
    memcpy(c->out + HDR_SIZE + UICTL_RESULT_SIZE, data, len);
  c->out_len = HDR_SIZE + UICTL_RESULT_SIZE + len;
  c->out_sent = 0;
}

/* A bare acknowledgement: result code, no answer. */
static void conn_reply(struct conn *c, uint16_t result) {
  conn_reply_data(c, result, NULL, 0);
}

/* Push as much of the staged response as the socket will take.
     0  -> fully drained, out buffer is free again
     1  -> bytes remain; caller must arm EPOLLOUT and stop reading
    -1  -> fatal socket error, connection is dead
   Never spins on EAGAIN and never loops waiting for the peer: a client
   that stops reading must cost us one failed write() and nothing more.
   (M3.5 task 7. Before this, a partial write just killed the connection
   — correct but wrong: 18 bytes into a ~200KB socket buffer only fails
   when the peer is misbehaving *or* is a legitimate pipelining client
   that has queued thousands of frames without reading the replies.) */
static int conn_flush(struct conn *c) {
  while (c->out_sent < c->out_len) {
    ssize_t w = write(c->fd, c->out + c->out_sent, c->out_len - c->out_sent);
    if (w < 0) {
      if (errno == EINTR)
        continue;
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        return 1;
      return -1;
    }
    c->out_sent += (size_t)w;
  }
  /* Drained. Clearing both makes `out_sent < out_len` the single
     authoritative "response pending" test everywhere else. */
  c->out_len = 0;
  c->out_sent = 0;
  c->out_since = 0;
  return 0;
}

/* Point the epoll registration at whichever half of the socket we
   actually care about. EPOLLIN and EPOLLOUT are mutually exclusive here,
   and that is deliberate:

   - While a response is pending we must not parse another frame (one out
     buffer), so we stop reading. But merely *not calling read()* is not
     enough — this epoll set is level-triggered, so unread bytes sitting
     in the receive buffer would be re-reported on every single
     epoll_wait and spin the daemon at 100%. EPOLLIN has to come off the
     registration, not just be ignored.
   - Conversely, arming EPOLLOUT when nothing is queued is the classic
     busy-loop: a writable socket is almost always writable. */
static int conn_update_events(int epfd, struct conn *c) {
  uint32_t want = (c->out_sent < c->out_len) ? (uint32_t)EPOLLOUT
                                             : (uint32_t)EPOLLIN;
  if (want == c->events)
    return 0; /* nothing to do; skip the syscall */
  /* MOD replaces `data` as well as `events`, so the key must be rebuilt
     identically — a MOD that dropped back to .fd would silently undo the
     aliasing fix. */
  struct epoll_event ev = {.events = want, .data.u64 = conn_evkey(c)};
  if (epoll_ctl(epfd, EPOLL_CTL_MOD, c->fd, &ev) < 0) {
    perror("uictld: epoll_ctl MOD client");
    return -1;
  }
  c->events = want;
  return 0;
}

/* Common tail for "we just staged (and tried to send) a response".
   Returns 0 if the connection survives and may keep parsing, -1 if it
   was closed. */
static int conn_after_flush(int epfd, struct conn *c, int flushed) {
  if (flushed < 0) { /* dead socket */
    conn_close(epfd, c);
    return -1;
  }
  if (flushed > 0) { /* still queued: wait for EPOLLOUT */
    if (c->out_since == 0)
      c->out_since = mono_secs(); /* start the stall clock */
    if (conn_update_events(epfd, c) < 0) {
      conn_close(epfd, c);
      return -1;
    }
    return -1; /* survives, but the caller must stop reading */
  }
  if (c->close_after_flush) { /* fatal frame, reply delivered */
    conn_close(epfd, c);
    return -1;
  }
  return 0;
}

/* The peer drained enough of its receive buffer for us to continue. */
static void conn_writable(int epfd, struct conn *c) {
  int flushed = conn_flush(c);
  if (flushed < 0) {
    conn_close(epfd, c);
    return;
  }
  if (flushed > 0)
    return; /* still not drained; EPOLLOUT stays armed */
  if (c->close_after_flush) {
    conn_close(epfd, c);
    return;
  }
  /* Re-arm EPOLLIN. We do NOT call conn_readable here: if the peer
     pipelined more frames while we were blocked, those bytes are already
     in the receive buffer and level-triggered epoll will hand us an
     EPOLLIN on the very next epoll_wait. Letting the loop do it keeps
     this function from recursing into the parser. */
  if (conn_update_events(epfd, c) < 0)
    conn_close(epfd, c);
}

/* One complete, size-validated frame is in c->hdr + c->buf. */
/* The daemon's self-description, answered to every accepted HELLO
   (M3.6 task 3). Built once per call rather than held in a static so
   the fields stay next to the code that justifies them; it is 24 bytes.

   The two bitmaps are the contract. `daemon_version` is deliberately
   *not* — a client that branches on it is feature-sniffing, and the
   whole point of shipping a capability map is that it never has to. */
static struct uictl_resp_hello daemon_capabilities(uint16_t proto_selected) {
  struct uictl_resp_hello r = {
      .proto_selected = proto_selected,
      /* Only the absolute pointer exists today. Keyboard is M4, buttons
         and relative motion are M5.5 — a client asking "do you have
         buttons yet?" gets a truthful no, which is exactly the question
         G3 says muvor needs to be able to ask. */
      .device_caps = CAP_POINTER_ABS,
      .abs_range_max = (uint32_t)ABS_RANGE_MAX,
      .opcode_bitmap = UICTL_OP_BIT(OP_PING) | UICTL_OP_BIT(OP_MOVE_ABS) |
                       UICTL_OP_BIT(OP_HELLO),
      .daemon_version = UICTL_DAEMON_VERSION,
      .reserved = 0,
  };
  return r;
}

/* May this connection send a frame stamped with this version?
   (M3.6 task 4 — replaces a bare `version != UICTL_PROTO_VERSION`.)

   Two regimes, and the second is the one that matters. Before HELLO,
   anything the daemon speaks is admissible — a client has to be able to
   get a frame in to negotiate at all. After HELLO the version is
   *pinned* to what was selected: allowing a client to hop versions
   mid-connection would mean the same opcode could carry two different
   payload layouts on one stream, and the daemon would be guessing which
   one it just parsed. Negotiation that can be revised isn't
   negotiation. */
static int conn_version_ok(const struct conn *c, uint16_t version,
                           uint16_t opcode) {
  if (c->proto_selected != 0)
    return version == c->proto_selected;
  /* The bootstrap exemption. An un-negotiated HELLO is admitted at any
     version, because the alternative makes negotiation impossible for
     the only clients that need it: a client whose range excludes ours
     cannot send a frame we would admit, and cannot learn to until it has
     asked. Refusing it here would leave the intersection below
     unreachable — the frame would die at the header, and "we disagree
     about versions" would be indistinguishable from "your frame is
     garbage". The envelope is fixed across versions and payload_len is
     still bounded, so admitting it costs nothing. */
  if (opcode == OP_HELLO)
    return 1;
  return version >= UICTL_PROTO_MIN && version <= UICTL_PROTO_MAX;
}

static void conn_handle_frame(struct conn *c, int uinput_fd, int audit_fd) {
  uint16_t result;
  /* 128, not 64: a 31-char client name plus the negotiated version, the
     range it asked for and its class does not fit in 64, and snprintf
     would truncate the *class* — the policy-relevant half — off the end
     of the one record that is supposed to explain a decision. */
  char args[128];
  args[0] = '\0';

  /* Most opcodes are commands and answer with a bare result. An opcode
     that answers a *question* points these at its payload before the
     shared reply at the bottom. */
  const void *resp_data = NULL;
  size_t resp_len = 0;
  struct uictl_resp_hello caps; /* must outlive the switch */

  /* Handshake enforcement (M3.6 task 7). Checked BEFORE the opcode
     switch, so an un-handshaked peer is told to handshake rather than
     told which opcodes exist — the refusal reveals nothing about the
     daemon's surface, and there is exactly one thing it can do next.
     ERR_OPCODE_UNKNOWN for an unknown opcode is a post-handshake answer.

     OP_PING is exempt on purpose: it stays usable as a bare liveness
     probe, which is what a supervisor, a health check or `uictl ping`
     wants, and it neither reads state nor touches the device. OP_HELLO
     is exempt for the obvious reason. Everything else — every opcode
     that has ever moved the pointer or will ever press a key — goes
     through the handshake, because that is where the class M4's policy
     reads gets derived. Without this, a client skips HELLO and operates
     at whatever the un-negotiated default is, forever. */
  if (!c->hello_seen && c->hdr.opcode != OP_HELLO &&
      c->hdr.opcode != OP_PING) {
    audit_log(audit_fd, c->cred.pid, c->cred.uid, c->hdr.source_tag,
              c->hdr.opcode, c->hdr.seq, ERR_HANDSHAKE_REQUIRED, "no hello");
    /* Per-frame, not fatal: the frame was fully consumed, so the next
       boundary is known and the client can simply say HELLO and retry
       on this same connection. */
    conn_reply(c, ERR_HANDSHAKE_REQUIRED);
    return;
  }

  switch (c->hdr.opcode) {
  case OP_PING:
    result = (c->hdr.payload_len == 0) ? OK : ERR_PAYLOAD_INVALID;
    break;
  case OP_MOVE_ABS: {
    if (c->hdr.payload_len != sizeof(struct uictl_payload_move_abs)) {
      result = ERR_PAYLOAD_INVALID;
      break;
    }
    struct uictl_payload_move_abs mv;
    decode_move_abs(c->buf, &mv);
    /* audit records intent: the value asked for, before clamping */
    snprintf(args, sizeof(args), "x=%d y=%d", mv.x, mv.y);
    if (mv.x < 0)
      mv.x = 0;
    if (mv.x > ABS_RANGE_MAX)
      mv.x = ABS_RANGE_MAX;
    if (mv.y < 0)
      mv.y = 0;
    if (mv.y > ABS_RANGE_MAX)
      mv.y = ABS_RANGE_MAX;
    result = (uinput_move_abs(uinput_fd, mv.x, mv.y) < 0) ? ERR_INTERNAL : OK;
    break;
  }
  case OP_HELLO: {
    /* >=, not ==, for the same reason the client accepts a longer
       response: HELLO is the bootstrap frame, so a v2 client's longer
       HELLO must still be readable by a v1 daemon — otherwise it gets
       ERR_PAYLOAD_INVALID and never learns that the real disagreement
       was about versions. The prefix is fixed forever; the tail is
       whatever a newer version appended and is ignored here. */
    if (c->hdr.payload_len < sizeof(struct uictl_payload_hello)) {
      result = ERR_PAYLOAD_INVALID;
      break;
    }
    /* One HELLO per connection, and it is terminal, not retryable. A
       second one would let a client rename itself *after* the daemon has
       attached a class to the first name — which is exactly the
       per-frame self-assertion (G2) this frame exists to replace. The
       connection is the scope of the handshake; a client that wants a
       different identity opens a different connection. */
    if (c->hello_seen) {
      result = ERR_DENIED_BY_POLICY;
      snprintf(args, sizeof(args), "duplicate hello name=%s", c->client_name);
      break;
    }

    struct uictl_payload_hello hello;
    decode_hello(c->buf, &hello);

    if (!uictl_client_name_valid(hello.client_name)) {
      /* Deliberately does NOT echo the offending name — it just failed
         the check that makes it safe to put in a newline-delimited log. */
      result = ERR_PAYLOAD_INVALID;
      snprintf(args, sizeof(args), "bad client name");
      break;
    }
    if (hello.proto_min > hello.proto_max) {
      result = ERR_PAYLOAD_INVALID;
      snprintf(args, sizeof(args), "inverted proto range %u-%u",
               hello.proto_min, hello.proto_max);
      break;
    }
    /* The frame is self-describing, so it must not contradict itself:
       a client claiming to speak 2-3 while stamping this very header
       version 1 has a bug, and guessing which half to believe is how a
       negotiation ends up with two disagreeing parties who both think
       they succeeded. */
    if (c->hdr.version < hello.proto_min || c->hdr.version > hello.proto_max) {
      result = ERR_PAYLOAD_INVALID;
      snprintf(args, sizeof(args), "header v%u outside declared %u-%u",
               c->hdr.version, hello.proto_min, hello.proto_max);
      break;
    }

    /* The intersection (M3.6 task 4). Highest mutually supported wins:
       both sides claim to speak everything in their range, so the newest
       common version is the one with the most features and no downside.

       ERR_VERSION here is a *per-frame* error, not the fatal kind the
       header check raises. The difference is whether the next frame
       boundary is knowable: a bad header version means payload_len is
       untrustworthy and the stream is lost, whereas here the payload was
       already read and validated, so the connection survives. It stays
       usable on purpose — hello_seen is only set on success, so a client
       may retry HELLO with a different range on the same connection. */
    uint16_t lo = hello.proto_min > UICTL_PROTO_MIN ? hello.proto_min
                                                    : (uint16_t)UICTL_PROTO_MIN;
    uint16_t hi = hello.proto_max < UICTL_PROTO_MAX ? hello.proto_max
                                                    : (uint16_t)UICTL_PROTO_MAX;
    if (lo > hi) {
      result = ERR_VERSION;
      snprintf(args, sizeof(args), "no overlap: client %u-%u daemon %u-%u",
               hello.proto_min, hello.proto_max, UICTL_PROTO_MIN,
               UICTL_PROTO_MAX);
      break;
    }

    c->proto_min = hello.proto_min;
    c->proto_max = hello.proto_max;
    c->proto_selected = hi;
    memcpy(c->client_name, hello.client_name, sizeof(c->client_name));
    c->cl = class_for_name(c->client_name);
    c->hello_seen = 1;

    caps = daemon_capabilities(c->proto_selected);
    resp_data = &caps;
    resp_len = sizeof(caps);

    /* Both halves: the range the client asked for is its *intent*, the
       selected version and derived class are the daemon's *decision*.
       Security rule 5 wants the first; a policy audit needs the second. */
    snprintf(args, sizeof(args), "name=%s proto=%u asked=%u-%u class=%s",
             c->client_name, c->proto_selected, c->proto_min, c->proto_max,
             class_name(c->cl));
    result = OK;
    break;
  }
  default:
    result = ERR_OPCODE_UNKNOWN;
    break;
  }

  audit_log(audit_fd, c->cred.pid, c->cred.uid, c->hdr.source_tag,
            c->hdr.opcode, c->hdr.seq, result, args);
  /* An answer rides along only on success: an error response is a bare
     result code for every opcode, so a client never has to decide
     whether a failed request left it a half-filled struct. */
  if (result == OK)
    conn_reply_data(c, result, resp_data, resp_len);
  else
    conn_reply(c, result);
}

/* Drain what is readable on this connection, dispatching each frame as
   it completes, up to CONN_FRAMES_PER_TURN frames. Exact-size reads: we
   ask for precisely the bytes the current phase still needs, so a read
   can never overshoot into the next frame and there is no leftover tail
   to compact. Pipelined frames still work — the loop simply comes back
   around, and past the budget the *next* epoll turn comes back around.

   The budget (M3.7 task 1, G6) is what makes the scheduling unit "one
   frame" instead of "one connection's whole backlog". Returning early
   with bytes still sitting in the receive buffer IS the round-robin:
   epoll here is level-triggered, so this connection is re-reported as
   readable on the very next turn, after every other ready fd has had
   theirs. The kernel's readiness list is the queue — no scheduler, no
   priority queue, no fairness counter to keep consistent. (Third thing
   level-triggered mode gives us for free, after re-arming EPOLLIN post
   EPOLLOUT stall and never having to remember "there may be more".) */
static void conn_readable(int epfd, struct conn *c, int uinput_fd,
                          int audit_fd) {
  unsigned dispatched = 0;

  for (;;) {
    while (c->have < c->want) {
      ssize_t r = read(c->fd, c->buf + c->have, c->want - c->have);
      if (r < 0) {
        if (errno == EINTR)
          continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK)
          return; /* socket drained; wait for the next EPOLLIN */
        perror("uictld: read client");
        conn_close(epfd, c);
        return;
      }
      if (r == 0) { /* peer EOF */
        conn_close(epfd, c);
        return;
      }
      if (c->have == 0 && c->phase == CONN_WANT_HEADER)
        c->frame_since = mono_secs(); /* first byte of a new frame */
      c->have += (size_t)r;
    }

    if (c->phase == CONN_WANT_HEADER) {
      decode_frame_header(c->buf, &c->hdr);

      /* Validation order is load-bearing. payload_len is attacker-
         controlled up to 4 GB and the very next read uses it as a
         length into a 4 KB buffer, so it MUST be bounded before it is
         copied into c->want. */
      uint16_t fatal = 0;
      if (!conn_version_ok(c, c->hdr.version, c->hdr.opcode))
        fatal = ERR_VERSION;
      else if (c->hdr.payload_len > UICTL_MAX_PAYLOAD)
        fatal = ERR_TOO_LARGE;

      if (fatal) {
        /* Both errors leave us unable to find the next frame boundary:
           a rejected version means payload_len is untrustworthy, and an
           over-long payload means those bytes are still queued and
           would be misparsed as the next header. So these are fatal to
           the stream, not per-frame. ERR_OPCODE_UNKNOWN and
           ERR_PAYLOAD_INVALID are not — there the payload was consumed
           and the connection continues. */
        audit_log(audit_fd, c->cred.pid, c->cred.uid, c->hdr.source_tag,
                  c->hdr.opcode, c->hdr.seq, fatal, "fatal frame");
        conn_reply(c, fatal);
        /* Close *after* the error actually reaches the peer, not before.
           Previously the reply was written best-effort and the socket
           closed immediately; if it didn't drain, the client learned
           nothing but "connection reset". */
        c->close_after_flush = 1;
        (void)conn_after_flush(epfd, c, conn_flush(c));
        return;
      }

      c->phase = CONN_WANT_PAYLOAD;
      c->want = c->hdr.payload_len;
      c->have = 0;
      if (c->want > 0)
        continue; /* go read the payload */
      /* Zero-length payload (PING) falls through and is dispatched now.
         It must NOT go back through the read loop: read(fd, buf, 0)
         returns 0, which is indistinguishable from EOF. */
    }

    conn_handle_frame(c, uinput_fd, audit_fd);
    int flushed = conn_flush(c);

    /* Reset for the next frame on this same connection. Done before the
       flush verdict is acted on: the request has been fully consumed and
       answered either way, so the read state is stale regardless of
       whether the reply made it out. */
    c->phase = CONN_WANT_HEADER;
    c->want = HDR_SIZE;
    c->have = 0;
    explicit_bzero(c->buf, sizeof(c->buf));

    /* -1 means closed, or queued and waiting on EPOLLOUT. Either way we
       stop parsing: with one out buffer, handling the next pipelined
       frame here would clobber the reply still in flight. */
    if (conn_after_flush(epfd, c, flushed) < 0)
      return;

    /* Counted here, per *dispatched frame* — not per read() and not per
       loop iteration. A frame trickling in across five reads is still
       one frame's worth of work; charging it five would let a slow but
       honest client spend its budget on nothing and yield a turn for
       every fragment. Nothing else is needed on the way out: EPOLLIN is
       still armed (conn_after_flush only drops it while a reply is
       pending), so the leftover bytes come back to us next turn. */
    c->frames_served++;
    if (++dispatched >= CONN_FRAMES_PER_TURN)
      return;
  }
}

/* A frame is in progress iff we are holding parse state for bytes that
   have not all arrived. Two cases: mid-header (have > 0, still in
   CONN_WANT_HEADER), or header complete and payload outstanding
   (CONN_WANT_PAYLOAD). An idle connection sitting at
   CONN_WANT_HEADER with have == 0 is NOT in progress — that is the
   normal resting state of a long-lived client between hotkeys, and
   reaping it would break the very thing M3.5 exists to support. */
static int conn_frame_in_progress(const struct conn *c) {
  return c->have > 0 || c->phase == CONN_WANT_PAYLOAD;
}

/* One timer, scanned against the whole table — not one timer per
   connection. At <= 32 slots the scan is cheaper than 32 timerfds, and
   there is no per-connection fd to leak on close. */
static void conn_reap_partial(int epfd, int audit_fd) {
  time_t now = mono_secs();
  for (int i = 0; i < MAX_CONNS; i++) {
    struct conn *c = &conns[i];
    if (c->fd < 0)
      continue;

    /* Two independent stalls, same deadline.

       A peer that stops *sending* mid-frame leaves us holding parse
       state (task 6). A peer that stops *reading* leaves us holding an
       undeliverable reply — a hole task 7 opened, because the old
       conn_flush killed such a connection on the spot and the new one
       parks it on EPOLLOUT indefinitely. Both occupy a slot forever, so
       both are reaped. */
    const char *why = NULL;
    if (conn_frame_in_progress(c) &&
        now - c->frame_since >= CONN_PARTIAL_TIMEOUT_SEC)
      why = "partial frame timeout";
    else if (c->out_since != 0 && now - c->out_since >= CONN_PARTIAL_TIMEOUT_SEC)
      why = "response stalled";
    if (!why)
      continue;

    /* c->hdr is only decoded once the header phase completes; in
       CONN_WANT_HEADER it still holds the previous frame's values, so
       report zeros rather than auditing stale state as if it were this
       frame's. (On the stalled-write path hdr *is* this frame's — the
       reply was built from it — so it reports usefully either way.) */
    int hdr_valid = (c->phase == CONN_WANT_PAYLOAD) || (c->out_since != 0);
    uint16_t op = hdr_valid ? c->hdr.opcode : OP_INVALID;
    uint32_t src = hdr_valid ? c->hdr.source_tag : 0;
    uint32_t seq = hdr_valid ? c->hdr.seq : 0;

    audit_log(audit_fd, c->cred.pid, c->cred.uid, src, op, seq,
              ERR_DENIED_BY_POLICY, why);
    /* No reply attempt. The peer is by definition not talking, so its
       receive window may be full and a write could block the daemon —
       which is exactly the failure this whole milestone removes. */
    conn_close(epfd, c);
  }
}

/* SIGUSR1 handler body (M3.7 task 4 / G10): what the operator gets
   instead of grepping an append-only log to answer "who is connected and
   who is being refused". Deliberately stderr and not a new opcode:
   open question 4 leans against exposing peer identities *to clients*
   (an information leak between peers of the same user), and that
   objection does not apply to the operator running the daemon.

   Everything here is metadata — pids, phases, counters. No payload
   bytes, no coordinates, nothing that would become keystrokes at M4.
   That is security rule 5's "intent, not content" applied to a channel
   the rule was not written for; keep it that way when adding fields.

   Called straight from the event loop, not from a signal handler, so
   fprintf is safe. That is the whole reason signalfd exists: an
   async-signal handler could not do any of this. */
static void conn_dump_table(void) {
  time_t now = mono_secs();
  int used = 0;
  for (int i = 0; i < MAX_CONNS; i++)
    if (conns[i].fd >= 0)
      used++;

  fprintf(stderr, "uictld: %d/%d slots used (max %d per pid)\n", used,
          MAX_CONNS, MAX_CONNS_PER_PID);
  for (int i = 0; i < MAX_CONNS; i++) {
    const struct conn *c = &conns[i];
    if (c->fd < 0)
      continue;

    /* Same distinction the reaper makes: "idle" is a resting long-lived
       client, "hdr"/"payload" mean bytes are outstanding and the reap
       clock is running. Printing them apart is the point — it is what
       tells an operator whether a quiet connection is healthy or stuck. */
    const char *phase = !conn_frame_in_progress(c) ? "idle"
                        : c->phase == CONN_WANT_PAYLOAD
                            ? "payload"
                            : "hdr";
    /* "-" for a peer that has not said HELLO. Safe to print unquoted:
       uictl_client_name_valid() is what let it be stored at all. */
    fprintf(stderr,
            "  slot=%2d gen=%u fd=%d pid=%d uid=%u name=%s class=%s "
            "phase=%s(%zu/%zu) reply=%zu/%zu age=%llds frames=%llu\n",
            i, c->generation, c->fd, (int)c->cred.pid, (unsigned)c->cred.uid,
            c->hello_seen ? c->client_name : "-", class_name(c->cl), phase,
            c->have, c->want,
            c->out_sent, c->out_len, (long long)(now - c->accepted_at),
            (unsigned long long)c->frames_served);
  }
  fflush(stderr);
}

int main(void) {

  const char *xdg = getenv("XDG_RUNTIME_DIR");
  if (!xdg) {
    fprintf(stderr, "uictld: XDG_RUNTIME_DIR is not set. failed to start\n");
    return 1;
  }

  char path[108];
  int n = snprintf(path, sizeof(path), "%s/uictld.sock", xdg);
  if (n < 0 || (size_t)n >= sizeof(path)) {
    fprintf(stderr, "uictld: socket path too long\n");
    return 1;
  }

  umask(0077);
  /* SOCK_NONBLOCK on the LISTENING socket. accept4()'s flag argument
     applies to the socket it returns, not to the one it is called on —
     without this, the accept-until-EAGAIN loop blocks forever on its
     second iteration and the daemon never reaches epoll_wait again. */
  int sfd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
  if (sfd < 0) {
    perror("uictld: socket");
    return 1;
  }

  struct sockaddr_un addr = {.sun_family = AF_UNIX};
  strcpy(addr.sun_path, path);

  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGINT);
  sigaddset(&mask, SIGTERM);
  /* SIGUSR1 is the operator's "who is connected?" (M3.7 task 4). It has
     to be in this set for two reasons, and the second one is the sharp
     one: signalfd only ever reports signals that are BLOCKED, and the
     default disposition of SIGUSR1 is *terminate the process*. Add it to
     the signalfd mask but forget it here and `kill -USR1 $(pidof uictld)`
     kills the daemon instead of printing a table. */
  sigaddset(&mask, SIGUSR1);
  if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) {
    perror("uictld: sigprocmask");
    close(sfd);
    return 1;
  }

  struct sigaction ign = {.sa_handler = SIG_IGN};
  sigemptyset(&ign.sa_mask);

  if (sigaction(SIGPIPE, &ign, NULL) < 0) {
    perror("uictld: sigaction SIGPIPE");
    close(sfd);
    return 1;
  }

  char state_dir[256];
  if (prepare_state_dir(state_dir, sizeof(state_dir)) < 0) {
    close(sfd);
    return 1;
  }

  char lock_path[256];
  int lp = snprintf(lock_path, sizeof(lock_path), "%s/uictld.lock", state_dir);
  if (lp < 0 || (size_t)lp >= sizeof(lock_path)) {
    fprintf(stderr, "uictld: loack path too long\n");
    close(sfd);
    return 1;
  }
  int lockfd = open(lock_path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
  if (lockfd < 0) {
    perror("uictld: open lockfile");
    close(sfd);
    return 1;
  }
  if (flock(lockfd, LOCK_EX | LOCK_NB) < 0) {
    if (errno == EWOULDBLOCK) {
      fprintf(stderr, "uictld: another daemon already running\n");
    } else {
      perror("uictld: flock");
    }
    close(lockfd);
    close(sfd);
    return 1;
  }

  int audit_fd = open_audit_log(state_dir);
  if (audit_fd < 0) {
    close(lockfd);
    close(sfd);
    return 1;
  }

  if (unlink(path) < 0 && errno != ENOENT) {
    perror("uictld: unlink");
    close(audit_fd);
    close(lockfd);
    close(sfd);
    return 1;
  }

  if (bind(sfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    perror("uictld: bind");
    close(audit_fd);
    close(sfd);
    return 1;
  }

  if (listen(sfd, 16) < 0) {
    perror("uictld: listen");
    close(audit_fd);
    close(lockfd);
    close(sfd);
    unlink(path);
    return 1;
  }

  int uinput_fd = uinput_open();
  if (uinput_fd < 0) {
    close(audit_fd);
    close(lockfd);
    close(sfd);
    unlink(path);
    return 1;
  }

  int sigfd = signalfd(-1, &mask, SFD_CLOEXEC);
  if (sigfd < 0) {
    perror("uictld: signalfd");
    uinput_close(uinput_fd);
    close(audit_fd);
    close(lockfd);
    close(sfd);
    unlink(path);
    return 1;
  }

  int epfd = epoll_create1(EPOLL_CLOEXEC);
  if (epfd < 0) {
    perror("uictld: epoll_create1");
    uinput_close(uinput_fd);
    close(sigfd);
    close(audit_fd);
    close(lockfd);
    close(sfd);
    unlink(path);
    return 1;
  }
  /* CLOCK_MONOTONIC, not CLOCK_REALTIME: an NTP step or a settimeofday
     must not make the reaper fire early or stall for hours. TFD_NONBLOCK
     so the mandatory read() below can never park the loop. */
  int tfd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
  if (tfd < 0) {
    perror("uictld: timerfd_create");
    uinput_close(uinput_fd);
    close(epfd);
    close(sigfd);
    close(audit_fd);
    close(lockfd);
    close(sfd);
    unlink(path);
    return 1;
  }
  /* it_value arms the first expiry, it_interval makes it periodic. Leave
     it_interval zero and the timer fires exactly once — the classic
     one-shot bug that looks like "the reaper worked, then stopped". */
  struct itimerspec its = {.it_value = {.tv_sec = REAPER_TICK_SEC},
                           .it_interval = {.tv_sec = REAPER_TICK_SEC}};
  if (timerfd_settime(tfd, 0, &its, NULL) < 0) {
    perror("uictld: timerfd_settime");
    close(tfd);
    uinput_close(uinput_fd);
    close(epfd);
    close(sigfd);
    close(audit_fd);
    close(lockfd);
    close(sfd);
    unlink(path);
    return 1;
  }

  /* Static sources carry generation 0 in their key, which is what makes
     them distinguishable from connection keys at dispatch. */
  struct epoll_event ev = {.events = EPOLLIN, .data.u64 = EVKEY_STATIC(sfd)};
  epoll_ctl(epfd, EPOLL_CTL_ADD, sfd, &ev);
  ev.data.u64 = EVKEY_STATIC(sigfd);
  epoll_ctl(epfd, EPOLL_CTL_ADD, sigfd, &ev);
  ev.data.u64 = EVKEY_STATIC(tfd);
  epoll_ctl(epfd, EPOLL_CTL_ADD, tfd, &ev);

  conn_table_init(); /* fd = -1 in every slot; 0 would alias stdin */
  /* Before the first accept, so no connection can be classified against
     a half-loaded registry. */
  load_client_registry();

  printf("uictld: listening on %s\n", path);
  fflush(stdout);

  struct epoll_event events[8];
  int stop = 0;

  while (!stop) {
    int nfd = epoll_wait(epfd, events, 8, -1);
    if (nfd < 0) {
      if (errno == EINTR)
        continue;
      perror("uictld: epoll_wait");
      break;
    }

    for (int i = 0; i < nfd; i++) {
      uint64_t key = events[i].data.u64;
      int is_static = (EVKEY_GEN(key) == 0);
      int skey = is_static ? (int)EVKEY_LOW(key) : -1;

      if (is_static && skey == sigfd) {
        struct signalfd_siginfo si;
        if (read(sigfd, &si, sizeof(si)) != (ssize_t)sizeof(si)) {
          /* Can't tell what arrived. Shutting down is the safe reading:
             the alternative is ignoring a SIGTERM. */
          perror("uictld: read signalfd");
          stop = 1;
          break;
        }

        /* Not every signal is a shutdown — this branch used to assume
           so. One siginfo is consumed per event; if several signals are
           pending the fd stays readable (level-triggered) and we come
           back for the rest, so `continue` here loses nothing. */
        if (si.ssi_signo == SIGUSR1) {
          conn_dump_table();
          continue;
        }

        fprintf(stderr, "uictld: signal %u, shutting down\n", si.ssi_signo);
        stop = 1;
        break;
      } else if (is_static && skey == tfd) {
        /* MANDATORY. epoll here is level-triggered, so the fd stays
           readable until the expiration count is consumed; skip this
           read and the loop spins at 100% CPU forever. The value is the
           number of expiries since the last read (>1 if we were busy) —
           we do not care how many, only that a tick happened. */
        uint64_t expirations;
        if (read(tfd, &expirations, sizeof(expirations)) !=
            (ssize_t)sizeof(expirations)) {
          if (errno != EAGAIN && errno != EWOULDBLOCK)
            perror("uictld: read timerfd");
          continue;
        }
        conn_reap_partial(epfd, audit_fd);
      } else if (is_static && skey == sfd) {
        /* Accept until EAGAIN: one EPOLLIN on the listening socket can
           stand for several queued connections, and level-triggered
           epoll would otherwise just fire again. */
        for (;;) {
          int cfd = accept4(sfd, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
          if (cfd < 0) {
            if (errno == EINTR)
              continue;
            if (errno != EAGAIN && errno != EWOULDBLOCK)
              perror("uictld: accept4");
            break;
          }

          struct ucred cred;
          socklen_t cred_len = sizeof(cred);
          if (getsockopt(cfd, SOL_SOCKET, SO_PEERCRED, &cred, &cred_len) < 0) {
            perror("uictld: getsockopt SO_PEERCRED");
            close(cfd);
            continue;
          }
          if (cred.uid != getuid()) {
            audit_log(audit_fd, cred.pid, cred.uid, 0, OP_INVALID, 0,
                      ERR_DENIED_BY_POLICY, "peer uid mismatch");
            deny_and_close(cfd, ERR_DENIED_BY_POLICY);
            continue;
          }

          /* Per-pid cap before the table cap, so a peer that is already
             at its own limit is told so specifically. Both are ERR_BUSY:
             from the client's side both mean "no slot for you right now,
             try again", which is exactly what ERR_BUSY promises and what
             ERR_DENIED_BY_POLICY (terminal) must not be used for.

             The M3.5 reaper cannot substitute for this check and that is
             deliberate, not an oversight: decision 2 defines an idle
             connection with no frame in progress as well-behaved, so 32
             idle connections from one pid are, by the daemon's own
             rules, 32 innocent connections. This is the only thing that
             stops them from being all of them. */
          if (conn_count_pid(cred.pid) >= MAX_CONNS_PER_PID) {
            audit_log(audit_fd, cred.pid, cred.uid, 0, OP_INVALID, 0,
                      ERR_BUSY, "per-pid conn cap");
            deny_and_close(cfd, ERR_BUSY);
            continue;
          }

          struct conn *c = conn_alloc(cfd, &cred);
          if (!c) {
            /* M3.5 task 3: hard global cap. We still accept() and
               close() rather than leaving it queued — an unaccepted
               connection keeps the listening socket readable forever. */
            audit_log(audit_fd, cred.pid, cred.uid, 0, OP_INVALID, 0, ERR_BUSY,
                      "conn table full");
            deny_and_close(cfd, ERR_BUSY);
            continue;
          }

          struct epoll_event cev = {.events = EPOLLIN,
                                    .data.u64 = conn_evkey(c)};
          if (epoll_ctl(epfd, EPOLL_CTL_ADD, cfd, &cev) < 0) {
            perror("uictld: epoll_ctl ADD client");
            conn_close(epfd, c);
            continue;
          }
        }
      } else {
        struct conn *c = conn_from_evkey(key);
        if (!c)
          continue; /* connection closed earlier in this same batch */
        if (events[i].events & (EPOLLHUP | EPOLLERR)) {
          conn_close(epfd, c);
          continue;
        }
        /* Only ever one of the two is registered at a time (see
           conn_update_events), but check both and re-test c->fd:
           conn_writable can close the connection out from under us. */
        if (events[i].events & EPOLLOUT)
          conn_writable(epfd, c);
        if (c->fd >= 0 && (events[i].events & EPOLLIN))
          conn_readable(epfd, c, uinput_fd, audit_fd);
      }
    }
  }

  fprintf(stderr, "uictld: shutting down\n");

  /* Close live connections before tearing down the device, so a client
     blocked in read() sees EOF rather than a silently vanished daemon. */
  for (int i = 0; i < MAX_CONNS; i++)
    if (conns[i].fd >= 0)
      conn_close(epfd, &conns[i]);

  uinput_close(uinput_fd);
  close(tfd);
  close(sigfd);
  close(epfd);
  close(sfd);
  unlink(path);
  close(audit_fd);
  close(lockfd);
  return 0;
}
