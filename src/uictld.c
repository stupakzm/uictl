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

enum conn_phase { CONN_WANT_HEADER, CONN_WANT_PAYLOAD };

struct conn {
  int fd;            /* < 0 => slot free. the ONLY free marker.        */
  struct ucred cred; /* captured once at accept; never re-read.        */

  /* --- read side --- invariant: have <= want <= sizeof(buf) --------- */
  enum conn_phase phase;
  size_t want;                   /* bytes this phase still needs total */
  size_t have;                   /* bytes currently in buf             */
  struct uictl_frame_header hdr; /* valid only in CONN_WANT_PAYLOAD    */
  char buf[CONN_BUF_SIZE];

  /* --- write side --- M3.5 task 7 turns this into EPOLLOUT-driven --- */
  char out[CONN_OUT_SIZE];
  size_t out_len;
  size_t out_sent;
  int close_after_flush; /* fatal frame: finish the reply, then close  */

  /* CLOCK_MONOTONIC seconds when the current frame's first byte
     arrived. Valid only while a frame is in progress, i.e.
     (have > 0 || phase == CONN_WANT_PAYLOAD). Read by the M3.5 task 6
     reaper; nothing consumes it yet. */
  time_t frame_since;
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

static struct conn *conn_alloc(int fd, const struct ucred *cred) {
  for (int i = 0; i < MAX_CONNS; i++) {
    if (conns[i].fd >= 0)
      continue;
    struct conn *c = &conns[i];
    c->fd = fd;
    c->cred = *cred;
    c->phase = CONN_WANT_HEADER;
    c->want = HDR_SIZE;
    c->have = 0;
    c->out_len = 0;
    c->out_sent = 0;
    c->close_after_flush = 0;
    c->frame_since = 0;
    return c;
  }
  return NULL; /* table full — caller refuses the connection */
}

static struct conn *conn_find(int fd) {
  for (int i = 0; i < MAX_CONNS; i++)
    if (conns[i].fd == fd)
      return &conns[i];
  return NULL;
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
   the reply to its request; only payload_len is rewritten. */
static void conn_reply(struct conn *c, uint16_t result) {
  struct uictl_frame_header resp = c->hdr;
  resp.payload_len = sizeof(uint16_t);
  encode_frame_header(&resp, c->out);
  memcpy(c->out + HDR_SIZE, &result, sizeof(result));
  c->out_len = HDR_SIZE + sizeof(result);
  c->out_sent = 0;
}

/* Returns -1 if the response could not be fully written. Responses are
   18 bytes and the socket buffer is ~200 KB, so a partial write means
   the peer is pathological; closing is the safe answer until task 7
   gives us a real EPOLLOUT path. Notably we do NOT spin on EAGAIN. */
static int conn_flush(struct conn *c) {
  while (c->out_sent < c->out_len) {
    ssize_t w = write(c->fd, c->out + c->out_sent, c->out_len - c->out_sent);
    if (w < 0) {
      if (errno == EINTR)
        continue;
      return -1;
    }
    c->out_sent += (size_t)w;
  }
  return 0;
}

/* One complete, size-validated frame is in c->hdr + c->buf. */
static void conn_handle_frame(struct conn *c, int uinput_fd, int audit_fd) {
  uint16_t result;
  char args[64];
  args[0] = '\0';

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
  default:
    result = ERR_OPCODE_UNKNOWN;
    break;
  }

  audit_log(audit_fd, c->cred.pid, c->cred.uid, c->hdr.source_tag,
            c->hdr.opcode, c->hdr.seq, result, args);
  conn_reply(c, result);
}

/* Drain everything readable on this connection, dispatching each frame
   as it completes. Exact-size reads: we ask for precisely the bytes the
   current phase still needs, so a read can never overshoot into the
   next frame and there is no leftover tail to compact. Pipelined frames
   still work — the loop simply comes back around. */
static void conn_readable(int epfd, struct conn *c, int uinput_fd,
                          int audit_fd) {
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
      if (c->hdr.version != UICTL_PROTO_VERSION)
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
        (void)conn_flush(c);
        conn_close(epfd, c);
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

    /* Reset for the next frame on this same connection. */
    c->phase = CONN_WANT_HEADER;
    c->want = HDR_SIZE;
    c->have = 0;
    explicit_bzero(c->buf, sizeof(c->buf));

    if (flushed < 0 || c->close_after_flush) {
      conn_close(epfd, c);
      return;
    }
  }
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
  struct epoll_event ev = {.events = EPOLLIN, .data.fd = sfd};
  epoll_ctl(epfd, EPOLL_CTL_ADD, sfd, &ev);
  ev.data.fd = sigfd;
  epoll_ctl(epfd, EPOLL_CTL_ADD, sigfd, &ev);

  conn_table_init(); /* fd = -1 in every slot; 0 would alias stdin */

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
      if (events[i].data.fd == sigfd) {
        struct signalfd_siginfo si;
        if (read(sigfd, &si, sizeof(si)) == (ssize_t)sizeof(si))
          fprintf(stderr, "uictld: signal %u, shutting down\n", si.ssi_signo);
        else
          perror("uictld: read signalfd");

        stop = 1;
        break;
      } else if (events[i].data.fd == sfd) {
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

          struct conn *c = conn_alloc(cfd, &cred);
          if (!c) {
            /* Task 3: hard cap. We still accept() and close() rather
               than leaving it queued — an unaccepted connection keeps
               the listening socket readable forever. */
            audit_log(audit_fd, cred.pid, cred.uid, 0, OP_INVALID, 0,
                      ERR_DENIED_BY_POLICY, "conn table full");
            deny_and_close(cfd, ERR_DENIED_BY_POLICY);
            continue;
          }

          struct epoll_event cev = {.events = EPOLLIN, .data.fd = cfd};
          if (epoll_ctl(epfd, EPOLL_CTL_ADD, cfd, &cev) < 0) {
            perror("uictld: epoll_ctl ADD client");
            conn_close(epfd, c);
            continue;
          }
        }
      } else {
        struct conn *c = conn_find(events[i].data.fd);
        if (!c)
          continue; /* event for an fd we already closed */
        if (events[i].events & (EPOLLHUP | EPOLLERR)) {
          conn_close(epfd, c);
          continue;
        }
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
  close(sigfd);
  close(epfd);
  close(sfd);
  unlink(path);
  close(audit_fd);
  close(lockfd);
  return 0;
}
