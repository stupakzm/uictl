#include "platform/uinput.h"
#include "proto.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/file.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t stop = 0;

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
  int sfd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
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
        int cfd = accept4(sfd, NULL, NULL, SOCK_CLOEXEC);
        if (cfd < 0) {
          if (errno == EINTR)
            continue;
          perror("uictld: accept4");
          continue;
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
          struct uictl_frame_header deny = {.version = UICTL_PROTO_VERSION,
                                            .opcode = OP_INVALID,
                                            .source_tag = 0,
                                            .seq = 0,
                                            .payload_len = sizeof(uint16_t)};
          char deny_buf[sizeof(deny) + sizeof(uint16_t)];
          encode_frame_header(&deny, deny_buf);
          uint16_t deny_result = ERR_DENIED_BY_POLICY;
          memcpy(deny_buf + sizeof(deny), &deny_result, sizeof(deny_result));
          (void)write_full(cfd, deny_buf, sizeof(deny_buf));
          close(cfd);
          continue;
        }

        char hdr_buf[sizeof(struct uictl_frame_header)];
        ssize_t rh = read_full(cfd, hdr_buf, sizeof(hdr_buf));
        if (rh < 0) {
          perror("uictld: read header");
          close(cfd);
          continue;
        }
        if ((size_t)rh != sizeof(hdr_buf)) {
          fprintf(stderr, "uictld: client closed mid-header\n");
          close(cfd);
          continue;
        }

        struct uictl_frame_header req;
        decode_frame_header(hdr_buf, &req);

        struct uictl_frame_header resp = req;
        resp.payload_len = sizeof(uint16_t);

        uint16_t result;
        char payload_buf[UICTL_MAX_PAYLOAD];

        if (req.version != UICTL_PROTO_VERSION) {
          result = ERR_VERSION;
        } else if (req.payload_len > UICTL_MAX_PAYLOAD) {
          result = ERR_TOO_LARGE;
        } else {
          ssize_t rp = read_full(cfd, payload_buf, req.payload_len);
          if (rp < 0) {
            perror("uictld: read payload");
            close(cfd);
            continue;
          }
          if ((size_t)rp != req.payload_len) {
            fprintf(stderr, "uictld: client closed mid-payload\n");
            close(cfd);
            continue;
          }

          switch (req.opcode) {
          case OP_PING:
            result = (req.payload_len == 0) ? OK : ERR_PAYLOAD_INVALID;
            break;
          case OP_MOVE_ABS:
            if (req.payload_len != sizeof(struct uictl_payload_move_abs)) {
              result = ERR_PAYLOAD_INVALID;
              break;
            }
            struct uictl_payload_move_abs mv;
            decode_move_abs(payload_buf, &mv);
            if (mv.x < 0)
              mv.x = 0;
            if (mv.x > ABS_RANGE_MAX)
              mv.x = ABS_RANGE_MAX;
            if (mv.y < 0)
              mv.y = 0;
            if (mv.y > ABS_RANGE_MAX)
              mv.y = ABS_RANGE_MAX;
            result =
                (uinput_move_abs(uinput_fd, mv.x, mv.y) < 0) ? ERR_INTERNAL : 0;
            break;
          default:
            result = ERR_OPCODE_UNKNOWN;
            break;
          }
        }

        char args_buf[64];
        args_buf[0] = '\0';
        if (result == OK && req.opcode == OP_MOVE_ABS) {
          struct uictl_payload_move_abs mv;
          decode_move_abs(payload_buf, &mv);
          snprintf(args_buf, sizeof(args_buf), "x=%d y=%d", mv.x, mv.y);
        }
        audit_log(audit_fd, cred.pid, cred.uid, req.source_tag, req.opcode,
                  req.seq, result, args_buf);

        char resp_buf[sizeof(struct uictl_frame_header) + sizeof(uint16_t)];
        encode_frame_header(&resp, resp_buf);
        memcpy(resp_buf + sizeof(struct uictl_frame_header), &result,
               sizeof(result));

        if (write_full(cfd, resp_buf, sizeof(resp_buf)) < 0) {
          perror("uictld: write_full");
        }

        close(cfd);
      }
    }
  }

  fprintf(stderr, "uictld: shutting down\n");

  uinput_close(uinput_fd);
  close(sigfd);
  close(epfd);
  close(sfd);
  unlink(path);
  close(audit_fd);
  close(lockfd);
  return 0;
}
