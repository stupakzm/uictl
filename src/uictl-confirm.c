/* uictl-confirm — the human in the loop (M5).
 *
 * The third binary, and the reason there is a third rather than a
 * subprocess: plan.md forbids uictld from ever fork()ing or exec()ing,
 * so the daemon cannot summon a prompter. The prompter comes to it — an
 * ordinary unprivileged client that connects to the same socket, says
 * OP_CONFIRM_SUBSCRIBE, and then answers the prompts the daemon pushes.
 *
 * Threat model, stated plainly because it is easy to overestimate this:
 * client names are self-asserted at HELLO, so a hostile process of the
 * same uid can claim to be this binary and approve its own requests.
 * Nothing name-based can prevent that — an AF_UNIX socket authenticates
 * a uid, not a binary, which is the entire reason this broker exists.
 * Confirmation is a user-visible speed bump in front of a *cooperative*
 * flagged client (the LLM agent). What bounds a hostile one is the
 * deny-list, the allowlist and the rate limiter.
 *
 * Deliberately a terminal program: it reads y/n from stdin and writes
 * the prompt to stdout. A desktop notification version is a nicety that
 * can be written later against the same three frames, and keeping the
 * first one a TTY program means it is scriptable and testable without a
 * compositor.
 */
#include "proto.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define HDR_SIZE (sizeof(struct uictl_frame_header))

static const char *opname(uint16_t op) {
  switch (op) {
  case OP_MOVE_ABS:
    return "move the pointer";
  case OP_KEY_TAP:
    return "tap a key";
  case OP_KEY_SEQUENCE:
    return "send a key sequence";
  case OP_KEY_DOWN:
    return "hold a key down";
  case OP_KEY_UP:
    return "release a key";
  default:
    return "do something";
  }
}

static const char *classname(uint16_t cl) {
  switch (cl) {
  case 1:
    return "standard";
  case 2:
    return "interactive";
  default:
    return "untrusted";
  }
}

static int dial(void) {
  const char *xdg = getenv("XDG_RUNTIME_DIR");
  if (!xdg) {
    fprintf(stderr, "uictl-confirm: XDG_RUNTIME_DIR is not set\n");
    return -1;
  }
  char path[108];
  int n = snprintf(path, sizeof(path), "%s/uictld.sock", xdg);
  if (n < 0 || (size_t)n >= sizeof(path)) {
    fprintf(stderr, "uictl-confirm: socket path too long\n");
    return -1;
  }
  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    perror("uictl-confirm: socket");
    return -1;
  }
  struct sockaddr_un addr = {.sun_family = AF_UNIX};
  strcpy(addr.sun_path, path);
  if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    fprintf(stderr,
            "uictl-confirm: cannot reach uictld at %s: %s\n"
            "  fix:  start the daemon first.\n",
            path, strerror(errno));
    close(fd);
    return -1;
  }
  return fd;
}

/* Read exactly one frame. Returns 0 on success, -1 on EOF or error.
   Unlike the CLI's read_response this does not match on seq: a confirmer
   receives frames it never asked for, which is the whole point. */
static int read_frame(int fd, struct uictl_frame_header *h, void *payload,
                      size_t cap) {
  char hdr_buf[HDR_SIZE];
  ssize_t got = read_full(fd, hdr_buf, HDR_SIZE);
  if (got != (ssize_t)HDR_SIZE)
    return -1;
  decode_frame_header(hdr_buf, h);
  if (h->payload_len > cap)
    return -1;
  if (h->payload_len &&
      read_full(fd, payload, h->payload_len) != (ssize_t)h->payload_len)
    return -1;
  return 0;
}

static int send_frame(int fd, uint16_t op, uint32_t seq, const void *payload,
                      size_t len) {
  struct uictl_frame_header h = {.version = UICTL_PROTO_VERSION,
                                 .opcode = op,
                                 .source_tag = SRC_CLI,
                                 .seq = seq,
                                 .payload_len = (uint32_t)len};
  char hdr_buf[HDR_SIZE];
  encode_frame_header(&h, hdr_buf);
  if (write_full(fd, hdr_buf, HDR_SIZE) < 0)
    return -1;
  if (len && write_full(fd, payload, len) < 0)
    return -1;
  return 0;
}

int main(int argc, char **argv) {
  const char *name = (argc > 1) ? argv[1] : "uictl-confirm";
  /* --yes answers every prompt without asking. It exists for tests and
     for a user who wants the audit trail without the interruption; it is
     NOT the default, because a confirmer that always says yes is the
     same as no confirmer at all and should have to be asked for. */
  int auto_yes = 0;
  for (int i = 1; i < argc; i++)
    if (strcmp(argv[i], "--yes") == 0) {
      auto_yes = 1;
      if (i == 1)
        name = "uictl-confirm";
    }

  int fd = dial();
  if (fd < 0)
    return 1;

  struct uictl_payload_hello hello = {.proto_min = UICTL_PROTO_MIN,
                                      .proto_max = UICTL_PROTO_MAX};
  size_t nlen = strlen(name);
  if (nlen >= sizeof(hello.client_name)) {
    fprintf(stderr, "uictl-confirm: name too long\n");
    return 1;
  }
  memcpy(hello.client_name, name, nlen);
  char hbuf[sizeof(hello)];
  encode_hello(&hello, hbuf);
  if (send_frame(fd, OP_HELLO, 1, hbuf, sizeof(hbuf)) < 0) {
    fprintf(stderr, "uictl-confirm: write hello\n");
    return 1;
  }

  struct uictl_frame_header h;
  char payload[UICTL_MAX_PAYLOAD];
  if (read_frame(fd, &h, payload, sizeof(payload)) < 0) {
    fprintf(stderr, "uictl-confirm: no response to hello\n");
    return 1;
  }
  uint16_t result;
  memcpy(&result, payload, sizeof(result));
  if (result != OK) {
    fprintf(stderr, "uictl-confirm: hello refused (result=%u)\n", result);
    return 1;
  }

  if (send_frame(fd, OP_CONFIRM_SUBSCRIBE, 2, NULL, 0) < 0) {
    fprintf(stderr, "uictl-confirm: write subscribe\n");
    return 1;
  }
  if (read_frame(fd, &h, payload, sizeof(payload)) < 0) {
    fprintf(stderr, "uictl-confirm: no response to subscribe\n");
    return 1;
  }
  memcpy(&result, payload, sizeof(result));
  if (result != OK) {
    fprintf(stderr,
            "uictl-confirm: subscribe refused (result=%u)\n"
            "  why:  the daemon only accepts a confirmer whose name "
            "carries the\n"
            "        `confirmer` role, and only one at a time\n"
            "  fix:  add a line `%s untrusted confirmer` to "
            "~/.config/uictl/clients\n"
            "        (mode 0600) and restart uictld. check `kill -USR1 "
            "$(pgrep -x uictld)`\n"
            "        for whether one is already subscribed.\n",
            result, name);
    return 1;
  }

  printf("uictl-confirm: subscribed as '%s'%s. waiting for requests.\n", name,
         auto_yes ? " (--yes: approving everything)" : "");
  fflush(stdout);

  uint32_t seq = 3;
  for (;;) {
    if (read_frame(fd, &h, payload, sizeof(payload)) < 0) {
      printf("uictl-confirm: daemon closed the connection\n");
      return 0;
    }
    if (h.opcode != OP_CONFIRM_REQUEST ||
        h.payload_len != sizeof(struct uictl_payload_confirm_req)) {
      /* Not a prompt: a late reply to something we sent. Ignore it
         rather than treat it as a protocol error — the daemon is allowed
         to answer us, and a confirmer that exits on a stray ack would be
         a fragile piece of the security path. */
      continue;
    }

    struct uictl_payload_confirm_req req;
    memcpy(&req, payload, sizeof(req));
    /* The name came off a socket. The daemon validated it before storing
       it, but this binary prints it to a terminal, so treat a missing
       terminator as hostile rather than trusting the length. */
    char safe_name[UICTL_CLIENT_NAME_MAX + 1];
    memcpy(safe_name, req.client_name, UICTL_CLIENT_NAME_MAX);
    safe_name[UICTL_CLIENT_NAME_MAX] = '\0';

    printf("\n--- uictl confirmation request ---\n"
           "  client:  %s (pid %u, class %s)\n"
           "  wants:   %s\n",
           safe_name, req.peer_pid, classname(req.cl), opname(req.opcode));
    if (req.keycode)
      printf("  keycode: %u\n", req.keycode);

    int allow = auto_yes;
    if (!auto_yes) {
      /* Newline-terminated, not a trailing-space prompt. A TTY user
         answers on the next line, which is marginally less pretty; a
         program reading this over a pipe gets a complete line instead of
         blocking forever on a prompt that never ends. The confirmer is
         a thing scripts and tests drive, so it prints in lines. */
      printf("  allow? [y/N]\n");
      fflush(stdout);
      char line[16];
      if (!fgets(line, sizeof(line), stdin)) {
        printf("\nuictl-confirm: stdin closed, denying\n");
        allow = 0;
      } else {
        allow = (line[0] == 'y' || line[0] == 'Y');
      }
    }

    struct uictl_payload_confirm_decide dec;
    memset(&dec, 0, sizeof(dec));
    dec.token = req.token;
    dec.allow = allow ? 1 : 0;
    if (send_frame(fd, OP_CONFIRM_DECIDE, seq++, &dec, sizeof(dec)) < 0) {
      fprintf(stderr, "uictl-confirm: write decision\n");
      return 1;
    }
    printf("  -> %s\n", allow ? "allowed" : "denied");
    fflush(stdout);
    /* The daemon acks the decision; read it so it does not sit in the
       receive buffer and get mistaken for the next prompt. */
    if (read_frame(fd, &h, payload, sizeof(payload)) < 0) {
      printf("uictl-confirm: daemon closed the connection\n");
      return 0;
    }
  }
}
