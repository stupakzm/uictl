#include "proto.h"
#include "platform/uinput.h" /* UINPUT_KEY_CODE_MAX */
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>

/* Result codes are numbers on the wire; a person reading a terminal
   wants the name. Kept in the client, not proto.h: the daemon must never
   grow a reason to render a result code, and a table it does not have is
   a table it cannot start logging instead of the audit line. */
static const char *result_name(uint16_t r) {
  switch (r) {
  case OK:
    return "OK";
  case ERR_VERSION:
    return "protocol version mismatch";
  case ERR_OPCODE_UNKNOWN:
    return "opcode not implemented";
  case ERR_PAYLOAD_INVALID:
    return "malformed request";
  case ERR_DENIED_BY_POLICY:
    return "denied by policy";
  case ERR_TOO_LARGE:
    return "payload too large";
  case ERR_INTERNAL:
    return "daemon internal error";
  case ERR_BUSY:
    return "daemon busy, retry";
  case ERR_HANDSHAKE_REQUIRED:
    return "handshake required";
  default:
    return "unknown result code";
  }
}

static void usage(const char *prog) {
  fprintf(stderr, "usage: %s ping\n", prog);
  fprintf(stderr, "       %s hello NAME\n", prog);
  fprintf(stderr, "       %s move-abs X Y\n", prog);
  fprintf(stderr, "       %s key-tap CODE\n", prog);
}

static int open_socket(void) {
  const char *xdg = getenv("XDG_RUNTIME_DIR");
  if (!xdg) {
    fprintf(stderr, "uictl: XDG_RUNTIME_DIR is not set\n");
    return -1;
  }

  char path[108];
  int n = snprintf(path, sizeof(path), "%s/uictld.sock", xdg);
  if (n < 0 || (size_t)n >= sizeof(path)) {
    fprintf(stderr, "uictl: socket path too long\n");
    return -1;
  }

  int sfd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (sfd < 0) {
    perror("uictl: socket");
    return -1;
  }

  struct sockaddr_un addr = {.sun_family = AF_UNIX};
  strcpy(addr.sun_path, path);

  if (connect(sfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    perror("uictl: connect");
    close(sfd);
    return -1;
  }

  return sfd;
}

static bool parse_int32(const char *s, int32_t *out) {
  if (*s == '\0')
    return false;
  errno = 0;
  char *end;
  long v = strtol(s, &end, 10);
  if (errno != 0)
    return false;
  if (*end != '\0')
    return false;
  if (v < INT32_MIN || v > INT32_MAX)
    return false;
  *out = (int32_t)v;
  return true;
}

/* Read one response frame.

   `data_out`/`data_cap` receive the opcode-specific answer that follows
   the result code (M3.6 task 1); pass NULL/0 for the commands that only
   ever get an acknowledgement, which is all of them until OP_HELLO.
   `data_len_out` may be NULL if the caller doesn't care.

   Note what is *not* attempted when the answer doesn't fit: the frame is
   not skipped to resynchronise the stream. Every path here that returns
   -1 is followed by the caller closing the connection, and reading bytes
   we have already decided we cannot handle only invites a hostile daemon
   to hold us there. A future long-lived client library will need the
   skip; a one-shot CLI must not pretend to recover. */
static int read_response(int sfd, uint16_t expected_opcode,
                         uint32_t expected_seq, uint16_t *result_out,
                         void *data_out, size_t data_cap,
                         size_t *data_len_out) {
  char resp_hdr_buf[sizeof(struct uictl_frame_header)];
  ssize_t rh = read_full(sfd, resp_hdr_buf, sizeof(resp_hdr_buf));
  if (rh < 0) {
    perror("uictl: read header");
    return -1;
  }
  if ((size_t)rh != sizeof(resp_hdr_buf)) {
    fprintf(stderr, "uictl: daemon closed mid-header\n");
    return -1;
  }

  struct uictl_frame_header resp;
  decode_frame_header(resp_hdr_buf, &resp);

  if (resp.opcode != expected_opcode) {
    fprintf(stderr, "uictl: daemon misframed\n");
    return -1;
  }
  if (resp.version != UICTL_PROTO_VERSION) {
    fprintf(stderr, "uictl: protocol mismatch\n");
    return -1;
  }
  if (resp.seq != expected_seq) {
    fprintf(stderr, "uictl: response/request mismatch\n");
    return -1;
  }
  /* Was `!= sizeof(uint16_t)`. The result code is still mandatory and
     still first, so the floor is unchanged; what used to be an exact
     length is now a minimum, because a response may carry an answer
     after it. The ceiling matters just as much: payload_len is a u32
     chosen by the peer and everything below sizes a read from it. */
  if (resp.payload_len < UICTL_RESULT_SIZE) {
    fprintf(stderr, "uictl: response too short to carry a result\n");
    return -1;
  }
  if (resp.payload_len > UICTL_MAX_PAYLOAD) {
    fprintf(stderr, "uictl: response payload too large\n");
    return -1;
  }

  char result_buf[UICTL_RESULT_SIZE];
  ssize_t rr = read_full(sfd, result_buf, sizeof(result_buf));
  if (rr < 0) {
    perror("uictl: read result");
    return -1;
  }
  if ((size_t)rr != sizeof(result_buf)) {
    fprintf(stderr, "uictl: daemon closed mid-result\n");
    return -1;
  }
  memcpy(result_out, result_buf, sizeof(*result_out));

  size_t data_len = resp.payload_len - UICTL_RESULT_SIZE;
  if (data_len > data_cap) {
    fprintf(stderr, "uictl: response carries %zu bytes, expected at most %zu\n",
            data_len, data_cap);
    return -1;
  }
  if (data_len) {
    ssize_t rd = read_full(sfd, data_out, data_len);
    if (rd < 0) {
      perror("uictl: read response payload");
      return -1;
    }
    if ((size_t)rd != data_len) {
      fprintf(stderr, "uictl: daemon closed mid-payload\n");
      return -1;
    }
  }
  if (data_len_out)
    *data_len_out = data_len;
  return 0;
}

/* Deliberately does NOT handshake: PING is exempt from the task 7
   requirement so it stays a bare liveness probe, and the CLI exercising
   that exemption is how we know it still works. */
static int cmd_ping(int sfd) {
  struct uictl_frame_header req = {.version = UICTL_PROTO_VERSION,
                                   .opcode = OP_PING,
                                   .payload_len = 0,
                                   .seq = 1,
                                   .source_tag = SRC_CLI};
  char req_hdr_buf[sizeof(struct uictl_frame_header)];
  encode_frame_header(&req, req_hdr_buf);

  if (write_full(sfd, req_hdr_buf, sizeof(req_hdr_buf)) < 0) {
    perror("uictl: write_full");
    return 1;
  }
  uint16_t result;
  if (read_response(sfd, OP_PING, req.seq, &result, NULL, 0, NULL) < 0) {
    return 1;
  }

  if (result != OK) {
    fprintf(stderr, "uictl: ping failed: %s (result=%u)\n",
            result_name(result), result);
    return 1;
  }

  if (write(STDOUT_FILENO, "PONG\n", 5) < 0) {
    perror("uictl: write stdout");
    return 1;
  }
  return 0;
}

/* Perform the handshake, optionally printing what the daemon answered.

   Since M3.6 task 7 the daemon requires this before any opcode that is
   not PING or HELLO, so this is no longer just the `hello` subcommand —
   it is the first thing every real command does. In a long-lived client
   it would live inside the connect path of a library (M-lib); here the
   CLI's one-shot connections each pay one extra round trip, which is
   the honest cost of the daemon knowing who it is talking to. */
static int client_hello(int sfd, const char *name, int verbose,
                        struct uictl_resp_hello *caps_out) {
  struct uictl_payload_hello hello = {.proto_min = UICTL_PROTO_MIN,
                                      .proto_max = UICTL_PROTO_MAX};

  size_t len = strlen(name);
  if (len >= sizeof(hello.client_name)) {
    fprintf(stderr, "uictl: client name must be under %zu characters\n",
            sizeof(hello.client_name));
    return 1;
  }
  /* hello is zero-initialised above, so the tail past the NUL stays
     zero — the daemon rejects junk hiding there. */
  memcpy(hello.client_name, name, len);
  if (!uictl_client_name_valid(hello.client_name)) {
    fprintf(stderr, "uictl: client name must be [A-Za-z0-9._-]\n");
    return 1;
  }

  struct uictl_frame_header req = {.version = UICTL_PROTO_VERSION,
                                   .opcode = OP_HELLO,
                                   .source_tag = SRC_CLI,
                                   .seq = 1,
                                   .payload_len = sizeof(hello)};
  char req_hdr_buf[sizeof(struct uictl_frame_header)];
  encode_frame_header(&req, req_hdr_buf);
  if (write_full(sfd, req_hdr_buf, sizeof(req_hdr_buf)) < 0) {
    fprintf(stderr, "uictl: write header\n");
    return 1;
  }

  char payload_buf[sizeof(hello)];
  encode_hello(&hello, payload_buf);
  if (write_full(sfd, payload_buf, sizeof(payload_buf)) < 0) {
    fprintf(stderr, "uictl: write payload\n");
    return 1;
  }

  /* Sized for the largest answer the daemon could legally send, not for
     the struct we know: the response is append-only, so a newer daemon
     may return a longer one and that must not be an error. */
  char data[UICTL_MAX_RESP_DATA];
  size_t data_len = 0;
  uint16_t result;
  if (read_response(sfd, OP_HELLO, req.seq, &result, data, sizeof(data),
                    &data_len) < 0)
    return 1;
  if (result != OK) {
    fprintf(stderr, "uictl: hello failed: %s (result=%u)\n",
            result_name(result), result);
    return 1;
  }
  /* >=, never ==. Short is a broken daemon; long is a newer one, and
     ignoring the tail we don't understand is what makes adding a
     capability field a non-event for old clients. */
  if (data_len < sizeof(struct uictl_resp_hello)) {
    fprintf(stderr, "uictl: hello response truncated (%zu bytes)\n", data_len);
    return 1;
  }

  struct uictl_resp_hello caps;
  decode_resp_hello(data, &caps);
  if (caps_out)
    *caps_out = caps;

  if (!verbose)
    return 0;

  printf("HELLO ok name=%s\n", hello.client_name);
  printf("  proto      %u (asked %u-%u)\n", caps.proto_selected,
         hello.proto_min, hello.proto_max);
  printf("  daemon     %u.%u.%u\n", (caps.daemon_version >> 16) & 0xff,
         (caps.daemon_version >> 8) & 0xff, caps.daemon_version & 0xff);
  printf("  abs range  0..%u\n", caps.abs_range_max);
  printf("  device     %s%s%s%s\n",
         (caps.device_caps & CAP_POINTER_ABS) ? "pointer-abs " : "",
         (caps.device_caps & CAP_KEYBOARD) ? "keyboard " : "",
         (caps.device_caps & CAP_POINTER_REL) ? "pointer-rel " : "",
         (caps.device_caps & CAP_BUTTONS) ? "buttons" : "");
  printf("  opcodes    %s%s%s%s\n",
         (caps.opcode_bitmap & UICTL_OP_BIT(OP_PING)) ? "ping " : "",
         (caps.opcode_bitmap & UICTL_OP_BIT(OP_MOVE_ABS)) ? "move-abs " : "",
         (caps.opcode_bitmap & UICTL_OP_BIT(OP_HELLO)) ? "hello " : "",
         (caps.opcode_bitmap & UICTL_OP_BIT(OP_KEY_TAP)) ? "key-tap" : "");
  return 0;
}

/* `uictl key-tap <code>` (M4 step 4).

   Gates on `opcode_bitmap` rather than trying and hoping. That is the
   pattern every client is supposed to follow — the bitmap is the
   contract, `device_caps` only says the hardware side is ready — and
   this is the first place the CLI actually uses it. Until step 7
   advertises OP_KEY_TAP the command refuses locally and says exactly
   what is missing, which beats sending a frame and printing an opaque
   "result=2". */
static int cmd_key_tap(int sfd, int32_t code) {
  if (code < 1 || code > UINPUT_KEY_CODE_MAX) {
    fprintf(stderr, "uictl: keycode must be 1..%d\n", UINPUT_KEY_CODE_MAX);
    return 1;
  }

  struct uictl_resp_hello caps;
  if (client_hello(sfd, "uictl", 0, &caps) != 0)
    return 1;

  if (!(caps.opcode_bitmap & UICTL_OP_BIT(OP_KEY_TAP))) {
    fprintf(stderr,
            "uictl: this daemon does not advertise key-tap "
            "(opcode_bitmap=0x%llx). key injection is wired in M4 step 7, "
            "after the deny-list.\n",
            (unsigned long long)caps.opcode_bitmap);
    return 1;
  }

  struct uictl_payload_key key = {.keycode = (uint16_t)code};
  struct uictl_frame_header req = {.version = UICTL_PROTO_VERSION,
                                   .opcode = OP_KEY_TAP,
                                   .source_tag = SRC_CLI,
                                   .seq = 2, /* 1 was the handshake */
                                   .payload_len = sizeof(key)};
  char req_hdr_buf[sizeof(struct uictl_frame_header)];
  encode_frame_header(&req, req_hdr_buf);
  if (write_full(sfd, req_hdr_buf, sizeof(req_hdr_buf)) < 0) {
    fprintf(stderr, "uictl: write header\n");
    return 1;
  }
  char payload_buf[sizeof(key)];
  encode_key(&key, payload_buf);
  if (write_full(sfd, payload_buf, sizeof(payload_buf)) < 0) {
    fprintf(stderr, "uictl: write payload\n");
    return 1;
  }

  uint16_t result;
  if (read_response(sfd, OP_KEY_TAP, req.seq, &result, NULL, 0, NULL) < 0)
    return 1;
  if (result != OK) {
    fprintf(stderr, "uictl: key-tap failed: %s (result=%u)\n",
            result_name(result), result);
    return 1;
  }
  printf("OK seq=%u code=%d\n", req.seq, code);
  return 0;
}

static int cmd_move_abs(int sfd, int32_t x, int32_t y) {
  /* Not optional since task 7: MOVE_ABS before HELLO is refused with
     ERR_HANDSHAKE_REQUIRED. The name is what the daemon looks up in its
     client registry to decide this connection's class. */
  if (client_hello(sfd, "uictl", 0, NULL) != 0)
    return 1;

  struct uictl_payload_move_abs mv = {.x = x, .y = y};
  struct uictl_frame_header req = {.version = UICTL_PROTO_VERSION,
                                   .opcode = OP_MOVE_ABS,
                                   .source_tag = SRC_CLI,
                                   /* 2: the handshake above was seq 1 on
                                      this same connection. */
                                   .seq = 2,
                                   .payload_len = sizeof(mv)};
  char req_hdr_buf[sizeof(struct uictl_frame_header)];
  encode_frame_header(&req, req_hdr_buf);
  if (write_full(sfd, req_hdr_buf, sizeof(req_hdr_buf)) < 0) {
    fprintf(stderr, "uictl: write header\n");
    return 1;
  }

  char payload_buf[sizeof(mv)];
  encode_move_abs(&mv, payload_buf);

  if (write_full(sfd, payload_buf, sizeof(payload_buf)) < 0) {
    fprintf(stderr, "uictl: write payload\n");
    return 1;
  }

  uint16_t result;
  if (read_response(sfd, OP_MOVE_ABS, req.seq, &result, NULL, 0, NULL) < 0) {
    return 1;
  }

  if (result != OK) {
    fprintf(stderr, "uictl: move-abs failed: %s (result=%u)\n",
            result_name(result), result);
    return 1;
  }

  printf("OK seq=%u\n", req.seq);
  return 0;
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    usage(argv[0]);
    return 1;
  }

  if (strcmp(argv[1], "ping") == 0) {
    if (argc != 2) {
      usage(argv[0]);
      return 1;
    }
    int sfd = open_socket();
    if (sfd < 0)
      return 1;
    int rc = cmd_ping(sfd);
    close(sfd);
    return rc;
  }

  if (strcmp(argv[1], "hello") == 0) {
    if (argc != 3) {
      usage(argv[0]);
      return 1;
    }
    int sfd = open_socket();
    if (sfd < 0)
      return 1;
    int rc = client_hello(sfd, argv[2], 1, NULL);
    close(sfd);
    return rc;
  }

  if (strcmp(argv[1], "key-tap") == 0) {
    if (argc != 3) {
      usage(argv[0]);
      return 1;
    }
    int32_t code;
    if (!parse_int32(argv[2], &code)) {
      fprintf(stderr, "uictl: bad keycode\n");
      return 1;
    }
    int sfd = open_socket();
    if (sfd < 0)
      return 1;
    int rc = cmd_key_tap(sfd, code);
    close(sfd);
    return rc;
  }

  if (strcmp(argv[1], "move-abs") == 0) {
    if (argc != 4) {
      usage(argv[0]);
      return 1;
    }
    int32_t x, y;
    if (!parse_int32(argv[2], &x)) {
      fprintf(stderr, "uictl: bad X\n");
      return 1;
    }
    if (!parse_int32(argv[3], &y)) {
      fprintf(stderr, "uictl: bad Y\n");
      return 1;
    }
    int sfd = open_socket();
    if (sfd < 0)
      return 1;
    int rc = cmd_move_abs(sfd, x, y);
    close(sfd);
    return rc;
  }

  usage(argv[0]);
  return 1;
}
