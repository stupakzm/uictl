#include "proto.h"
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

static void usage(const char *prog) {
  fprintf(stderr, "usage: %s ping\n", prog);
  fprintf(stderr, "       %s move-abs X Y\n", prog);
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

static int read_response(int sfd, uint16_t expected_opcode,
                         uint32_t expected_seq, uint16_t *result_out) {
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
  if (resp.payload_len != sizeof(uint16_t)) {
    fprintf(stderr, "uictl: unexpected payload length\n");
    return -1;
  }

  char result_buf[sizeof(uint16_t)];
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
  return 0;
}

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
  if (read_response(sfd, OP_PING, req.seq, &result) < 0) {
    return 1;
  }

  if (result != OK) {
    fprintf(stderr, "uictl: ping failed, result=%u\n", result);
    return 1;
  }

  if (write(STDOUT_FILENO, "PONG\n", 5) < 0) {
    perror("uictl: write stdout");
    return 1;
  }
  return 0;
}

static int cmd_move_abs(int sfd, int32_t x, int32_t y) {
  struct uictl_payload_move_abs mv = {.x = x, .y = y};
  struct uictl_frame_header req = {.version = UICTL_PROTO_VERSION,
                                   .opcode = OP_MOVE_ABS,
                                   .source_tag = SRC_CLI,
                                   .seq = 1,
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
  if (read_response(sfd, OP_MOVE_ABS, req.seq, &result) < 0) {
    return 1;
  }

  if (result != OK) {
    fprintf(stderr, "uictl: move-abs failed, result=%u\n", result);
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
