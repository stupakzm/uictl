// never use htonl/htons/ntohl/ntohs, that is for TCP/IP
#pragma once

#include <endian.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#define UICTL_PROTO_VERSION 1
#define UICTL_MAX_PAYLOAD 4096

enum uictl_op { OP_INVALID = 0, OP_PING, OP_MOVE_ABS };
enum uictl_result {
  OK = 0,
  ERR_VERSION,
  ERR_OPCODE_UNKNOWN,
  ERR_PAYLOAD_INVALID,
  ERR_DENIED_BY_POLICY,
  ERR_TOO_LARGE,
  ERR_INTERNAL
};

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

_Static_assert(sizeof(struct uictl_frame_header) == 16,
               "frame header must be exactly 16 bytes");

struct uictl_payload_move_abs {
  int32_t x;
  int32_t y;
};

_Static_assert(sizeof(struct uictl_payload_move_abs) == 8,
               "MOVE_ABS payload must be exactly 8 bytes");

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
