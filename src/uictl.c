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
  case ERR_KEY_DENYLISTED:
    return "keycode is on the built-in deny-list";
  case ERR_KEY_NOT_ALLOWED:
    return "keycode is not in your policy file";
  case ERR_RATE_LIMITED:
    return "sending faster than your class allows";
  case ERR_KEY_ALREADY_HELD:
    return "you already hold that keycode";
  case ERR_KEY_HELD_BY_OTHER:
    return "another client is holding that keycode";
  case ERR_KEY_NOT_HELD:
    return "you do not hold that keycode";
  case ERR_TOO_MANY_HELD:
    return "too many keys held at once";
  case ERR_CONFIRM_UNAVAILABLE:
    return "this client needs confirmation and no confirmer is running";
  case ERR_CONFIRM_DENIED:
    return "the user declined";
  case ERR_CONFIRM_TIMEOUT:
    return "nobody answered the confirmation prompt";
  case ERR_NOT_CONFIRMER:
    return "not allowed to act as the confirmer";
  default:
    return "unknown result code";
  }
}

/* What to DO about a result code.

   A refusal that only says "denied" leaves the user to guess whether
   they hit a wall or a config gap — and those call for opposite actions.
   Every failure path here answers two questions: what happened, and what
   would make it work. Where nothing would, it says so plainly instead of
   sending someone to edit a file that cannot help.

   `detail` carries the request-specific bit (a keycode, usually) so the
   advice can be concrete enough to copy. */
static void explain(uint16_t result, long detail) {
  switch (result) {
  case ERR_KEY_DENYLISTED:
    fprintf(stderr,
            "  why:  keycode %ld is on uictld's built-in destructive-key "
            "deny-list\n"
            "  fix:  none — this list is static and configuration cannot "
            "unlock it.\n"
            "        it covers power/suspend/restart, SysRq, radio kills, "
            "brightness,\n"
            "        eject, and the Fn/braille/numeric blocks.\n",
            detail);
    break;
  case ERR_KEY_NOT_ALLOWED:
    fprintf(stderr,
            "  why:  keycode %ld is not listed in ~/.config/uictl/policy\n"
            "  fix:  add a line `%ld` to that file (create it mode 0600), "
            "then restart uictld.\n"
            "        ranges work too: `183-194`. an absent or empty policy "
            "file means\n"
            "        NO keys at all — that is deliberate default-deny, not "
            "a bug.\n",
            detail, detail);
    break;
  case ERR_DENIED_BY_POLICY:
    fprintf(stderr,
            "  why:  the daemon refused this peer\n"
            "  fix:  uictld only serves connections from its own uid. check "
            "you are\n"
            "        running as the same user that started it (`id`, "
            "`pgrep -a uictld`).\n");
    break;
  case ERR_HANDSHAKE_REQUIRED:
    fprintf(stderr,
            "  why:  the daemon requires OP_HELLO before this opcode\n"
            "  fix:  this is a client bug — every command except `ping` "
            "must handshake\n"
            "        first. report it.\n");
    break;
  case ERR_RATE_LIMITED:
    fprintf(stderr,
            "  why:  this process exceeded the request rate for its client "
            "class\n"
            "  fix:  pace the requests — retrying immediately makes it "
            "worse, the bucket\n"
            "        refills over time. limits are 5/s untrusted, 20/s "
            "standard,\n"
            "        50/s interactive. to get a higher class, add a line "
            "like\n"
            "        `myclient interactive` to ~/.config/uictl/clients "
            "(mode 0600),\n"
            "        restart uictld, and have the client send that name in "
            "its HELLO.\n");
    break;
  case ERR_BUSY:
    fprintf(stderr,
            "  why:  no connection slot right now (32 total, 4 per "
            "process)\n"
            "  fix:  retry in a moment. if it persists, `kill -USR1 $(pgrep "
            "-x uictld)`\n"
            "        prints the connection table to the daemon's stderr — "
            "look for a\n"
            "        client holding slots it is not using.\n");
    break;
  case ERR_OPCODE_UNKNOWN:
    fprintf(stderr,
            "  why:  this daemon does not implement that request\n"
            "  fix:  it is older than this client. rebuild and restart "
            "uictld;\n"
            "        `uictl hello NAME` lists what it does support.\n");
    break;
  case ERR_VERSION:
    fprintf(stderr,
            "  why:  no protocol version in common with the daemon\n"
            "  fix:  rebuild both binaries from the same tree and restart "
            "uictld.\n");
    break;
  case ERR_PAYLOAD_INVALID:
    fprintf(stderr,
            "  why:  the daemon rejected the request's contents\n"
            "  fix:  for key-tap, keycodes run 1..%d. otherwise this is a "
            "client bug.\n",
            UINPUT_KEY_CODE_MAX);
    break;
  case ERR_TOO_LARGE:
    fprintf(stderr, "  why:  the request exceeded the daemon's payload "
                    "limit\n  fix:  send fewer items per request.\n");
    break;
  /* The held-state refusals. Three of the four are client bugs, and the
     advice says so rather than inventing a workaround — a client that
     has lost track of what it holds cannot be fixed from the outside. */
  case ERR_KEY_ALREADY_HELD:
    fprintf(stderr,
            "  why:  this connection already holds keycode %ld\n"
            "  fix:  client bug — send the key-up you owe before pressing "
            "again.\n"
            "        the daemon does not model auto-repeat; a second "
            "key-down is\n"
            "        never what you want.\n",
            detail);
    break;
  case ERR_KEY_HELD_BY_OTHER:
    fprintf(stderr,
            "  why:  a different client is holding keycode %ld right now\n"
            "  fix:  wait and retry — it is mid-gesture, and two clients "
            "holding one\n"
            "        key means whoever releases first releases it for both. "
            "`kill -USR1\n"
            "        $(pgrep -x uictld)` shows which connection holds what.\n",
            detail);
    break;
  case ERR_KEY_NOT_HELD:
    fprintf(stderr,
            "  why:  this connection does not hold keycode %ld\n"
            "  fix:  none needed — the key is up, which is what you asked "
            "for. either\n"
            "        you released it twice, or the daemon's dead-man timer "
            "already\n"
            "        force-released it (a hold may not outlive 30s).\n",
            detail);
    break;
  case ERR_CONFIRM_UNAVAILABLE:
    fprintf(stderr,
            "  why:  this client's name carries the `confirm` role, so its "
            "requests\n"
            "        wait for a human — and no confirmer is subscribed\n"
            "  fix:  run `uictl-confirm NAME` in a terminal, where NAME has "
            "the\n"
            "        `confirmer` role in ~/.config/uictl/clients. it fails "
            "closed on\n"
            "        purpose: no prompter means no approval, not automatic "
            "approval.\n");
    break;
  case ERR_CONFIRM_DENIED:
    fprintf(stderr, "  why:  a human was asked and said no\n"
                    "  fix:  none — asking again is asking twice. do "
                    "something else.\n");
    break;
  case ERR_CONFIRM_TIMEOUT:
    fprintf(stderr,
            "  why:  the confirmation prompt went unanswered\n"
            "  fix:  retry if you expect someone to be at the keyboard. a "
            "timeout\n"
            "        is always a denial, never a silent approval.\n");
    break;
  case ERR_NOT_CONFIRMER:
    fprintf(stderr,
            "  why:  only a client whose registry entry carries the "
            "`confirmer`\n"
            "        role may subscribe, and only one at a time\n"
            "  fix:  add `NAME untrusted confirmer` to "
            "~/.config/uictl/clients (mode\n"
            "        0600) and restart uictld. `kill -USR1 $(pgrep -x "
            "uictld)` shows\n"
            "        whether one is already subscribed.\n");
    break;
  case ERR_TOO_MANY_HELD:
    fprintf(stderr,
            "  why:  this connection is already holding the maximum number "
            "of keys\n"
            "  fix:  release some. no real gesture needs more than a "
            "handful down at\n"
            "        once; if yours does, it probably wants key-combo "
            "instead.\n");
    break;
  case ERR_INTERNAL:
    fprintf(stderr,
            "  why:  the daemon failed while performing the action\n"
            "  fix:  check uictld's stderr — the device write failed, which "
            "usually\n"
            "        means /dev/uinput went away (module unloaded, device "
            "destroyed).\n");
    break;
  default:
    break;
  }
}

static void usage(const char *prog) {
  fprintf(stderr, "usage: %s ping\n", prog);
  fprintf(stderr, "       %s hello NAME\n", prog);
  fprintf(stderr, "       %s move-abs X Y\n", prog);
  fprintf(stderr, "       %s key-tap CODE\n", prog);
  fprintf(stderr, "       %s key-combo CODE [CODE...]   (e.g. 29 30 = "
                  "Ctrl+A)\n", prog);
  fprintf(stderr, "       %s click BUTTON             (272=left 273=right "
                  "274=middle)\n", prog);
  fprintf(stderr, "       %s move-rel DX DY           (device units, not "
                  "pixels)\n", prog);
  fprintf(stderr, "       %s scroll VERT [HORIZ]      (wheel notches, + is "
                  "up/right)\n", prog);
  /* No `button-down` / `button-up`, for the same reason there is no
     `key-down`: this process exits, the connection closes, and the
     daemon releases the hold. `click` is what a one-shot can honestly
     offer. */
}

static int open_socket(void) {
  const char *xdg = getenv("XDG_RUNTIME_DIR");
  if (!xdg) {
    fprintf(stderr, "uictl: XDG_RUNTIME_DIR is not set\n"
                    "  why:  the socket lives in the per-user runtime "
                    "directory\n"
                    "  fix:  run inside a normal login session, or set it "
                    "to the same\n"
                    "        directory uictld used.\n");
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
    fprintf(stderr, "uictl: cannot reach the daemon at %s: %s\n", path,
            strerror(errno));
    if (errno == ENOENT || errno == ECONNREFUSED)
      fprintf(stderr, "  fix:  uictld is not running. start it "
                      "(`./uictld`) and try again.\n");
    else if (errno == EACCES)
      fprintf(stderr, "  fix:  the socket belongs to another user. uictld "
                      "serves only its own uid.\n");
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
    fprintf(stderr, "uictl: ping failed: %s\n", result_name(result));
    explain(result, 0);
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
    fprintf(stderr,
            "uictl: client name '%s' is not usable\n"
            "  why:  names go into the audit log, so only [A-Za-z0-9._-] "
            "are accepted\n"
            "        (a newline would let a client forge log lines)\n"
            "  fix:  use a plain name, e.g. `muvor` or `auto-c`.\n",
            name);
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
    fprintf(stderr, "uictl: hello failed: %s\n", result_name(result));
    explain(result, 0);
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
  /* key-down/key-up appear here with no matching subcommand below, and
     that is not an omission. The daemon releases everything a connection
     holds when it closes, so a one-shot CLI that presses a key and exits
     has written an elaborate key-tap. They are advertised because
     long-lived clients — muvor, auto-c — are who they are for. */
  printf("  opcodes    %s%s%s%s%s%s%s\n",
         (caps.opcode_bitmap & UICTL_OP_BIT(OP_PING)) ? "ping " : "",
         (caps.opcode_bitmap & UICTL_OP_BIT(OP_MOVE_ABS)) ? "move-abs " : "",
         (caps.opcode_bitmap & UICTL_OP_BIT(OP_HELLO)) ? "hello " : "",
         (caps.opcode_bitmap & UICTL_OP_BIT(OP_KEY_TAP)) ? "key-tap " : "",
         (caps.opcode_bitmap & UICTL_OP_BIT(OP_KEY_SEQUENCE)) ? "key-seq " : "",
         (caps.opcode_bitmap & UICTL_OP_BIT(OP_KEY_DOWN)) ? "key-down " : "",
         (caps.opcode_bitmap & UICTL_OP_BIT(OP_KEY_UP)) ? "key-up " : "");
  printf("             %s%s%s%s%s\n",
         (caps.opcode_bitmap & UICTL_OP_BIT(OP_BUTTON)) ? "button " : "",
         (caps.opcode_bitmap & UICTL_OP_BIT(OP_MOVE_REL)) ? "move-rel " : "",
         (caps.opcode_bitmap & UICTL_OP_BIT(OP_SCROLL)) ? "scroll " : "",
         (caps.opcode_bitmap & UICTL_OP_BIT(OP_BATCH)) ? "batch " : "",
         (caps.opcode_bitmap & UICTL_OP_BIT(OP_CONFIRM_SUBSCRIBE))
             ? "confirm"
             : "");
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
    fprintf(stderr,
            "uictl: keycode %d is out of range\n"
            "  why:  the kernel's keycodes run 1..%d (0 is KEY_RESERVED)\n"
            "  fix:  see /usr/include/linux/input-event-codes.h — e.g. 30 "
            "is KEY_A,\n"
            "        183 is KEY_F13.\n",
            code, UINPUT_KEY_CODE_MAX);
    return 1;
  }

  struct uictl_resp_hello caps;
  if (client_hello(sfd, "uictl", 0, &caps) != 0)
    return 1;

  if (!(caps.opcode_bitmap & UICTL_OP_BIT(OP_KEY_TAP))) {
    fprintf(stderr,
            "uictl: this daemon does not offer key-tap\n"
            "  why:  it did not advertise the opcode (bitmap=0x%llx)\n"
            "  fix:  it is an older build. rebuild and restart uictld.\n",
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
    fprintf(stderr, "uictl: key-tap %d failed: %s\n", code,
            result_name(result));
    explain(result, code);
    return 1;
  }
  printf("OK seq=%u code=%d\n", req.seq, code);
  return 0;
}

/* `uictl key-combo MOD... KEY` — press every code in order, then release
   them in reverse. Ctrl+A is `key-combo 29 30`.

   The CLI only offers this shape, not arbitrary sequences, because it is
   the shape that is always balanced by construction: the user cannot ask
   for something the daemon will reject as unbalanced. The wire is more
   general (any list of press/release items) for clients that need it. */
static int cmd_key_combo(int sfd, const int32_t *codes, int n) {
  if (n < 1 || n * 2 > UICTL_SEQ_MAX) {
    fprintf(stderr,
            "uictl: %d key(s) is out of range\n"
            "  why:  a combo becomes 2 events per key and a sequence "
            "carries at most %d\n"
            "  fix:  use at most %d keys per combo.\n",
            n, UICTL_SEQ_MAX, UICTL_SEQ_MAX / 2);
    return 1;
  }
  for (int i = 0; i < n; i++) {
    if (codes[i] < 1 || codes[i] > UINPUT_KEY_CODE_MAX) {
      fprintf(stderr,
              "uictl: keycode %d is out of range\n"
              "  why:  the kernel's keycodes run 1..%d (0 is "
              "KEY_RESERVED)\n"
              "  fix:  see /usr/include/linux/input-event-codes.h — 29 is "
              "KEY_LEFTCTRL,\n        30 is KEY_A.\n",
              codes[i], UINPUT_KEY_CODE_MAX);
      return 1;
    }
    for (int j = 0; j < i; j++)
      if (codes[j] == codes[i]) {
        fprintf(stderr,
                "uictl: keycode %d appears twice\n"
                "  why:  a combo presses each key once; pressing a held "
                "key is refused\n"
                "  fix:  list each keycode at most once.\n",
                codes[i]);
        return 1;
      }
  }

  struct uictl_resp_hello caps;
  if (client_hello(sfd, "uictl", 0, &caps) != 0)
    return 1;
  if (!(caps.opcode_bitmap & UICTL_OP_BIT(OP_KEY_SEQUENCE))) {
    fprintf(stderr,
            "uictl: this daemon does not offer key sequences\n"
            "  why:  it did not advertise the opcode (bitmap=0x%llx)\n"
            "  fix:  it is an older build. rebuild and restart uictld.\n",
            (unsigned long long)caps.opcode_bitmap);
    return 1;
  }

  uint16_t count = (uint16_t)(n * 2);
  char payload[sizeof(struct uictl_payload_key_seq) +
               UICTL_SEQ_MAX * sizeof(struct uictl_seq_item)];
  memset(payload, 0, sizeof(payload));
  struct uictl_payload_key_seq shdr = {.count = count, .reserved = 0};
  memcpy(payload, &shdr, sizeof(shdr));

  size_t off = sizeof(shdr);
  for (int i = 0; i < n; i++) { /* press in order */
    struct uictl_seq_item it = {.keycode = (uint16_t)codes[i], .value = 1};
    memcpy(payload + off, &it, sizeof(it));
    off += sizeof(it);
  }
  for (int i = n - 1; i >= 0; i--) { /* release in reverse */
    struct uictl_seq_item it = {.keycode = (uint16_t)codes[i], .value = 0};
    memcpy(payload + off, &it, sizeof(it));
    off += sizeof(it);
  }

  struct uictl_frame_header req = {.version = UICTL_PROTO_VERSION,
                                   .opcode = OP_KEY_SEQUENCE,
                                   .source_tag = SRC_CLI,
                                   .seq = 2,
                                   .payload_len = (uint32_t)off};
  char req_hdr_buf[sizeof(struct uictl_frame_header)];
  encode_frame_header(&req, req_hdr_buf);
  if (write_full(sfd, req_hdr_buf, sizeof(req_hdr_buf)) < 0 ||
      write_full(sfd, payload, off) < 0) {
    fprintf(stderr, "uictl: write request\n");
    return 1;
  }

  uint16_t result;
  if (read_response(sfd, OP_KEY_SEQUENCE, req.seq, &result, NULL, 0, NULL) < 0)
    return 1;
  if (result != OK) {
    fprintf(stderr, "uictl: key-combo failed: %s\n", result_name(result));
    /* The keycode in the message is the first one; the daemon rejects on
       the first offending item, and for a 2-key combo that is nearly
       always the modifier or the key itself. */
    explain(result, codes[0]);
    return 1;
  }
  printf("OK seq=%u (%d keys)\n", req.seq, n);
  return 0;
}

/* One shape for every simple M5.5 command: handshake, send a fixed-size
   payload, read one result. They differ only in opcode, payload and the
   name in the error message, so they share a helper rather than being
   four copies of cmd_move_abs with three words changed. */
static int simple_cmd(int sfd, uint16_t opcode, const char *label,
                      const void *payload, size_t len, long detail) {
  if (client_hello(sfd, "uictl", 0, NULL) != 0)
    return 1;
  struct uictl_frame_header req = {.version = UICTL_PROTO_VERSION,
                                   .opcode = opcode,
                                   .source_tag = SRC_CLI,
                                   .seq = 2, /* the handshake was seq 1 */
                                   .payload_len = (uint32_t)len};
  char hdr_buf[sizeof(struct uictl_frame_header)];
  encode_frame_header(&req, hdr_buf);
  if (write_full(sfd, hdr_buf, sizeof(hdr_buf)) < 0 ||
      (len && write_full(sfd, payload, len) < 0)) {
    fprintf(stderr, "uictl: write %s\n", label);
    return 1;
  }
  uint16_t result;
  if (read_response(sfd, opcode, req.seq, &result, NULL, 0, NULL) < 0)
    return 1;
  if (result != OK) {
    fprintf(stderr, "uictl: %s failed: %s\n", label, result_name(result));
    explain(result, detail);
    return 1;
  }
  printf("OK seq=%u\n", req.seq);
  return 0;
}

/* `uictl click BUTTON` presses and releases in one connection, because a
   one-shot CLI cannot hold anything: the daemon releases everything a
   connection holds the moment it closes (M4.5 task 2), so a bare
   `button down` from a process that then exits is a click with extra
   steps. Holding across requests is what long-lived clients use
   OP_BUTTON's two halves for. Sent as a BATCH so the press and release
   are validated together. */
static int cmd_click(int sfd, uint16_t code) {
  struct {
    struct uictl_payload_batch h;
    struct uictl_batch_item items[2];
  } b;
  memset(&b, 0, sizeof(b));
  b.h.count = 2;
  b.items[0].opcode = OP_BUTTON;
  b.items[0].a = code;
  b.items[0].b = 1;
  b.items[1].opcode = OP_BUTTON;
  b.items[1].a = code;
  b.items[1].b = 0;
  return simple_cmd(sfd, OP_BATCH, "click", &b, sizeof(b), code);
}

static int cmd_move_rel(int sfd, int32_t dx, int32_t dy) {
  struct uictl_payload_move_rel mv = {.dx = dx, .dy = dy};
  return simple_cmd(sfd, OP_MOVE_REL, "move-rel", &mv, sizeof(mv), 0);
}

static int cmd_scroll(int sfd, int32_t v, int32_t h) {
  struct uictl_payload_scroll sc = {.notches_v = v, .notches_h = h};
  return simple_cmd(sfd, OP_SCROLL, "scroll", &sc, sizeof(sc), 0);
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
    fprintf(stderr, "uictl: move-abs failed: %s\n", result_name(result));
    explain(result, 0);
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

  if (strcmp(argv[1], "key-combo") == 0) {
    if (argc < 3) {
      usage(argv[0]);
      return 1;
    }
    int32_t codes[UICTL_SEQ_MAX];
    int n = argc - 2;
    if (n > (int)(sizeof(codes) / sizeof(codes[0]))) {
      fprintf(stderr, "uictl: too many keys\n");
      return 1;
    }
    for (int i = 0; i < n; i++) {
      if (!parse_int32(argv[2 + i], &codes[i])) {
        fprintf(stderr, "uictl: '%s' is not a keycode\n", argv[2 + i]);
        return 1;
      }
    }
    int sfd = open_socket();
    if (sfd < 0)
      return 1;
    int rc = cmd_key_combo(sfd, codes, n);
    close(sfd);
    return rc;
  }

  if (strcmp(argv[1], "click") == 0) {
    if (argc != 3) {
      usage(argv[0]);
      return 1;
    }
    int32_t code;
    if (!parse_int32(argv[2], &code) || code < 0 || code > 0xffff) {
      fprintf(stderr, "uictl: bad BUTTON\n");
      return 1;
    }
    int sfd = open_socket();
    if (sfd < 0)
      return 1;
    int rc = cmd_click(sfd, (uint16_t)code);
    close(sfd);
    return rc;
  }

  if (strcmp(argv[1], "move-rel") == 0) {
    if (argc != 4) {
      usage(argv[0]);
      return 1;
    }
    int32_t dx, dy;
    if (!parse_int32(argv[2], &dx) || !parse_int32(argv[3], &dy)) {
      fprintf(stderr, "uictl: bad DX/DY\n");
      return 1;
    }
    int sfd = open_socket();
    if (sfd < 0)
      return 1;
    int rc = cmd_move_rel(sfd, dx, dy);
    close(sfd);
    return rc;
  }

  if (strcmp(argv[1], "scroll") == 0) {
    if (argc != 3 && argc != 4) {
      usage(argv[0]);
      return 1;
    }
    int32_t v, h = 0;
    if (!parse_int32(argv[2], &v) ||
        (argc == 4 && !parse_int32(argv[3], &h))) {
      fprintf(stderr, "uictl: bad notch count\n");
      return 1;
    }
    int sfd = open_socket();
    if (sfd < 0)
      return 1;
    int rc = cmd_scroll(sfd, v, h);
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
