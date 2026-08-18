/* gen_vectors — emits WIRE.md §9's conformance vectors (M-lib task 5).
 *
 * The vectors are GENERATED, not typed. Every offset, size and enum
 * value comes from src/proto.h, so a field that moves in the header
 * moves in the document, and `make gen-vectors` plus
 * tests/test_wire9_vectors.py turns "the spec drifted from the code"
 * from a thing a reader might notice into a test that fails.
 *
 * plan-multiclient.md open question 5 asked whether the vectors should
 * be hex frames plus an expected decode, or a replay mode inside the
 * daemon. Hex, decisively: a test mode in a security binary is a code
 * path that exists in production for the benefit of tests, and this
 * broker's whole claim is that it has no such paths. A hex file also
 * works for an implementor in Rust or Go who is not running the daemon
 * yet, which is the case M-lib exists to serve.
 *
 * Output is the body between the two HTML markers in §9, and nothing
 * else — the prose around it is hand-written and stable.
 */
#include "../src/proto.h"

#include <stdio.h>
#include <string.h>

/* From <linux/input-event-codes.h>. Written as a literal rather than
   included: scope discipline keeps kernel headers inside src/platform,
   and a vector file that pulled in the kernel's headers would stop
   building for the non-Linux reader who is implementing a client. */
#define BTN_LEFT_ 0x110
#define KEY_LEFTCTRL_ 29
#define KEY_A_ 30
#define KEY_F13_ 183

/* Trailing spaces are trimmed. Not cosmetic: this output is diffed
   against WIRE.md by tests/test_wire9_vectors.py, and an editor that
   strips trailing whitespace on save would otherwise make the document
   permanently "drifted" from the generator. */
static void hexdump(const void *buf, size_t n) {
  const unsigned char *p = buf;
  char line[80];
  puts("```");
  for (size_t off = 0; off < n; off += 16) {
    int w = snprintf(line, sizeof(line), "%04zx ", off);
    for (size_t i = 0; i < 16 && off + i < n; i++) {
      if (i % 8 == 0)
        w += snprintf(line + w, sizeof(line) - (size_t)w, " ");
      w += snprintf(line + w, sizeof(line) - (size_t)w, "%02x ",
                    p[off + i]);
    }
    while (w > 0 && line[w - 1] == ' ')
      line[--w] = '\0';
    puts(line);
  }
  puts("```");
}

/* A frame is a header plus payload bytes, contiguous, exactly as it goes
   on the socket. Nothing here pads or aligns: the header is 16 bytes and
   every payload struct is asserted to its exact size in proto.h. */
static size_t frame(unsigned char *out, uint16_t version, uint16_t opcode,
                    uint32_t source_tag, uint32_t seq, const void *payload,
                    size_t plen) {
  struct uictl_frame_header h = {.version = version,
                                 .opcode = opcode,
                                 .source_tag = source_tag,
                                 .seq = seq,
                                 .payload_len = (uint32_t)plen};
  encode_frame_header(&h, out);
  if (plen)
    memcpy(out + sizeof(h), payload, plen);
  return sizeof(h) + plen;
}

/* A response is the request's header echoed with payload_len rewritten,
   then u16 result, then opcode-specific data (§2.4). Built here the same
   way the daemon builds it, from the request header, so a vector cannot
   silently stop being an echo. */
static size_t response(unsigned char *out, const unsigned char *request,
                       uint16_t result, const void *data, size_t dlen) {
  struct uictl_frame_header h;
  decode_frame_header(request, &h);
  h.payload_len = (uint32_t)(UICTL_RESULT_SIZE + dlen);
  encode_frame_header(&h, out);
  memcpy(out + sizeof(h), &result, sizeof(result));
  if (dlen)
    memcpy(out + sizeof(h) + sizeof(result), data, dlen);
  return sizeof(h) + sizeof(result) + dlen;
}

/* The field table is buffered rather than printed as it is built,
   because the heading has to come first and the vector's own name is
   only known at the call to vec(). Buffering keeps each vector's
   description in source order — table, then bytes — with one helper per
   line instead of a name repeated at both ends. */
static char table[4096];
static size_t table_len;

static void field(const char *name, const char *value) {
  int n = snprintf(table + table_len, sizeof(table) - table_len,
                   "| `%s` | %s |\n", name, value);
  if (n > 0 && (size_t)n < sizeof(table) - table_len)
    table_len += (size_t)n;
}

static void field_table_begin(void) {
  table_len = 0;
  table[0] = '\0';
}

static void vec(const char *id, const char *title, const void *buf,
                size_t n) {
  printf("\n#### %s — %s\n\n", id, title);
  if (table_len) {
    puts("| field | value |");
    puts("|---|---|");
    fputs(table, stdout);
    putchar('\n');
    field_table_begin();
  }
  hexdump(buf, n);
}

int main(void) {
  unsigned char req[512], resp[512];
  size_t rn, sn;
  char num[64];

  puts("## 9.1 Requests");
  puts("");
  puts("Every request below is stamped `version = 1` and");
  puts("`source_tag = SRC_CLI` (1). `seq` is the client's own counter and");
  puts("is echoed untouched (§2.7); the values here are arbitrary.");

  /* --- HELLO ---------------------------------------------------- */
  {
    struct uictl_payload_hello h;
    memset(&h, 0, sizeof(h));
    h.proto_min = UICTL_PROTO_MIN;
    h.proto_max = UICTL_PROTO_MAX;
    memcpy(h.client_name, "uictl", 5);
    rn = frame(req, 1, OP_HELLO, SRC_CLI, 1, &h, sizeof(h));
    field_table_begin();
    field("opcode", "`OP_HELLO` (3)");
    field("payload_len", "36");
    field("proto_min / proto_max", "1 / 1");
    field("client_name", "`\"uictl\"`, NUL-padded to 32 bytes");
    vec("R1", "`HELLO`", req, rn);
    puts("");
    puts("The 27 trailing zero bytes are not optional padding a client");
    puts("may omit: `client_name` is a fixed 32-byte field and every byte");
    puts("after the NUL MUST be zero (§3.5).");
  }

  /* --- PING ------------------------------------------------------ */
  {
    rn = frame(req, 1, OP_PING, SRC_CLI, 2, NULL, 0);
    field_table_begin();
    field("opcode", "`OP_PING` (1)");
    field("payload_len", "0");
    vec("R2", "`PING` — the whole frame is the header", req, rn);
  }

  /* --- MOVE_ABS -------------------------------------------------- */
  {
    struct uictl_payload_move_abs m = {.x = 100, .y = 200};
    rn = frame(req, 1, OP_MOVE_ABS, SRC_CLI, 3, &m, sizeof(m));
    field_table_begin();
    field("opcode", "`OP_MOVE_ABS` (2)");
    field("x / y", "100 / 200, device units (§3.4)");
    vec("R3", "absolute motion", req, rn);
  }

  /* --- MOVE_REL — negative deltas, two's complement --------------- */
  {
    struct uictl_payload_move_rel m = {.dx = -5, .dy = 3};
    rn = frame(req, 1, OP_MOVE_REL, SRC_CLI, 4, &m, sizeof(m));
    field_table_begin();
    field("opcode", "`OP_MOVE_REL` (12)");
    field("dx / dy", "-5 / 3");
    vec("R4", "relative motion, negative delta", req, rn);
    puts("");
    puts("`dx = -5` is `fb ff ff ff`: two's complement, little-endian.");
    puts("An implementation that encodes signed fields as sign-and-");
    puts("magnitude, or that byte-swaps, fails here and nowhere else —");
    puts("which is why this vector uses a negative number.");
  }

  /* --- SCROLL ---------------------------------------------------- */
  {
    struct uictl_payload_scroll s = {.notches_v = 1, .notches_h = 0};
    rn = frame(req, 1, OP_SCROLL, SRC_CLI, 5, &s, sizeof(s));
    field_table_begin();
    field("opcode", "`OP_SCROLL` (13)");
    field("notches_v / notches_h", "1 / 0 — one detent up");
    vec("R5", "scroll", req, rn);
  }

  /* --- BUTTON ---------------------------------------------------- */
  {
    struct uictl_payload_button b = {
        .code = BTN_LEFT_, .down = 1, .reserved = 0};
    rn = frame(req, 1, OP_BUTTON, SRC_CLI, 6, &b, sizeof(b));
    field_table_begin();
    field("opcode", "`OP_BUTTON` (11)");
    snprintf(num, sizeof(num), "`BTN_LEFT` = %u (0x%03x)", BTN_LEFT_,
             BTN_LEFT_);
    field("code", num);
    field("down", "1 — press");
    field("reserved", "0, and MUST be");
    vec("R6", "button press", req, rn);

    b.down = 0;
    rn = frame(req, 1, OP_BUTTON, SRC_CLI, 7, &b, sizeof(b));
    vec("R7", "button release — never confirmed, never rate-charged", req,
        rn);
  }

  /* --- KEY_TAP --------------------------------------------------- */
  {
    struct uictl_payload_key k = {.keycode = KEY_F13_};
    rn = frame(req, 1, OP_KEY_TAP, SRC_CLI, 8, &k, sizeof(k));
    field_table_begin();
    field("opcode", "`OP_KEY_TAP` (4)");
    snprintf(num, sizeof(num), "%u (`KEY_F13`)", KEY_F13_);
    field("keycode", num);
    vec("R8", "key tap", req, rn);
  }

  /* --- KEY_SEQUENCE — the balanced Ctrl+A --------------------------- */
  {
    unsigned char p[sizeof(struct uictl_payload_key_seq) +
                    4 * sizeof(struct uictl_seq_item)];
    struct uictl_payload_key_seq hdr = {.count = 4, .reserved = 0};
    struct uictl_seq_item items[4] = {
        {KEY_LEFTCTRL_, 1, 0}, {KEY_A_, 1, 0}, {KEY_A_, 0, 0},
        {KEY_LEFTCTRL_, 0, 0}};
    memcpy(p, &hdr, sizeof(hdr));
    memcpy(p + sizeof(hdr), items, sizeof(items));
    rn = frame(req, 1, OP_KEY_SEQUENCE, SRC_CLI, 9, p, sizeof(p));
    field_table_begin();
    field("opcode", "`OP_KEY_SEQUENCE` (5)");
    field("count", "4");
    field("items", "down 29, down 30, up 30, up 29 — Ctrl+A");
    snprintf(num, sizeof(num), "%zu = 4 + 4 x 4", sizeof(p));
    field("payload_len", num);
    vec("R9", "`KEY_SEQUENCE` — balanced Ctrl+A", req, rn);
    puts("");
    puts("Balance is tracked per key, not counted: `down 29, down 29,");
    puts("up 29, up 29` sums to zero and is still refused (§5B.2).");
  }

  /* --- KEY_DOWN / KEY_UP ------------------------------------------ */
  {
    struct uictl_payload_key k = {.keycode = KEY_F13_};
    rn = frame(req, 1, OP_KEY_DOWN, SRC_CLI, 10, &k, sizeof(k));
    vec("R10", "`KEY_DOWN` — same 2-byte payload as `KEY_TAP`", req, rn);
    rn = frame(req, 1, OP_KEY_UP, SRC_CLI, 11, &k, sizeof(k));
    vec("R11", "`KEY_UP` — the frame that is never refused for policy",
        req, rn);
  }

  /* --- BATCH ------------------------------------------------------ */
  {
    unsigned char p[sizeof(struct uictl_payload_batch) +
                    2 * sizeof(struct uictl_batch_item)];
    struct uictl_payload_batch hdr = {.count = 2, .reserved = 0};
    struct uictl_batch_item items[2] = {
        {OP_MOVE_REL, 0, 10, 0},
        {OP_BUTTON, 0, BTN_LEFT_, 1},
    };
    memcpy(p, &hdr, sizeof(hdr));
    memcpy(p + sizeof(hdr), items, sizeof(items));
    rn = frame(req, 1, OP_BATCH, SRC_CLI, 12, p, sizeof(p));
    field_table_begin();
    field("opcode", "`OP_BATCH` (14)");
    field("count", "2");
    field("item 0", "`MOVE_REL` dx=10 dy=0");
    field("item 1", "`BUTTON` code=272 down=1");
    snprintf(num, sizeof(num), "%zu = 4 + 2 x 12", sizeof(p));
    field("payload_len", num);
    vec("R12", "`BATCH` — nudge then click, one device, one report", req,
        rn);
    puts("");
    puts("Both items land on the pointer, so this is one `SYN_REPORT`.");
    puts("Adding a key item would make it two — atomic per device, and");
    puts("nothing below the kernel joins them (§5B.4).");
  }

  /* --- confirmation client frames --------------------------------- */
  {
    rn = frame(req, 1, OP_CONFIRM_SUBSCRIBE, SRC_CLI, 13, NULL, 0);
    field_table_begin();
    field("opcode", "`OP_CONFIRM_SUBSCRIBE` (8)");
    field("payload_len", "0 — the request is the whole message");
    vec("R13", "subscribe as the confirmer", req, rn);

    struct uictl_payload_confirm_decide d = {.token = 1, .allow = 1};
    memset(d.reserved, 0, sizeof(d.reserved));
    rn = frame(req, 1, OP_CONFIRM_DECIDE, SRC_CLI, 14, &d, sizeof(d));
    field_table_begin();
    field("opcode", "`OP_CONFIRM_DECIDE` (10)");
    field("token", "1 — echoed from the prompt");
    field("allow", "1. **Any other value denies** (§7.5)");
    vec("R14", "approve a parked request", req, rn);
  }

  puts("");
  puts("---");
  puts("");
  puts("## 9.2 Responses");
  puts("");
  puts("A response echoes the request's header with `payload_len`");
  puts("rewritten, then `u16 result`, then opcode-specific data (§2.4).");
  puts("Each vector below names the request it answers.");

  {
    rn = frame(req, 1, OP_PING, SRC_CLI, 2, NULL, 0);
    sn = response(resp, req, OK, NULL, 0);
    field_table_begin();
    field("answers", "R2");
    field("payload_len", "2 — the result and nothing else");
    field("result", "`OK` (0)");
    vec("S1", "`PING` answered", resp, sn);
    puts("");
    puts("Note the echo: `opcode` is still 1 and `seq` is still 2. A");
    puts("client matches on those, not on arrival order alone.");
  }

  {
    struct uictl_payload_hello h;
    memset(&h, 0, sizeof(h));
    h.proto_min = UICTL_PROTO_MIN;
    h.proto_max = UICTL_PROTO_MAX;
    memcpy(h.client_name, "uictl", 5);
    rn = frame(req, 1, OP_HELLO, SRC_CLI, 1, &h, sizeof(h));

    struct uictl_resp_hello r;
    memset(&r, 0, sizeof(r));
    r.proto_selected = 1;
    r.device_caps =
        CAP_POINTER_ABS | CAP_KEYBOARD | CAP_POINTER_REL | CAP_BUTTONS;
    r.abs_range_max = 32767;
    r.opcode_bitmap =
        UICTL_OP_BIT(OP_PING) | UICTL_OP_BIT(OP_MOVE_ABS) |
        UICTL_OP_BIT(OP_HELLO) | UICTL_OP_BIT(OP_KEY_TAP) |
        UICTL_OP_BIT(OP_KEY_SEQUENCE) | UICTL_OP_BIT(OP_KEY_DOWN) |
        UICTL_OP_BIT(OP_KEY_UP) | UICTL_OP_BIT(OP_CONFIRM_SUBSCRIBE) |
        UICTL_OP_BIT(OP_CONFIRM_REQUEST) | UICTL_OP_BIT(OP_CONFIRM_DECIDE) |
        UICTL_OP_BIT(OP_BUTTON) | UICTL_OP_BIT(OP_MOVE_REL) |
        UICTL_OP_BIT(OP_SCROLL) | UICTL_OP_BIT(OP_BATCH);
    r.daemon_version = UICTL_DAEMON_VERSION;
    sn = response(resp, req, OK, &r, sizeof(r));

    field_table_begin();
    field("answers", "R1");
    snprintf(num, sizeof(num), "%zu = 2 + %zu",
             UICTL_RESULT_SIZE + sizeof(r), sizeof(r));
    field("payload_len", num);
    field("proto_selected", "1");
    snprintf(num, sizeof(num), "0x%04x — all four bits **[varies]**",
             (unsigned)r.device_caps);
    field("device_caps", num);
    field("abs_range_max", "32767");
    snprintf(num, sizeof(num), "0x%016llx **[varies]**",
             (unsigned long long)r.opcode_bitmap);
    field("opcode_bitmap", num);
    snprintf(num, sizeof(num), "0x%06x = %u.%u.%u **[varies]**",
             UICTL_DAEMON_VERSION, UICTL_DAEMON_VERSION >> 16,
             (UICTL_DAEMON_VERSION >> 8) & 0xff, UICTL_DAEMON_VERSION & 0xff);
    field("daemon_version", num);
    field("reconnect_*", "0 = `RECONNECT_UNSPEC`, no registry advice");
    vec("S2", "`HELLO` answered — the capability set", resp, sn);
    puts("");
    puts("**[varies]** marks a field an implementation MUST read rather");
    puts("than assert. `device_caps` is whatever the device came up");
    puts("with, `opcode_bitmap` is what this build implements, and");
    puts("`daemon_version` is informational — branching on it is the");
    puts("feature-sniffing §2.2 forbids. The three reconnect bytes and");
    puts("`reserved2` are the §8.6 tail: a client built against the");
    puts("24-byte prefix reads this same frame and ignores them.");
  }

  {
    struct uictl_payload_move_abs m = {.x = 100, .y = 200};
    rn = frame(req, 1, OP_MOVE_ABS, SRC_CLI, 3, &m, sizeof(m));
    sn = response(resp, req, OK, NULL, 0);
    field_table_begin();
    field("answers", "R3");
    field("result", "`OK` (0)");
    vec("S3", "a command acknowledged", resp, sn);

    sn = response(resp, req, ERR_HANDSHAKE_REQUIRED, NULL, 0);
    field_table_begin();
    field("answers", "R3, sent before any `HELLO`");
    snprintf(num, sizeof(num), "`ERR_HANDSHAKE_REQUIRED` (%u)",
             ERR_HANDSHAKE_REQUIRED);
    field("result", num);
    vec("S4", "the correctable refusal", resp, sn);
    puts("");
    puts("Per-frame, not fatal: the payload was consumed, so the next");
    puts("frame boundary is known. Send `HELLO` on this same connection");
    puts("and retry (§4.2).");
  }

  {
    struct uictl_frame_header deny = {.version = UICTL_PROTO_VERSION,
                                      .opcode = OP_INVALID,
                                      .source_tag = 0,
                                      .seq = 0,
                                      .payload_len = UICTL_RESULT_SIZE};
    uint16_t result = ERR_BUSY;
    encode_frame_header(&deny, resp);
    memcpy(resp + sizeof(deny), &result, sizeof(result));
    sn = sizeof(deny) + sizeof(result);
    field_table_begin();
    field("answers", "nothing — sent before the peer is a connection");
    field("opcode", "0 (`OP_INVALID`)");
    field("seq", "0");
    snprintf(num, sizeof(num), "`ERR_BUSY` (%u)", ERR_BUSY);
    field("result", num);
    vec("S5", "an admission refusal (§1.2)", resp, sn);
    puts("");
    puts("This frame matches no request. A client that reads it as a");
    puts("reply to something it sent will mis-attribute it; a client that");
    puts("does not read it at all reports a refusal as a mysterious EOF.");
    puts("The same shape carries `ERR_DENIED_BY_POLICY` (4) when the peer");
    puts("uid does not match.");
  }

  puts("");
  puts("---");
  puts("");
  puts("## 9.3 The frame the daemon sends unprompted");

  {
    struct uictl_payload_confirm_req p;
    memset(&p, 0, sizeof(p));
    p.token = 1;
    p.peer_pid = 4242;
    p.opcode = OP_KEY_TAP;
    p.keycode = KEY_F13_;
    p.cl = 0; /* untrusted */
    memcpy(p.client_name, "agent", 5);
    sn = frame(resp, 1, OP_CONFIRM_REQUEST, 0, p.token, &p, sizeof(p));
    field_table_begin();
    field("opcode", "`OP_CONFIRM_REQUEST` (9)");
    field("seq", "**the token**, not a client counter (§7.4)");
    field("source_tag", "0 — the daemon sets none");
    field("token / peer_pid", "1 / 4242");
    field("opcode (payload)", "4 = `KEY_TAP`");
    snprintf(num, sizeof(num), "%u", KEY_F13_);
    field("keycode", num);
    field("cl", "0 = `untrusted`, daemon-derived");
    field("client_name", "`\"agent\"` — self-asserted (§7.0)");
    snprintf(num, sizeof(num), "%zu", sizeof(p));
    field("payload_len", num);
    vec("P1", "a prompt pushed to the subscribed confirmer", resp, sn);
    puts("");
    puts("Not a response: nothing is echoed, because there was no");
    puts("request. A client library that assumes one read per write");
    puts("cannot host a confirmer (§2.7).");
  }

  puts("");
  puts("---");
  puts("");
  puts("## 9.4 Frames a conforming daemon MUST reject");
  puts("");
  puts("These are the negative vectors. An implementation that accepts");
  puts("any of them is not conforming, and each one is a bug class rather");
  puts("than a typo.");

  {
    struct uictl_frame_header h = {.version = 1,
                                   .opcode = OP_MOVE_ABS,
                                   .source_tag = SRC_CLI,
                                   .seq = 100,
                                   .payload_len = UICTL_MAX_PAYLOAD + 1};
    encode_frame_header(&h, req);
    /* header only: the point is that the daemon must refuse on the
       header, before it reads a single payload byte. */
    field_table_begin();
    snprintf(num, sizeof(num), "%u — one over `UICTL_MAX_PAYLOAD`",
             UICTL_MAX_PAYLOAD + 1);
    field("payload_len", num);
    snprintf(num, sizeof(num), "`ERR_TOO_LARGE` (%u), **then close**",
             ERR_TOO_LARGE);
    field("expected", num);
    vec("N1", "oversized payload — header only, no payload follows", req,
        sizeof(h));
    puts("");
    puts("Fatal to the stream (§2.6): the daemon cannot know where the");
    puts("next frame starts. It MUST answer before closing, and it MUST");
    puts("NOT attempt to read 4097 bytes into a 4096-byte buffer — this");
    puts("is the vector that catches the one field an attacker fully");
    puts("controls.");
  }

  {
    struct uictl_payload_key k = {.keycode = KEY_F13_};
    rn = frame(req, 1, OP_KEY_TAP, SRC_CLI, 101, &k, sizeof(k));
    struct uictl_frame_header h;
    decode_frame_header(req, &h);
    h.payload_len = 3;
    encode_frame_header(&h, req);
    field_table_begin();
    field("payload_len", "3, where `KEY_TAP` is exactly 2");
    snprintf(num, sizeof(num), "`ERR_PAYLOAD_INVALID` (%u), per-frame",
             ERR_PAYLOAD_INVALID);
    field("expected", num);
    vec("N2", "wrong payload size — the first 19 bytes on the wire", req,
        sizeof(h) + 3);
    puts("");
    puts("Command payloads are exact-size, never `>=` (§2.3). The");
    puts("connection survives: the payload was consumed, so the next");
    puts("boundary is known.");
  }

  {
    unsigned char p[sizeof(struct uictl_payload_key_seq) +
                    sizeof(struct uictl_seq_item)];
    struct uictl_payload_key_seq hdr = {.count = 1, .reserved = 1};
    struct uictl_seq_item item = {KEY_F13_, 1, 0};
    memcpy(p, &hdr, sizeof(hdr));
    memcpy(p + sizeof(hdr), &item, sizeof(item));
    rn = frame(req, 1, OP_KEY_SEQUENCE, SRC_CLI, 102, p, sizeof(p));
    field_table_begin();
    field("reserved", "1");
    snprintf(num, sizeof(num), "`ERR_PAYLOAD_INVALID` (%u)",
             ERR_PAYLOAD_INVALID);
    field("expected", num);
    vec("N3", "non-zero reserved field", req, rn);
    puts("");
    puts("Reserved bytes are read and rejected, not ignored (§2.3), so a");
    puts("future field cannot collide with junk an old client left there.");
    puts("This sequence is also unbalanced, which would refuse it anyway —");
    puts("a conforming daemon MAY report either, and the reserved check");
    puts("comes first.");
  }

  {
    struct uictl_payload_hello h;
    memset(&h, 0, sizeof(h));
    h.proto_min = 1;
    h.proto_max = 1;
    memcpy(h.client_name, "ui\nctl", 6);
    rn = frame(req, 1, OP_HELLO, SRC_CLI, 103, &h, sizeof(h));
    field_table_begin();
    field("client_name", "`\"ui\\nctl\"` — a newline at offset 2");
    snprintf(num, sizeof(num),
             "`ERR_PAYLOAD_INVALID` (%u), and the name is **not** echoed",
             ERR_PAYLOAD_INVALID);
    field("expected", num);
    vec("N4", "a client name that would forge audit lines", req, rn);
    puts("");
    puts("The audit log is newline-delimited (§3.5). A daemon that");
    puts("accepts this hands the client the ability to write invented");
    puts("denials into the record that exists to hold it accountable.");
  }

  {
    struct uictl_payload_key k = {.keycode = KEY_F13_};
    rn = frame(req, 2, OP_KEY_TAP, SRC_CLI, 104, &k, sizeof(k));
    field_table_begin();
    field("version", "2, on a connection that negotiated 1");
    snprintf(num, sizeof(num), "`ERR_VERSION` (%u), **then close**",
             ERR_VERSION);
    field("expected", num);
    vec("N5", "version hopping after the handshake", req, rn);
    puts("");
    puts("The version is pinned for the life of the connection (§3.3).");
    puts("Fatal, because a rejected version means `payload_len` is not");
    puts("trustworthy either. Sent *before* a `HELLO`, this same frame is");
    puts("`ERR_HANDSHAKE_REQUIRED` instead — the pin does not exist yet.");
  }

  return 0;
}
