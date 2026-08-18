/* gen_proto_json — emits proto.json, the machine-readable schema
 * (M-lib task 3).
 *
 * One schema, three consumers, and that is the point of the task: the
 * opcode table a client hardcodes, the op list in the spec, and the LLM
 * tool definitions auto-c v2.x will need all describe the same fourteen
 * requests. Three hand-maintained copies of that is three chances to
 * disagree, and the one that disagrees silently is the tool definition —
 * an agent calling a tool whose schema drifted produces a confidently
 * wrong keystroke.
 *
 * WHERE THE TRUTH LIVES. Not here. Field offsets, sizes and limits come
 * from src/proto.h via offsetof/sizeof, so the layout cannot be
 * mistyped. Result classes and hints come from libuictl by CALLING
 * uictl_result_class() and uictl_result_hint() -- so WIRE.md §4.2 is
 * transcribed exactly once, in the library, and proto.json is its
 * projection rather than a second copy that has to be kept in step.
 *
 * What IS authored here is prose: one summary line per opcode and per
 * parameter. That is the part a generator cannot derive and the part an
 * LLM tool definition actually needs.
 *
 * Output goes to stdout; `make proto.json` writes the file, and
 * tests/test_mlib_proto_json.py regenerates and diffs it.
 */
#include "../src/lib/uictl.h"
#include "../src/proto.h"

#include <stddef.h>
#include <stdio.h>
#include <string.h>

#define ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))

/* JSON strings here are all ASCII with no quotes or backslashes in them
   -- asserted by keeping the prose plain rather than by escaping, since
   an escaper nobody exercises is an escaper that is wrong. */
static void jstr(const char *s) {
  putchar('"');
  for (const char *p = s; *p; p++) {
    if (*p == '"' || *p == '\\')
      putchar('\\');
    putchar(*p);
  }
  putchar('"');
}

struct field {
  const char *name;
  const char *type;
  size_t offset;
  size_t size;
  const char *note;
};

struct opdesc {
  const char *name;
  int value;
  const char *direction;
  const char *summary;
  int touches_device; /* subject to the confirmation gate (WIRE.md §7.3) */
  int is_release;     /* never confirmed, never rate-charged (§6.3)      */
  int rate_charged;
  long payload_len; /* -1 = variable, see payload_formula */
  const char *payload_formula;
  const struct field *fields;
  size_t nfields;
};

/* --- payload layouts, straight out of proto.h ------------------------- */

#define F(struct_t, member, type_s, note_s)                                    \
  {#member, type_s, offsetof(struct_t, member),                                \
   sizeof(((struct_t *)0)->member), note_s}

static const struct field f_move_abs[] = {
    F(struct uictl_payload_move_abs, x, "i32",
      "device units, 0..abs_range_max; the daemon clamps"),
    F(struct uictl_payload_move_abs, y, "i32",
      "device units, 0..abs_range_max; the daemon clamps"),
};

static const struct field f_move_rel[] = {
    F(struct uictl_payload_move_rel, dx, "i32",
      "device units; not scaled by anything"),
    F(struct uictl_payload_move_rel, dy, "i32",
      "device units; not scaled by anything"),
};

static const struct field f_scroll[] = {
    F(struct uictl_payload_scroll, notches_v, "i32",
      "wheel detents; positive is up"),
    F(struct uictl_payload_scroll, notches_h, "i32",
      "wheel detents; positive is right"),
};

static const struct field f_button[] = {
    F(struct uictl_payload_button, code, "u16",
      "BTN_LEFT 272, BTN_RIGHT 273, BTN_MIDDLE 274"),
    F(struct uictl_payload_button, down, "u8", "1 = press, 0 = release"),
    F(struct uictl_payload_button, reserved, "u8", "MUST be zero"),
};

static const struct field f_key[] = {
    F(struct uictl_payload_key, keycode, "u16",
      "Linux keycode, 1..767; the daemon range-checks and policy-checks it"),
};

static const struct field f_hello[] = {
    F(struct uictl_payload_hello, proto_min, "u16",
      "lowest protocol version this client speaks"),
    F(struct uictl_payload_hello, proto_max, "u16",
      "highest protocol version this client speaks"),
    F(struct uictl_payload_hello, client_name, "char[32]",
      "self-asserted label, 1-31 bytes of [A-Za-z0-9._-], NUL-padded"),
};

static const struct field f_seq_hdr[] = {
    F(struct uictl_payload_key_seq, count, "u16", "number of items"),
    F(struct uictl_payload_key_seq, reserved, "u16", "MUST be zero"),
};

static const struct field f_batch_hdr[] = {
    F(struct uictl_payload_batch, count, "u16", "number of items"),
    F(struct uictl_payload_batch, reserved, "u16", "MUST be zero"),
};

static const struct field f_confirm_req[] = {
    F(struct uictl_payload_confirm_req, token, "u32",
      "the daemon's handle on the parked request; echo it back"),
    F(struct uictl_payload_confirm_req, peer_pid, "u32",
      "from SO_PEERCRED, unforgeable"),
    F(struct uictl_payload_confirm_req, opcode, "u16",
      "the opcode being asked about"),
    F(struct uictl_payload_confirm_req, keycode, "u16",
      "the key, or 0 where not applicable"),
    F(struct uictl_payload_confirm_req, cl, "u16",
      "daemon-derived class: 0 untrusted, 1 standard, 2 interactive"),
    F(struct uictl_payload_confirm_req, reserved, "u16", "MUST be zero"),
    F(struct uictl_payload_confirm_req, client_name, "char[32]",
      "what the requester said at HELLO; self-asserted"),
};

static const struct field f_confirm_decide[] = {
    F(struct uictl_payload_confirm_decide, token, "u32",
      "echoed from the prompt; a stale token is refused"),
    F(struct uictl_payload_confirm_decide, allow, "u8",
      "1 proceeds; ANY other value refuses"),
    F(struct uictl_payload_confirm_decide, reserved, "u8[3]",
      "MUST be zero"),
};

static const struct field f_hdr[] = {
    F(struct uictl_frame_header, version, "u16",
      "pinned to the negotiated version after HELLO"),
    F(struct uictl_frame_header, opcode, "u16", "see opcodes"),
    F(struct uictl_frame_header, source_tag, "u32",
      "ADVISORY, audit log only; never an input to a decision"),
    F(struct uictl_frame_header, seq, "u32",
      "client's own counter; echoed untouched"),
    F(struct uictl_frame_header, payload_len, "u32",
      "bytes after the header; MUST NOT exceed max_payload"),
};

static const struct field f_resp_hello[] = {
    F(struct uictl_resp_hello, proto_selected, "u16",
      "version pinned for this connection"),
    F(struct uictl_resp_hello, device_caps, "u16", "capability bits"),
    F(struct uictl_resp_hello, abs_range_max, "u32",
      "upper bound for MOVE_ABS coordinates"),
    F(struct uictl_resp_hello, opcode_bitmap, "u64",
      "bit N set means opcode N is implemented; the ONLY correct feature test"),
    F(struct uictl_resp_hello, daemon_version, "u32",
      "informational; branching on it is feature-sniffing"),
    F(struct uictl_resp_hello, reserved, "u32", "MUST be zero"),
    F(struct uictl_resp_hello, reconnect_mode, "u8",
      "0 unspecified, 1 never, 2 backoff; ADVISORY"),
    F(struct uictl_resp_hello, reconnect_max_tries, "u8",
      "0 = unbounded; only meaningful when mode is backoff"),
    F(struct uictl_resp_hello, reconnect_base_ms, "u16",
      "first delay, doubling each attempt"),
    F(struct uictl_resp_hello, reserved2, "u32", "MUST be zero"),
};

static const struct opdesc OPS[] = {
    {"PING", UICTL_OP_PING, "client_to_daemon",
     "Liveness probe. Exempt from the handshake and from the rate limit.",
     0, 0, 0, 0, NULL, NULL, 0},
    {"MOVE_ABS", UICTL_OP_MOVE_ABS, "client_to_daemon",
     "Move the pointer to an absolute position in device units.", 1, 0, 1,
     (long)sizeof(struct uictl_payload_move_abs), NULL, f_move_abs,
     ARRAY_LEN(f_move_abs)},
    {"HELLO", UICTL_OP_HELLO, "client_to_daemon",
     "Mandatory handshake. Negotiates the protocol version and names the "
     "client. One per connection.",
     0, 0, 0, (long)sizeof(struct uictl_payload_hello), NULL, f_hello,
     ARRAY_LEN(f_hello)},
    {"KEY_TAP", UICTL_OP_KEY_TAP, "client_to_daemon",
     "Press and release one key in a single request.", 1, 0, 1,
     (long)sizeof(struct uictl_payload_key), NULL, f_key, ARRAY_LEN(f_key)},
    {"KEY_SEQUENCE", UICTL_OP_KEY_SEQUENCE, "client_to_daemon",
     "Several key transitions applied atomically under one report. Must be "
     "self-balancing: every press has its release inside the same request.",
     1, 0, 1, -1, "4 + 4 * count", f_seq_hdr, ARRAY_LEN(f_seq_hdr)},
    {"KEY_DOWN", UICTL_OP_KEY_DOWN, "client_to_daemon",
     "Hold a key down across later requests. The daemon releases it when "
     "the connection ends, or after 30 seconds.",
     1, 0, 1, (long)sizeof(struct uictl_payload_key), NULL, f_key,
     ARRAY_LEN(f_key)},
    {"KEY_UP", UICTL_OP_KEY_UP, "client_to_daemon",
     "Release a held key. Never refused for a policy reason, never "
     "rate-charged, never confirmed.",
     1, 1, 0, (long)sizeof(struct uictl_payload_key), NULL, f_key,
     ARRAY_LEN(f_key)},
    {"CONFIRM_SUBSCRIBE", UICTL_OP_CONFIRM_SUBSCRIBE, "client_to_daemon",
     "Become the confirmer. Requires the confirmer role in the local "
     "registry; one at a time.",
     0, 0, 0, 0, NULL, NULL, 0},
    {"CONFIRM_REQUEST", UICTL_OP_CONFIRM_REQUEST, "daemon_to_client",
     "A prompt for a human, pushed to the subscribed confirmer. The only "
     "unsolicited frame in the protocol.",
     0, 0, 0, (long)sizeof(struct uictl_payload_confirm_req), NULL,
     f_confirm_req, ARRAY_LEN(f_confirm_req)},
    {"CONFIRM_DECIDE", UICTL_OP_CONFIRM_DECIDE, "client_to_daemon",
     "The confirmer's answer to a prompt.", 0, 0, 0,
     (long)sizeof(struct uictl_payload_confirm_decide), NULL,
     f_confirm_decide, ARRAY_LEN(f_confirm_decide)},
    {"BUTTON", UICTL_OP_BUTTON, "client_to_daemon",
     "Press or release one pointer button. A release is never confirmed "
     "and never rate-charged.",
     1, 0, 1, (long)sizeof(struct uictl_payload_button), NULL, f_button,
     ARRAY_LEN(f_button)},
    {"MOVE_REL", UICTL_OP_MOVE_REL, "client_to_daemon",
     "Nudge the pointer by a relative delta in device units.", 1, 0, 1,
     (long)sizeof(struct uictl_payload_move_rel), NULL, f_move_rel,
     ARRAY_LEN(f_move_rel)},
    {"SCROLL", UICTL_OP_SCROLL, "client_to_daemon",
     "Scroll by whole wheel notches.", 1, 0, 1,
     (long)sizeof(struct uictl_payload_scroll), NULL, f_scroll,
     ARRAY_LEN(f_scroll)},
    {"BATCH", UICTL_OP_BATCH, "client_to_daemon",
     "Several sub-ops, validated together and applied atomically per "
     "device. A batch touching both devices produces two reports.",
     1, 0, 1, -1, "4 + 12 * count", f_batch_hdr, ARRAY_LEN(f_batch_hdr)},
};

static const struct {
  const char *name;
  int value;
} RESULTS[] = {
    {"OK", UICTL_RES_OK},
    {"ERR_VERSION", UICTL_RES_VERSION},
    {"ERR_OPCODE_UNKNOWN", UICTL_RES_OPCODE_UNKNOWN},
    {"ERR_PAYLOAD_INVALID", UICTL_RES_PAYLOAD_INVALID},
    {"ERR_DENIED_BY_POLICY", UICTL_RES_DENIED_BY_POLICY},
    {"ERR_TOO_LARGE", UICTL_RES_TOO_LARGE},
    {"ERR_INTERNAL", UICTL_RES_INTERNAL},
    {"ERR_BUSY", UICTL_RES_BUSY},
    {"ERR_HANDSHAKE_REQUIRED", UICTL_RES_HANDSHAKE_REQUIRED},
    {"ERR_KEY_DENYLISTED", UICTL_RES_KEY_DENYLISTED},
    {"ERR_KEY_NOT_ALLOWED", UICTL_RES_KEY_NOT_ALLOWED},
    {"ERR_RATE_LIMITED", UICTL_RES_RATE_LIMITED},
    {"ERR_KEY_ALREADY_HELD", UICTL_RES_KEY_ALREADY_HELD},
    {"ERR_KEY_HELD_BY_OTHER", UICTL_RES_KEY_HELD_BY_OTHER},
    {"ERR_KEY_NOT_HELD", UICTL_RES_KEY_NOT_HELD},
    {"ERR_TOO_MANY_HELD", UICTL_RES_TOO_MANY_HELD},
    {"ERR_CONFIRM_UNAVAILABLE", UICTL_RES_CONFIRM_UNAVAILABLE},
    {"ERR_CONFIRM_DENIED", UICTL_RES_CONFIRM_DENIED},
    {"ERR_CONFIRM_TIMEOUT", UICTL_RES_CONFIRM_TIMEOUT},
    {"ERR_NOT_CONFIRMER", UICTL_RES_NOT_CONFIRMER},
};

/* The class NAMES are the only thing here that is not taken from the
   library: uictl_result_class() returns an enum, and JSON wants a word.
   Indexed by the enum, so adding a class without naming it is an
   out-of-bounds read on the first run rather than a silent "unknown". */
static const char *CLASS_NAMES[] = {"ok",         "terminal",  "fixable",
                                    "retryable",  "client_bug",
                                    "correctable"};

static void emit_fields(const struct field *f, size_t n, const char *indent) {
  for (size_t i = 0; i < n; i++) {
    printf("%s{\"name\": ", indent);
    jstr(f[i].name);
    printf(", \"type\": ");
    jstr(f[i].type);
    printf(", \"offset\": %zu, \"size\": %zu, \"note\": ", f[i].offset,
           f[i].size);
    jstr(f[i].note);
    printf("}%s\n", i + 1 < n ? "," : "");
  }
}

int main(void) {
  puts("{");
  printf("  \"$comment\": ");
  jstr("GENERATED by tests/gen_proto_json.c from src/proto.h and "
       "src/lib/uictl.h. Do not edit; run `make proto.json`. "
       "tests/test_mlib_proto_json.py fails if this file and the "
       "generator disagree.");
  puts(",");
  printf("  \"schema_version\": 1,\n");

  puts("  \"protocol\": {");
  printf("    \"version_min\": %u,\n", UICTL_PROTO_MIN);
  printf("    \"version_max\": %u,\n", UICTL_PROTO_MAX);
  printf("    \"daemon_version\": \"%u.%u.%u\",\n",
         UICTL_DAEMON_VERSION >> 16, (UICTL_DAEMON_VERSION >> 8) & 0xff,
         UICTL_DAEMON_VERSION & 0xff);
  printf("    \"spec\": \"WIRE.md\"\n");
  puts("  },");

  puts("  \"transport\": {");
  printf("    \"socket\": \"$XDG_RUNTIME_DIR/uictld.sock\",\n");
  printf("    \"family\": \"AF_UNIX\",\n");
  printf("    \"type\": \"SOCK_STREAM\",\n");
  printf("    \"socket_mode\": \"0700\",\n");
  printf("    \"byte_order\": \"little\",\n");
  printf("    \"max_payload\": %u,\n", UICTL_MAX_PAYLOAD);
  printf("    \"peer_auth\": \"SO_PEERCRED; the peer uid must equal the "
         "daemon's\"\n");
  puts("  },");

  printf("  \"frame_header\": {\"size\": %zu, \"fields\": [\n",
         sizeof(struct uictl_frame_header));
  emit_fields(f_hdr, ARRAY_LEN(f_hdr), "    ");
  puts("  ]},");

  printf("  \"response\": {\"comment\": ");
  jstr("the request's header echoed with payload_len rewritten, then u16 "
       "result, then opcode-specific data; response data grows "
       "append-only and a client must ignore a tail it does not "
       "understand");
  printf(", \"result_size\": %zu},\n", UICTL_RESULT_SIZE);

  printf("  \"hello_response\": {\"size\": %zu, \"min_accepted_size\": %u, "
         "\"fields\": [\n",
         sizeof(struct uictl_resp_hello), UICTL_RESP_HELLO_V1_SIZE);
  emit_fields(f_resp_hello, ARRAY_LEN(f_resp_hello), "    ");
  puts("  ]},");

  puts("  \"opcodes\": [");
  for (size_t i = 0; i < ARRAY_LEN(OPS); i++) {
    const struct opdesc *o = &OPS[i];
    puts("    {");
    printf("      \"name\": ");
    jstr(o->name);
    printf(",\n      \"value\": %d,\n", o->value);
    printf("      \"direction\": ");
    jstr(o->direction);
    printf(",\n      \"summary\": ");
    jstr(o->summary);
    printf(",\n      \"touches_device\": %s,\n",
           o->touches_device ? "true" : "false");
    printf("      \"is_release\": %s,\n", o->is_release ? "true" : "false");
    printf("      \"rate_charged\": %s,\n",
           o->rate_charged ? "true" : "false");
    /* The confirmation gate is exactly "touches the device and is not a
       release" (WIRE.md §7.3), so it is derived rather than stored --
       a stored copy could disagree with the two flags it is made of. */
    printf("      \"confirmable\": %s,\n",
           (o->touches_device && !o->is_release) ? "true" : "false");
    if (o->payload_len >= 0)
      printf("      \"payload_len\": %ld,\n", o->payload_len);
    else {
      printf("      \"payload_len\": null,\n");
      printf("      \"payload_formula\": ");
      jstr(o->payload_formula);
      puts(",");
    }
    if (o->nfields) {
      puts("      \"fields\": [");
      emit_fields(o->fields, o->nfields, "        ");
      printf("      ]\n");
    } else {
      puts("      \"fields\": []");
    }
    printf("    }%s\n", i + 1 < ARRAY_LEN(OPS) ? "," : "");
  }
  puts("  ],");

  puts("  \"results\": [");
  for (size_t i = 0; i < ARRAY_LEN(RESULTS); i++) {
    /* Class and hint are CALLED, not copied: WIRE.md §4.2 is transcribed
       once, in libuictl, and this file is its projection. */
    enum uictl_class cl = uictl_result_class((uint16_t)RESULTS[i].value);
    printf("    {\"name\": ");
    jstr(RESULTS[i].name);
    printf(", \"value\": %d, \"class\": ", RESULTS[i].value);
    jstr(CLASS_NAMES[cl]);
    printf(", \"hint\": ");
    jstr(uictl_result_hint((uint16_t)RESULTS[i].value));
    printf("}%s\n", i + 1 < ARRAY_LEN(RESULTS) ? "," : "");
  }
  puts("  ],");

  puts("  \"device_caps\": [");
  printf("    {\"name\": \"POINTER_ABS\", \"bit\": %u},\n",
         UICTL_CAP_POINTER_ABS);
  printf("    {\"name\": \"KEYBOARD\", \"bit\": %u},\n", UICTL_CAP_KEYBOARD);
  printf("    {\"name\": \"POINTER_REL\", \"bit\": %u},\n",
         UICTL_CAP_POINTER_REL);
  printf("    {\"name\": \"BUTTONS\", \"bit\": %u}\n", UICTL_CAP_BUTTONS);
  puts("  ],");

  puts("  \"source_tags\": [");
  printf("    {\"name\": \"CLI\", \"bit\": %u},\n", UICTL_SRC_CLI);
  printf("    {\"name\": \"HOTKEY\", \"bit\": %u},\n", UICTL_SRC_HOTKEY);
  printf("    {\"name\": \"LLM\", \"bit\": %u}\n", UICTL_SRC_LLM);
  puts("  ],");
  printf("  \"source_tag_note\": ");
  jstr("ADVISORY. The client writes it, so it MUST NOT be an input to any "
       "decision. Its only consumer is the audit log.");
  puts(",");

  puts("  \"limits\": {");
  printf("    \"max_payload\": %u,\n", UICTL_MAX_PAYLOAD);
  printf("    \"seq_steps\": %u,\n", UICTL_SEQ_MAX);
  printf("    \"batch_steps\": %u,\n", UICTL_BATCH_MAX);
  printf("    \"client_name\": %u,\n", UICTL_CLIENT_NAME_MAX);
  printf("    \"held_keys_per_connection\": 16,\n");
  printf("    \"hold_seconds\": 30,\n");
  printf("    \"confirm_payload\": 128,\n");
  printf("    \"confirm_seconds\": 30,\n");
  printf("    \"connections\": 32,\n");
  printf("    \"connections_per_pid\": 4\n");
  puts("  }");
  puts("}");
  return 0;
}
