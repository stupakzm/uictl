/* uictl — the command-line client, and libuictl's first real consumer
 * (M-lib task 2).
 *
 * Every frame this program used to build by hand now goes through
 * src/lib/uictl.h. What is left here is the half a library must not
 * have: argument parsing, and TEXT. The library never prints — see the
 * rules at the top of uictl.h — so it hands back a struct uictl_error
 * and this file decides what a person reading a terminal should see.
 *
 * That division is the whole point of the conversion. Before it, the
 * diagnostics below lived at the point of failure inside the socket
 * code, which meant any other C consumer either got uictl's wording on
 * its stderr or wrote its own encoder. Now there is one encoder, tested
 * against WIRE.md §9's vectors, and the wording is a property of this
 * program.
 */
#include "lib/uictl.h"
#include "platform/uinput.h" /* UINPUT_KEY_CODE_MAX — a kernel fact this
                                program explains to a user, not a wire
                                constant. The library deliberately does
                                not know it. */
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* The name this CLI announces at HELLO. Looked up in
   ~/.config/uictl/clients to pick the class and roles for the
   connection (WIRE.md §3.5). */
#define CLI_NAME "uictl"

/* Result codes are numbers on the wire; a person reading a terminal
   wants the name. Kept in the client, not in the library: the library's
   uictl_result_name() returns the ENUM name, which is what a log line
   or a bug report wants, and this returns a sentence, which is what a
   user wants. Two audiences, two tables. */
static const char *result_name(uint16_t r) {
  switch (r) {
  case UICTL_RES_OK:
    return "OK";
  case UICTL_RES_VERSION:
    return "protocol version mismatch";
  case UICTL_RES_OPCODE_UNKNOWN:
    return "opcode not implemented";
  case UICTL_RES_PAYLOAD_INVALID:
    return "malformed request";
  case UICTL_RES_DENIED_BY_POLICY:
    return "denied by policy";
  case UICTL_RES_TOO_LARGE:
    return "payload too large";
  case UICTL_RES_INTERNAL:
    return "daemon internal error";
  case UICTL_RES_BUSY:
    return "daemon busy, retry";
  case UICTL_RES_HANDSHAKE_REQUIRED:
    return "handshake required";
  case UICTL_RES_KEY_DENYLISTED:
    return "keycode is on the built-in deny-list";
  case UICTL_RES_KEY_NOT_ALLOWED:
    return "keycode is not in your policy file";
  case UICTL_RES_RATE_LIMITED:
    return "sending faster than your class allows";
  case UICTL_RES_KEY_ALREADY_HELD:
    return "you already hold that keycode";
  case UICTL_RES_KEY_HELD_BY_OTHER:
    return "another client is holding that keycode";
  case UICTL_RES_KEY_NOT_HELD:
    return "you do not hold that keycode";
  case UICTL_RES_TOO_MANY_HELD:
    return "too many keys held at once";
  case UICTL_RES_CONFIRM_UNAVAILABLE:
    return "this client needs confirmation and no confirmer is running";
  case UICTL_RES_CONFIRM_DENIED:
    return "the user declined";
  case UICTL_RES_CONFIRM_TIMEOUT:
    return "nobody answered the confirmation prompt";
  case UICTL_RES_NOT_CONFIRMER:
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

   The library has uictl_result_hint(), which says the same thing in one
   line for a caller that wants one. This is the long form, and it stays
   in the CLI because it names files, commands and keycodes — the kind of
   advice that is only right for someone at a terminal on this machine.

   `detail` carries the request-specific bit (a keycode, usually) so the
   advice can be concrete enough to copy. */
static void explain(uint16_t result, long detail) {
  switch (result) {
  case UICTL_RES_KEY_DENYLISTED:
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
  case UICTL_RES_KEY_NOT_ALLOWED:
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
  case UICTL_RES_DENIED_BY_POLICY:
    fprintf(stderr,
            "  why:  the daemon refused this peer\n"
            "  fix:  uictld only serves connections from its own uid. check "
            "you are\n"
            "        running as the same user that started it (`id`, "
            "`pgrep -a uictld`).\n");
    break;
  case UICTL_RES_HANDSHAKE_REQUIRED:
    fprintf(stderr,
            "  why:  the daemon requires OP_HELLO before this opcode\n"
            "  fix:  this is a client bug — every command except `ping` "
            "must handshake\n"
            "        first. report it.\n");
    break;
  case UICTL_RES_RATE_LIMITED:
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
  case UICTL_RES_BUSY:
    fprintf(stderr,
            "  why:  no connection slot right now (32 total, 4 per "
            "process)\n"
            "  fix:  retry in a moment. if it persists, `kill -USR1 $(pgrep "
            "-x uictld)`\n"
            "        prints the connection table to the daemon's stderr — "
            "look for a\n"
            "        client holding slots it is not using.\n");
    break;
  case UICTL_RES_OPCODE_UNKNOWN:
    fprintf(stderr,
            "  why:  this daemon does not implement that request\n"
            "  fix:  it is older than this client. rebuild and restart "
            "uictld;\n"
            "        `uictl hello NAME` lists what it does support.\n");
    break;
  case UICTL_RES_VERSION:
    fprintf(stderr,
            "  why:  no protocol version in common with the daemon\n"
            "  fix:  rebuild both binaries from the same tree and restart "
            "uictld.\n");
    break;
  case UICTL_RES_PAYLOAD_INVALID:
    fprintf(stderr,
            "  why:  the daemon rejected the request's contents\n"
            "  fix:  for key-tap, keycodes run 1..%d. otherwise this is a "
            "client bug.\n",
            UINPUT_KEY_CODE_MAX);
    break;
  case UICTL_RES_TOO_LARGE:
    fprintf(stderr, "  why:  the request exceeded the daemon's payload "
                    "limit\n  fix:  send fewer items per request.\n");
    break;
  /* The held-state refusals. Three of the four are client bugs, and the
     advice says so rather than inventing a workaround — a client that
     has lost track of what it holds cannot be fixed from the outside. */
  case UICTL_RES_KEY_ALREADY_HELD:
    fprintf(stderr,
            "  why:  this connection already holds keycode %ld\n"
            "  fix:  client bug — send the key-up you owe before pressing "
            "again.\n"
            "        the daemon does not model auto-repeat; a second "
            "key-down is\n"
            "        never what you want.\n",
            detail);
    break;
  case UICTL_RES_KEY_HELD_BY_OTHER:
    fprintf(stderr,
            "  why:  a different client is holding keycode %ld right now\n"
            "  fix:  wait and retry — it is mid-gesture, and two clients "
            "holding one\n"
            "        key means whoever releases first releases it for both. "
            "`kill -USR1\n"
            "        $(pgrep -x uictld)` shows which connection holds what.\n",
            detail);
    break;
  case UICTL_RES_KEY_NOT_HELD:
    fprintf(stderr,
            "  why:  this connection does not hold keycode %ld\n"
            "  fix:  none needed — the key is up, which is what you asked "
            "for. either\n"
            "        you released it twice, or the daemon's dead-man timer "
            "already\n"
            "        force-released it (a hold may not outlive 30s).\n",
            detail);
    break;
  case UICTL_RES_CONFIRM_UNAVAILABLE:
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
  case UICTL_RES_CONFIRM_DENIED:
    fprintf(stderr, "  why:  a human was asked and said no\n"
                    "  fix:  none — asking again is asking twice. do "
                    "something else.\n");
    break;
  case UICTL_RES_CONFIRM_TIMEOUT:
    fprintf(stderr,
            "  why:  the confirmation prompt went unanswered\n"
            "  fix:  retry if you expect someone to be at the keyboard. a "
            "timeout\n"
            "        is always a denial, never a silent approval.\n");
    break;
  case UICTL_RES_NOT_CONFIRMER:
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
  case UICTL_RES_TOO_MANY_HELD:
    fprintf(stderr,
            "  why:  this connection is already holding the maximum number "
            "of keys\n"
            "  fix:  release some. no real gesture needs more than a "
            "handful down at\n"
            "        once; if yours does, it probably wants key-combo "
            "instead.\n");
    break;
  case UICTL_RES_INTERNAL:
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

/* Exit codes — WIRE.md §8.8. Distinct, because "it did not work" is
   three different situations for whoever is scripting this, and only one
   of them is worth retrying:

     1  usage or a local error. Nothing was sent and nothing will be.
     2  the daemon could not be reached. Retryable — under socket
        activation it may simply not be up yet.
     3  the daemon answered and refused. The request reached the gate and
        was rejected; `explain()` has already said which gate. Retrying
        an identical request is only useful for the retryable result
        classes, which uictl_result_class() reports.
     4  the request was dropped without being sent, because a reconnect
        invalidated it (§8.5). The one-shot CLI cannot produce this — it
        never reconnects — but the code is claimed so the library and the
        CLI agree on the numbering.

   0 remains success. */
#define EXIT_USAGE 1
#define EXIT_UNREACHABLE 2
#define EXIT_REFUSED 3
#define EXIT_DROPPED 4

/* enum uictl_err -> exit status. The mapping is not one-to-one and the
   two that collapse are deliberate: E_NOTSUP and E_USAGE both mean this
   invocation was wrong and nothing was sent, which is exactly what 1
   promises. E_PROTO joins E_IO at 2 because a daemon that misframed is
   as unreachable as one that is not there — the connection is dead
   either way and the caller's retry logic is the same. */
static int exit_for(const struct uictl_error *e) {
  switch (e->err) {
  case UICTL_OK:
    return 0;
  case UICTL_E_REFUSED:
    return EXIT_REFUSED;
  case UICTL_E_DROPPED:
    return EXIT_DROPPED;
  case UICTL_E_ENV:
  case UICTL_E_SOCKET:
  case UICTL_E_IO:
  case UICTL_E_PROTO:
    return EXIT_UNREACHABLE;
  default:
    return EXIT_USAGE;
  }
}

/* Everything the user sees about a failure, in one place. `what` names
   the command; `detail` is the keycode or button the advice needs. */
static int report(const char *what, const struct uictl_error *e,
                  long detail) {
  if (e->err == UICTL_E_REFUSED) {
    fprintf(stderr, "uictl: %s failed: %s\n", what, result_name(e->result));
    explain(e->result, detail);
  } else if (e->err == UICTL_E_ENV) {
    fprintf(stderr, "uictl: XDG_RUNTIME_DIR is not set\n"
                    "  why:  the socket lives in the per-user runtime "
                    "directory\n"
                    "  fix:  run inside a normal login session, or set it "
                    "to the same\n"
                    "        directory uictld used.\n");
  } else if (e->err == UICTL_E_SOCKET) {
    /* The library returns errno and this decides what it means for a
       person. Before the conversion these strings lived inside the
       connect path, where every other consumer would have inherited
       them on its own stderr. */
    fprintf(stderr, "uictl: cannot reach the daemon: %s\n",
            strerror(e->sys_errno));
    if (e->sys_errno == ENOENT || e->sys_errno == ECONNREFUSED)
      fprintf(stderr, "  fix:  uictld is not running. start it "
                      "(`./uictld`) and try again.\n");
    else if (e->sys_errno == EACCES)
      fprintf(stderr, "  fix:  the socket belongs to another user. uictld "
                      "serves only its own uid.\n");
  } else if (e->err == UICTL_E_NOTSUP) {
    fprintf(stderr,
            "uictl: this daemon does not offer %s\n"
            "  why:  it did not advertise the opcode in its HELLO "
            "response\n"
            "  fix:  it is an older build. rebuild and restart uictld; "
            "`uictl hello\n"
            "        %s` lists what it does support.\n",
            what, CLI_NAME);
  } else {
    fprintf(stderr, "uictl: %s failed: %s\n", what, uictl_strerror(e));
  }
  return exit_for(e);
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

/* Open a connection, handshaked unless `flags` says otherwise. NULL on
   failure with the reason already printed; *rc is what to exit with. */
static uictl_conn *open_conn(const char *name, unsigned flags, int *rc) {
  struct uictl_error e;
  uictl_conn *c = uictl_connect(name, flags, &e);
  if (!c) {
    if (e.err == UICTL_E_USAGE)
      fprintf(stderr,
              "uictl: client name '%s' is not usable\n"
              "  why:  names go into the audit log, so only [A-Za-z0-9._-] "
              "are accepted\n"
              "        (a newline would let a client forge log lines)\n"
              "  fix:  use a plain name, e.g. `muvor` or `auto-c`.\n",
              name);
    else
      report("connect", &e, 0);
    *rc = exit_for(&e);
    return NULL;
  }
  *rc = 0;
  return c;
}

/* `uictl ping` — deliberately does NOT handshake. PING is exempt
   (WIRE.md §3.7) so it stays a bare liveness probe, and the CLI
   exercising that exemption is how we know the exemption still works.
   UICTL_NO_HELLO exists in the library for exactly this caller. */
static int cmd_ping(void) {
  int rc;
  uictl_conn *c = open_conn(CLI_NAME, UICTL_NO_HELLO, &rc);
  if (!c)
    return rc;

  struct uictl_error e;
  if (uictl_ping(c, &e) < 0) {
    rc = report("ping", &e, 0);
    uictl_close(c);
    return rc;
  }
  uictl_close(c);

  if (write(STDOUT_FILENO, "PONG\n", 5) < 0) {
    perror("uictl: write stdout");
    return EXIT_USAGE;
  }
  return 0;
}

/* `uictl hello NAME` — the handshake as a subcommand, printing what the
   daemon answered. The library performs it inside uictl_connect(); this
   only renders the capability set. */
static int cmd_hello(const char *name) {
  int rc;
  uictl_conn *c = open_conn(name, 0, &rc);
  if (!c)
    return rc;

  uint16_t asked_min = 0, asked_max = 0;
  uictl_proto_range(&asked_min, &asked_max);
  uint32_t dv = uictl_daemon_version(c);
  uint16_t caps = uictl_device_caps(c);

  printf("HELLO ok name=%s\n", name);
  printf("  proto      %u (asked %u-%u)\n", uictl_proto_selected(c),
         asked_min, asked_max);
  printf("  daemon     %u.%u.%u\n", (dv >> 16) & 0xff, (dv >> 8) & 0xff,
         dv & 0xff);
  printf("  abs range  0..%u\n", uictl_abs_range_max(c));
  printf("  device     %s%s%s%s\n",
         (caps & UICTL_CAP_POINTER_ABS) ? "pointer-abs " : "",
         (caps & UICTL_CAP_KEYBOARD) ? "keyboard " : "",
         (caps & UICTL_CAP_POINTER_REL) ? "pointer-rel " : "",
         (caps & UICTL_CAP_BUTTONS) ? "buttons" : "");
  /* key-down/key-up appear here with no matching subcommand below, and
     that is not an omission. The daemon releases everything a connection
     holds when it closes, so a one-shot CLI that presses a key and exits
     has written an elaborate key-tap. They are advertised because
     long-lived clients — muvor, auto-c — are who they are for, and
     libuictl now gives those clients uictl_key_down()/uictl_key_up(). */
  printf("  opcodes    %s%s%s%s%s%s%s\n",
         uictl_has_op(c, UICTL_OP_PING) ? "ping " : "",
         uictl_has_op(c, UICTL_OP_MOVE_ABS) ? "move-abs " : "",
         uictl_has_op(c, UICTL_OP_HELLO) ? "hello " : "",
         uictl_has_op(c, UICTL_OP_KEY_TAP) ? "key-tap " : "",
         uictl_has_op(c, UICTL_OP_KEY_SEQUENCE) ? "key-seq " : "",
         uictl_has_op(c, UICTL_OP_KEY_DOWN) ? "key-down " : "",
         uictl_has_op(c, UICTL_OP_KEY_UP) ? "key-up " : "");
  printf("             %s%s%s%s%s\n",
         uictl_has_op(c, UICTL_OP_BUTTON) ? "button " : "",
         uictl_has_op(c, UICTL_OP_MOVE_REL) ? "move-rel " : "",
         uictl_has_op(c, UICTL_OP_SCROLL) ? "scroll " : "",
         uictl_has_op(c, UICTL_OP_BATCH) ? "batch " : "",
         uictl_has_op(c, UICTL_OP_CONFIRM_SUBSCRIBE) ? "confirm" : "");
  uictl_close(c);
  return 0;
}

/* Every keycode the CLI accepts is range-checked here, before a socket
   exists. Not because the daemon would miss it — it range-checks too —
   but because the daemon charges the rate limit BEFORE it validates, so
   a typo caught locally costs nothing and the same typo caught remotely
   costs budget. The message names the header to look the code up in,
   which is the actual next thing a user needs. */
static bool keycode_ok(int32_t code, const char *examples) {
  if (code >= 1 && code <= UINPUT_KEY_CODE_MAX)
    return true;
  fprintf(stderr,
          "uictl: keycode %d is out of range\n"
          "  why:  the kernel's keycodes run 1..%d (0 is KEY_RESERVED)\n"
          "  fix:  see /usr/include/linux/input-event-codes.h — %s\n",
          code, UINPUT_KEY_CODE_MAX, examples);
  return false;
}

static int cmd_key_tap(int32_t code) {
  if (!keycode_ok(code, "e.g. 30 is KEY_A, 183 is KEY_F13."))
    return EXIT_USAGE;

  int rc;
  uictl_conn *c = open_conn(CLI_NAME, 0, &rc);
  if (!c)
    return rc;

  struct uictl_error e;
  if (uictl_key_tap(c, (uint16_t)code, &e) < 0) {
    rc = report("key-tap", &e, code);
    uictl_close(c);
    return rc;
  }
  uictl_close(c);
  printf("OK code=%d\n", code);
  return 0;
}

/* `uictl key-combo MOD... KEY` — press every code in order, then release
   them in reverse. Ctrl+A is `key-combo 29 30`.

   The CLI only offers this shape, not arbitrary sequences, because it is
   the shape that is always balanced by construction: the user cannot ask
   for something the daemon will reject as unbalanced. The wire is more
   general (any list of press/release items) and so is
   uictl_key_sequence(), for clients that need it. */
static int cmd_key_combo(const int32_t *codes, int n) {
  if (n < 1 || n * 2 > UICTL_MAX_SEQ_STEPS) {
    fprintf(stderr,
            "uictl: %d key(s) is out of range\n"
            "  why:  a combo becomes 2 events per key and a sequence "
            "carries at most %d\n"
            "  fix:  use at most %d keys per combo.\n",
            n, UICTL_MAX_SEQ_STEPS, UICTL_MAX_SEQ_STEPS / 2);
    return EXIT_USAGE;
  }
  for (int i = 0; i < n; i++) {
    if (!keycode_ok(codes[i], "29 is KEY_LEFTCTRL, 30 is KEY_A."))
      return EXIT_USAGE;
    for (int j = 0; j < i; j++)
      if (codes[j] == codes[i]) {
        fprintf(stderr,
                "uictl: keycode %d appears twice\n"
                "  why:  a combo presses each key once; pressing a held "
                "key is refused\n"
                "  fix:  list each keycode at most once.\n",
                codes[i]);
        return EXIT_USAGE;
      }
  }

  struct uictl_key_step steps[UICTL_MAX_SEQ_STEPS];
  int k = 0;
  for (int i = 0; i < n; i++) { /* press in order */
    steps[k].keycode = (uint16_t)codes[i];
    steps[k].value = 1;
    k++;
  }
  for (int i = n - 1; i >= 0; i--) { /* release in reverse */
    steps[k].keycode = (uint16_t)codes[i];
    steps[k].value = 0;
    k++;
  }

  int rc;
  uictl_conn *c = open_conn(CLI_NAME, 0, &rc);
  if (!c)
    return rc;

  struct uictl_error e;
  if (uictl_key_sequence(c, steps, (size_t)k, &e) < 0) {
    /* The keycode in the message is the first one; the daemon rejects on
       the first offending item, and for a 2-key combo that is nearly
       always the modifier or the key itself. */
    rc = report("key-combo", &e, codes[0]);
    uictl_close(c);
    return rc;
  }
  uictl_close(c);
  printf("OK (%d keys)\n", n);
  return 0;
}

/* `uictl click BUTTON` presses and releases in one connection, because a
   one-shot CLI cannot hold anything: the daemon releases everything a
   connection holds the moment it closes, so a bare `button down` from a
   process that then exits is a click with extra steps. Sent as a batch
   so the press and release are validated together. */
static int cmd_click(uint16_t code) {
  struct uictl_batch_step steps[2] = {
      {UICTL_OP_BUTTON, code, 1},
      {UICTL_OP_BUTTON, code, 0},
  };
  int rc;
  uictl_conn *c = open_conn(CLI_NAME, 0, &rc);
  if (!c)
    return rc;

  struct uictl_error e;
  if (uictl_batch(c, steps, 2, &e) < 0) {
    rc = report("click", &e, code);
    uictl_close(c);
    return rc;
  }
  uictl_close(c);
  printf("OK\n");
  return 0;
}

/* move-abs, move-rel and scroll differ only in which library call they
   make, so they share the connect/report/close shape rather than being
   three copies of it. */
enum simple_op { SIMPLE_MOVE_ABS, SIMPLE_MOVE_REL, SIMPLE_SCROLL };

static int cmd_simple(enum simple_op op, int32_t a, int32_t b) {
  static const char *labels[] = {"move-abs", "move-rel", "scroll"};
  int rc;
  uictl_conn *c = open_conn(CLI_NAME, 0, &rc);
  if (!c)
    return rc;

  struct uictl_error e;
  int r;
  switch (op) {
  case SIMPLE_MOVE_ABS:
    r = uictl_move_abs(c, a, b, &e);
    break;
  case SIMPLE_MOVE_REL:
    r = uictl_move_rel(c, a, b, &e);
    break;
  default:
    r = uictl_scroll(c, a, b, &e);
    break;
  }
  if (r < 0) {
    rc = report(labels[op], &e, 0);
    uictl_close(c);
    return rc;
  }
  uictl_close(c);
  printf("OK\n");
  return 0;
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    usage(argv[0]);
    return EXIT_USAGE;
  }

  if (strcmp(argv[1], "ping") == 0) {
    if (argc != 2) {
      usage(argv[0]);
      return EXIT_USAGE;
    }
    return cmd_ping();
  }

  if (strcmp(argv[1], "hello") == 0) {
    if (argc != 3) {
      usage(argv[0]);
      return EXIT_USAGE;
    }
    return cmd_hello(argv[2]);
  }

  if (strcmp(argv[1], "key-tap") == 0) {
    if (argc != 3) {
      usage(argv[0]);
      return EXIT_USAGE;
    }
    int32_t code;
    if (!parse_int32(argv[2], &code)) {
      fprintf(stderr, "uictl: bad keycode\n");
      return EXIT_USAGE;
    }
    return cmd_key_tap(code);
  }

  if (strcmp(argv[1], "key-combo") == 0) {
    if (argc < 3) {
      usage(argv[0]);
      return EXIT_USAGE;
    }
    int32_t codes[UICTL_MAX_SEQ_STEPS];
    int n = argc - 2;
    if (n > (int)(sizeof(codes) / sizeof(codes[0]))) {
      fprintf(stderr, "uictl: too many keys\n");
      return EXIT_USAGE;
    }
    for (int i = 0; i < n; i++) {
      if (!parse_int32(argv[2 + i], &codes[i])) {
        fprintf(stderr, "uictl: '%s' is not a keycode\n", argv[2 + i]);
        return EXIT_USAGE;
      }
    }
    return cmd_key_combo(codes, n);
  }

  if (strcmp(argv[1], "click") == 0) {
    if (argc != 3) {
      usage(argv[0]);
      return EXIT_USAGE;
    }
    int32_t code;
    if (!parse_int32(argv[2], &code) || code < 0 || code > 0xffff) {
      fprintf(stderr, "uictl: bad BUTTON\n");
      return EXIT_USAGE;
    }
    return cmd_click((uint16_t)code);
  }

  if (strcmp(argv[1], "move-rel") == 0) {
    if (argc != 4) {
      usage(argv[0]);
      return EXIT_USAGE;
    }
    int32_t dx, dy;
    if (!parse_int32(argv[2], &dx) || !parse_int32(argv[3], &dy)) {
      fprintf(stderr, "uictl: bad DX/DY\n");
      return EXIT_USAGE;
    }
    return cmd_simple(SIMPLE_MOVE_REL, dx, dy);
  }

  if (strcmp(argv[1], "scroll") == 0) {
    if (argc != 3 && argc != 4) {
      usage(argv[0]);
      return EXIT_USAGE;
    }
    int32_t v, h = 0;
    if (!parse_int32(argv[2], &v) ||
        (argc == 4 && !parse_int32(argv[3], &h))) {
      fprintf(stderr, "uictl: bad notch count\n");
      return EXIT_USAGE;
    }
    return cmd_simple(SIMPLE_SCROLL, v, h);
  }

  if (strcmp(argv[1], "move-abs") == 0) {
    if (argc != 4) {
      usage(argv[0]);
      return EXIT_USAGE;
    }
    int32_t x, y;
    if (!parse_int32(argv[2], &x)) {
      fprintf(stderr, "uictl: bad X\n");
      return EXIT_USAGE;
    }
    if (!parse_int32(argv[3], &y)) {
      fprintf(stderr, "uictl: bad Y\n");
      return EXIT_USAGE;
    }
    return cmd_simple(SIMPLE_MOVE_ABS, x, y);
  }

  usage(argv[0]);
  return EXIT_USAGE;
}
