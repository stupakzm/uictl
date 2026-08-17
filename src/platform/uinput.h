#pragma once

#include <stddef.h> /* size_t */
#include <stdint.h>

#define ABS_RANGE_MAX INT16_MAX

/* Mirrors KEY_MAX from <linux/input-event-codes.h>. It lives here
   because the daemon needs to range-check a keycode and must not include
   kernel headers — those stay inside src/platform/ (same rule that put
   ABS_RANGE_MAX here). uinput.c carries a _Static_assert that this still
   equals the kernel's KEY_MAX, so if a future kernel header moves it the
   BUILD fails rather than the daemon quietly rejecting valid keys or
   accepting codes the device never registered. */
#define UINPUT_KEY_CODE_MAX 767

/* What the virtual device was actually built with, reported by
   uinput_open(). These are PLATFORM names, deliberately not the wire
   CAP_* bits in proto.h: the HAL must not know the protocol. The single
   mapping between the two lives in uictld.c and is guarded by a
   _Static_assert against UINPUT_CAP__ALL, so adding a flag here breaks
   the build at the mapping instead of silently going unadvertised.

   Keep UINPUT_CAP__ALL in sync when adding a flag — that is the point. */
#define UINPUT_CAP_POINTER_ABS (1u << 0) /* EV_ABS + ABS_X/ABS_Y */
#define UINPUT_CAP_KEYBOARD (1u << 1)    /* EV_KEY over 0..KEY_MAX */
#define UINPUT_CAP_POINTER_REL (1u << 2) /* EV_REL + REL_X/Y + wheels */
#define UINPUT_CAP_BUTTONS (1u << 3)     /* BTN_LEFT/RIGHT/MIDDLE/SIDE/EXTRA */
#define UINPUT_CAP__ALL                                                        \
  (UINPUT_CAP_POINTER_ABS | UINPUT_CAP_KEYBOARD | UINPUT_CAP_POINTER_REL |     \
   UINPUT_CAP_BUTTONS)

/* ---- two devices, not one (M5.5 task 4) -----------------------------
   A single hybrid device carrying ABS + REL + BTN + every keycode is a
   shape no real hardware has, and libinput classifies by heuristic over
   the capability bits: the same bit pattern describes a touchscreen, a
   graphics tablet and an absolute mouse. Two devices that each look like
   something that exists get classified correctly without anyone having
   to guess how the heuristic will land.

   The cost, and it is real: an event frame is atomic per *device*, so a
   modifier-plus-click straddles the split and produces two SYN_REPORTs.
   That is a documented limitation rather than a bug — modifier+click on
   real hardware is also two devices — and it is why OP_BATCH is
   specified as atomic per device. */
struct uinput_devs {
  int pointer;  /* ABS + REL + BTN_*, INPUT_PROP_POINTER */
  int keyboard; /* EV_KEY over 1..KEY_MAX, minus the pointer's buttons */
};

/* Fills *devs and *caps_out, or returns -1 with neither usable. On
   success caps_out is the OR of the UINPUT_CAP_* flags the devices
   really have — verified against sysfs after creation, not merely the
   set we asked for. Never partially filled: on failure the daemon has no
   device and must not start. */
int uinput_open(struct uinput_devs *devs, uint32_t *caps_out);

void uinput_close(struct uinput_devs *devs);

/* Which device owns this code. The daemon routes on this rather than
   keeping its own list, so "buttons live on the pointer" is stated once,
   in the file that registers them.

   Non-zero means the pointer device. Note this is deliberately NOT
   "is it in the kernel's BTN_ range": it is "is it one of the buttons
   *this* pointer device registered", which is the only question a
   router can answer correctly. The keyboard device registers every other
   keycode, including the gamepad and digitiser buttons nothing here
   claims — capability is not permission, and excluding a hand-picked
   "safe" set from the keyboard is the drift M4 step 1 refused. */
int uinput_is_button(uint16_t code);

int uinput_move_abs(int fd, int32_t x, int32_t y);

/* Relative motion, and scroll (M5.5 task 3). Both take the POINTER fd.

   Scroll emits the classic REL_WHEEL/REL_HWHEEL notch *and* the
   high-resolution REL_WHEEL_HI_RES/REL_HWHEEL_HI_RES value in the same
   frame, which is what modern libinput expects: a device that sends only
   notches scrolls in coarse jumps under a compositor that has moved to
   hi-res, and one that sends only hi-res is invisible to consumers that
   never learned about it. 120 hi-res units == one notch, per the kernel's
   REL_WHEEL_HI_RES documentation. */
#define UINPUT_WHEEL_HI_RES_PER_NOTCH 120

int uinput_move_rel(int fd, int32_t dx, int32_t dy);
int uinput_scroll(int fd, int32_t notches_v, int32_t notches_h);

/* One button transition: EV_KEY on the pointer device plus SYN_REPORT.
   `code` must be one of the registered buttons — uinput_is_button() is
   the test, and a code that fails it is refused here rather than written
   to a device that never declared it (which the kernel drops silently). */
int uinput_button(int fd, uint16_t code, int down);

/* Press and release one key: EV_KEY value 1, EV_KEY value 0, SYN_REPORT,
   in a single write.

   M4 step 2 — UNWIRED. No opcode reaches this yet, and none may until
   the deny-list exists (step 6). The injection path is connected in
   step 7, *after* policy, so that no commit ever ships an ungated
   arbitrary-key write.

   `code` must be 1..KEY_MAX. This is a device-layer sanity check, NOT
   the policy check: it rejects codes the kernel could not accept
   anyway. Which keys a *client* may ask for is decided one layer up and
   is a different question with a different answer. */
int uinput_key_tap(int fd, uint16_t code);

/* Apply several key transitions in ONE event frame — one write, one
   SYN_REPORT, so the compositor sees them as a single atomic report.
   `n` must be 1..UINPUT_SEQ_MAX_EVENTS.

   The daemon guarantees the sequence is balanced before calling; this
   layer only range-checks and writes. Keeping the balance rule out of
   here is deliberate: it is a policy about what a *request* may contain,
   and the platform layer's job is what the *device* can accept. */
#define UINPUT_SEQ_MAX_EVENTS 16

struct uinput_key_event {
  uint16_t code;
  uint8_t value; /* 1 = press, 0 = release */
};

int uinput_key_seq(int fd, const struct uinput_key_event *evs, size_t n);

/* Is this keycode on the destructive-action deny-list? (M4 step 6.)
   Non-zero means refuse; `*why_out`, if given, receives a short static
   reason string suitable for the audit log.

   It lives in the platform layer for one reason: the list is written in
   kernel keycode names (KEY_POWER, the KEY_FN_* block, ...) and
   <linux/input-event-codes.h> stays inside src/platform/. The daemon
   asks a question and gets an answer; it never learns a keycode name.

   This is POLICY, unlike the range check inside uinput_key_tap(), which
   is validity. The daemon maps a denial to ERR_DENIED_BY_POLICY and a
   bad range to ERR_PAYLOAD_INVALID, and those two must not blur — one
   means "your client is broken", the other means "you may not do that".

   Deliberately consulted BEFORE any injection path exists (step 7), so
   no build in between can turn a socket into an arbitrary keystroke. */
int uinput_keycode_denied(uint16_t code, const char **why_out);

/* Validate the deny table itself. Called by uinput_open(); exposed so a
   future test or tool can run it. Non-zero means the table is malformed
   and the daemon must not start. */
int uinput_denylist_selftest(void);
