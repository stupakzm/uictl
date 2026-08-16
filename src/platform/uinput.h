#pragma once

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
#define UINPUT_CAP__ALL (UINPUT_CAP_POINTER_ABS | UINPUT_CAP_KEYBOARD)

/* Returns the device fd, or -1. On success *caps_out is the OR of the
   UINPUT_CAP_* flags the device really has — verified against sysfs
   after creation, not merely the set we asked for. Never partially
   filled: on failure the daemon has no device and must not start. */
int uinput_open(uint32_t *caps_out);

void uinput_close(int fd);

int uinput_move_abs(int fd, int32_t x, int32_t y);

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
