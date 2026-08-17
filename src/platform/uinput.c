#include "uinput.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/input-event-codes.h>
#include <linux/input.h>
#include <linux/limits.h>
#include <linux/uinput.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>
#include <stddef.h>


#define UINPUT_READY_TIMEOUT_MS 500
#define UINPUT_READY_POLL_MS 10
#define SYSNAME_BUF_SIZE 64

/* The devices this module owns, recorded at uinput_open() and cleared at
   uinput_close(). Not a convenience: it is what lets every primitive
   check that the fd handed to it is really one of our devices and really
   has the capability being used, instead of writing events into whatever
   fd the caller passed. See device_supports().

   Two entries since M5.5. This is exactly the case that check was
   written for — handing the pointer fd to a key primitive now has to
   fail loudly rather than write EV_KEY into a device that never declared
   it, which the kernel drops silently and presents as "the key did
   nothing" with no error anywhere. */
#define MAX_DEVS 2
static struct {
  int fd;
  uint32_t caps;
} g_devs[MAX_DEVS] = {{-1, 0}, {-1, 0}};

/* The buttons the POINTER device registers, in one place because three
   things must agree about them and a fourth must not drift: the pointer
   registers exactly these, the keyboard skips exactly these, and
   uinput_is_button() routes on exactly these. */
static const uint16_t pointer_buttons[] = {BTN_LEFT, BTN_RIGHT, BTN_MIDDLE,
                                           BTN_SIDE, BTN_EXTRA};
#define POINTER_BUTTON_COUNT                                                   \
  (sizeof(pointer_buttons) / sizeof(pointer_buttons[0]))

int uinput_is_button(uint16_t code) {
  for (size_t i = 0; i < POINTER_BUTTON_COUNT; i++)
    if (pointer_buttons[i] == code)
      return 1;
  return 0;
}

/* The drift guard for the constant the daemon range-checks against.
   This file is the only one that can see the kernel's KEY_MAX. */
_Static_assert(UINPUT_KEY_CODE_MAX == KEY_MAX,
               "UINPUT_KEY_CODE_MAX in uinput.h no longer matches the "
               "kernel's KEY_MAX — update it");

static int set_evbit(int fd, unsigned long bit) {
  if (ioctl(fd, UI_SET_EVBIT, bit) < 0) {
    fprintf(stderr, "uinput: UI_SET_EVBIT(%lu): %s\n", bit, strerror(errno));
    return -1;
  }
  return 0;
}

static int set_absbit(int fd, unsigned long bit) {
  if (ioctl(fd, UI_SET_ABSBIT, bit) < 0) {
    fprintf(stderr, "uinput: UI_SET_ABSBIT(%lu): %s\n", bit, strerror(errno));
    return -1;
  }
  return 0;
}

static int abs_setup(int fd, uint16_t code) {
  struct uinput_abs_setup abs = {0};
  abs.code = code;
  abs.absinfo.minimum = 0;
  abs.absinfo.maximum = ABS_RANGE_MAX;
  if (ioctl(fd, UI_ABS_SETUP, &abs) < 0) {
    fprintf(stderr, "uinput: UI_ABS_SETUP(code=%u): %s\n", code,
            strerror(errno));
    return -1;
  }
  return 0;
}

/* M4 step 1: register every keycode, not a hand-picked "safe" list.
   Capability is not permission — the device is *physically* able to emit
   KEY_POWER, and the broker simply never injects it because the RPC
   layer refuses (M4 step 6's deny-list). Conflating the two would mean a
   hand-maintained keybit list that silently diverges from policy, which
   is the failure this ordering exists to prevent. Closes analysis §C9.

   Every ioctl is checked and any failure aborts startup naming the
   keycode. A device that came up missing keys would fail much later, as
   an EINVAL on some injection or, worse, a dropped keystroke — the exact
   "garbage output, debug for hours" case. Fail here instead. */
static int set_all_keybits(int fd) {
  if (set_evbit(fd, EV_KEY) < 0)
    return -1;
  /* From 1: KEY_RESERVED (0) is not a key. */
  for (unsigned code = 1; code <= KEY_MAX; code++) {
    /* The five buttons the pointer device owns are skipped here, and
       only those five (M5.5). Not a "safe subset" — the keyboard still
       registers every gamepad, digitiser and joystick button nothing
       claims — but the two devices must be disjoint where they overlap,
       or a compositor sees a keyboard that also has a left mouse button,
       which is not a shape any real hardware has and is the whole reason
       the split exists. */
    if (uinput_is_button((uint16_t)code))
      continue;
    if (ioctl(fd, UI_SET_KEYBIT, code) < 0) {
      fprintf(stderr, "uinput: UI_SET_KEYBIT(%u of %u): %s\n", code, KEY_MAX,
              strerror(errno));
      return -1;
    }
  }
  return 0;
}

/* Read /sys/class/input/<sysname>/capabilities/ev and confirm the kernel
   agrees about what this device can emit.

   Why bother, when every ioctl above was checked: the ioctls say what we
   *asked for*, this says what we *got*. They can differ — every
   UI_SET_*BIT must precede UI_DEV_CREATE, and a future edit that moves
   one after it would still see all the ioctls succeed while the created
   device silently lacks the bits. That is precisely a change in one
   place breaking something far away, discovered as mysteriously dropped
   input. Checking costs one small file read at startup.

   The file is whitespace-separated hex words, most significant first;
   EV_* codes are all < 32, so the last word holds every bit we care
   about. */
static int verify_capabilities(int fd, uint32_t caps) {
  char sysname[SYSNAME_BUF_SIZE];
  if (ioctl(fd, UI_GET_SYSNAME(SYSNAME_BUF_SIZE), sysname) < 0) {
    fprintf(stderr, "uinput: UI_GET_SYSNAME: %s\n", strerror(errno));
    return -1;
  }

  char path[PATH_MAX];
  int n = snprintf(path, sizeof(path), "/sys/class/input/%s/capabilities/ev",
                   sysname);
  if (n < 0 || (size_t)n >= sizeof(path)) {
    fprintf(stderr, "uinput: capabilities path too long\n");
    return -1;
  }

  FILE *f = fopen(path, "re");
  if (!f) {
    fprintf(stderr, "uinput: open(%s): %s\n", path, strerror(errno));
    return -1;
  }
  char line[256];
  char *got = fgets(line, sizeof(line), f);
  fclose(f);
  if (!got) {
    fprintf(stderr, "uinput: %s is empty\n", path);
    return -1;
  }

  const char *last = line;
  for (const char *p = line; *p; p++)
    if (*p == ' ')
      last = p + 1;
  unsigned long long ev = strtoull(last, NULL, 16);

  struct {
    unsigned bit;
    const char *name;
    int required;
  } want[] = {
      {EV_SYN, "EV_SYN", 1},
      {EV_ABS, "EV_ABS", (caps & UINPUT_CAP_POINTER_ABS) != 0},
      {EV_KEY, "EV_KEY", (caps & UINPUT_CAP_KEYBOARD) != 0},
  };
  int bad = 0;
  for (size_t i = 0; i < sizeof(want) / sizeof(want[0]); i++) {
    if (!want[i].required)
      continue;
    if (!(ev & (1ull << want[i].bit))) {
      fprintf(stderr,
              "uinput: device %s came up WITHOUT %s (capabilities/ev=0x%llx). "
              "every UI_SET_*BIT must precede UI_DEV_CREATE.\n",
              sysname, want[i].name, ev);
      bad = 1;
    }
  }
  return bad ? -1 : 0;
}

static int wait_for_device_ready(int fd) {
  char bufs[SYSNAME_BUF_SIZE];
  if (ioctl(fd, UI_GET_SYSNAME(SYSNAME_BUF_SIZE), bufs) < 0) {
    fprintf(stderr, "uinput: UI_GET_SYSNAME error\n");
    return -1;
  }
  
  char bufp[PATH_MAX];
  int n = snprintf(bufp, PATH_MAX, "/sys/class/input/%s", bufs);
  if (n < 0 || n >= PATH_MAX) {
    fprintf(stderr, "uinput: error creating PATH\n");
    return -1;
  }

  struct timespec start;
  struct timespec now;
  if (clock_gettime(CLOCK_MONOTONIC, &start) < 0) {
    fprintf(stderr, "uinput: error getting start TIME\n");
    return -1;
  }
 
  while (1) {
    if (access(bufp, F_OK) == 0) {
      return 0;
    }
    if (errno != ENOENT) {
      fprintf(stderr, "uinput: access(%s): %s\n", bufp, strerror(errno));
      return -1;
    }
    if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) {
      fprintf(stderr, "uinput: error getting now TIME\n");
      return -1;
    }
    long elapsed_time = (now.tv_sec - start.tv_sec) * 1000L +
                        (now.tv_nsec - start.tv_nsec) / 1000000L;

    if (elapsed_time >= UINPUT_READY_TIMEOUT_MS) {
      fprintf(
          stderr,
          "device %s did not appear in /sys/class/input within timelimit of "
          "%d ms; proceeding (first event might be dropped)\n",
          bufp, UINPUT_READY_TIMEOUT_MS);
      return -1;
    }
    struct timespec poll = {.tv_nsec = UINPUT_READY_POLL_MS * 1000000L,
                            .tv_sec = 0};
    if (nanosleep(&poll, NULL) < 0 && errno != EINTR) {
      fprintf(stderr, "uinput: nanosleep: %s\n", strerror(errno));
      return -1;
    }
  }
  return -1;
}

/* Register the pointer device's abilities. Everything here must run
   before UI_DEV_CREATE -- see the note at the call site. */
static int build_pointer(int fd) {
  if (set_evbit(fd, EV_SYN) < 0 || set_evbit(fd, EV_ABS) < 0 ||
      set_evbit(fd, EV_REL) < 0 || set_evbit(fd, EV_KEY) < 0)
    return -1;
  if (set_absbit(fd, ABS_X) < 0 || set_absbit(fd, ABS_Y) < 0)
    return -1;
  if (abs_setup(fd, ABS_X) < 0 || abs_setup(fd, ABS_Y) < 0)
    return -1;

  /* REL_WHEEL_HI_RES/REL_HWHEEL_HI_RES alongside the classic notches:
     a device that sends only notches scrolls coarsely under a modern
     compositor, one that sends only hi-res is invisible to anything that
     never learned about them. Real hardware sends both. */
  static const unsigned rel_axes[] = {REL_X, REL_Y, REL_WHEEL, REL_HWHEEL,
                                      REL_WHEEL_HI_RES, REL_HWHEEL_HI_RES};
  for (size_t i = 0; i < sizeof(rel_axes) / sizeof(rel_axes[0]); i++) {
    if (ioctl(fd, UI_SET_RELBIT, rel_axes[i]) < 0) {
      fprintf(stderr, "uinput: UI_SET_RELBIT(%u): %s\n", rel_axes[i],
              strerror(errno));
      return -1;
    }
  }

  for (size_t i = 0; i < POINTER_BUTTON_COUNT; i++) {
    if (ioctl(fd, UI_SET_KEYBIT, pointer_buttons[i]) < 0) {
      fprintf(stderr, "uinput: UI_SET_KEYBIT(0x%x): %s\n", pointer_buttons[i],
              strerror(errno));
      return -1;
    }
  }

  /* M5.5 task 1, and the single most important line for how this device
     is treated. ABS_X/ABS_Y *plus* buttons is ambiguous: libinput's
     classifier reads that same bit pattern as a touchscreen, a graphics
     tablet or an absolute mouse, and a touchscreen sends touch sequences
     rather than pointer motion. INPUT_PROP_POINTER is the explicit
     declaration that removes the guess. */
  if (ioctl(fd, UI_SET_PROPBIT, INPUT_PROP_POINTER) < 0) {
    fprintf(stderr, "uinput: UI_SET_PROPBIT(INPUT_PROP_POINTER): %s\n",
            strerror(errno));
    return -1;
  }
  return 0;
}

static int build_keyboard(int fd) {
  if (set_evbit(fd, EV_SYN) < 0)
    return -1;
  return set_all_keybits(fd);
}

/* Open /dev/uinput, let `build` declare what the device can do, then
   create it and confirm from sysfs that the kernel agrees. One function
   for both devices: the ordering rules below are identical for each, and
   two copies of them is two chances to get one wrong. */
static int open_device(const char *name, uint16_t product, uint32_t caps,
                       int (*build)(int fd)) {
  int fd = open("/dev/uinput", O_WRONLY | O_CLOEXEC);
  if (fd < 0) {
    if (errno == EACCES) {
      fprintf(stderr,
              "uinput: cannot open /dev/uinput: %s\n"
              " are you in the 'input' group? run 'id' to check.\n",
              strerror(errno));
    } else {
      fprintf(stderr, "uinput: open(/dev/uinput): %s\n", strerror(errno));
    }
    return -1;
  }

  /* Ordering is load-bearing: the kernel snapshots the device's
     capabilities at UI_DEV_CREATE, so a UI_SET_*BIT after it is silently
     too late. Everything that declares an ability is inside build(),
     above the UI_DEV_SETUP/UI_DEV_CREATE pair, and verify_capabilities()
     re-checks the result from sysfs rather than trusting it. */
  if (build(fd) < 0)
    goto fail;

  struct uinput_setup setup = {0};
  setup.id.bustype = BUS_VIRTUAL;
  setup.id.vendor = 0x1d6b;
  setup.id.product = product;
  setup.id.version = 1;
  strncpy(setup.name, name, UINPUT_MAX_NAME_SIZE - 1);
  if (ioctl(fd, UI_DEV_SETUP, &setup) < 0) {
    fprintf(stderr, "uinput: UI_DEV_SETUP(%s): %s\n", name, strerror(errno));
    goto fail;
  }
  if (ioctl(fd, UI_DEV_CREATE) < 0) {
    fprintf(stderr, "uinput: UI_DEV_CREATE(%s): %s\n", name, strerror(errno));
    goto fail;
  }

  (void)wait_for_device_ready(fd);

  /* Fatal, not a warning. A device missing a capability produces dropped
     or EINVAL-ing input later, far from the cause. */
  if (verify_capabilities(fd, caps) < 0) {
    ioctl(fd, UI_DEV_DESTROY);
    goto fail;
  }
  return fd;

fail: {
  int save = errno;
  close(fd);
  errno = save;
  return -1;
}
}

int uinput_open(struct uinput_devs *devs, uint32_t *caps_out) {
  /* Before anything else: a malformed deny table means keys we believe
     are blocked are not, and the daemon must not run in that state. */
  if (uinput_denylist_selftest() != 0) {
    fprintf(stderr, "uinput: key deny-list is malformed, refusing to start\n");
    return -1;
  }
  if (!devs || !caps_out) {
    fprintf(stderr, "uinput: uinput_open() needs somewhere to report the "
                    "devices and caps\n");
    return -1;
  }
  /* Zeroed up front and only written on full success: a caller that
     ignores the return value still cannot end up advertising abilities
     the devices do not have. */
  *caps_out = 0;
  devs->pointer = -1;
  devs->keyboard = -1;

  const uint32_t pointer_caps =
      UINPUT_CAP_POINTER_ABS | UINPUT_CAP_POINTER_REL | UINPUT_CAP_BUTTONS;
  const uint32_t keyboard_caps = UINPUT_CAP_KEYBOARD;

  /* The pointer keeps the name it has had since M3 (decision 1: never
     rename, compositors key per-device config off it). The keyboard is
     new, so it gets product 0x0002 — a second device from the same
     vendor, which is how real hardware presents a composite device. */
  int pfd = open_device("uictl virtual pointer", 0x0001, pointer_caps,
                        build_pointer);
  if (pfd < 0)
    return -1;
  int kfd = open_device("uictl virtual keyboard", 0x0002, keyboard_caps,
                        build_keyboard);
  if (kfd < 0) {
    /* All or nothing. A daemon with a pointer and no keyboard would
       start, advertise CAP_KEYBOARD nowhere, and fail every key request
       at the device layer — a half-built state nobody would think to
       check for. */
    ioctl(pfd, UI_DEV_DESTROY);
    close(pfd);
    return -1;
  }

  g_devs[0].fd = pfd;
  g_devs[0].caps = pointer_caps;
  g_devs[1].fd = kfd;
  g_devs[1].caps = keyboard_caps;
  devs->pointer = pfd;
  devs->keyboard = kfd;
  *caps_out = pointer_caps | keyboard_caps;
  return 0;
}

static void close_one(int fd) {
  if (fd < 0)
    return;
  for (size_t i = 0; i < MAX_DEVS; i++) {
    if (g_devs[i].fd == fd) {
      /* Cleared before the fd is closed: an fd number is reused almost
         immediately, and a stale entry would let a primitive accept a
         completely unrelated fd that happens to reuse the number. */
      g_devs[i].fd = -1;
      g_devs[i].caps = 0;
    }
  }
  if (ioctl(fd, UI_DEV_DESTROY) < 0)
    fprintf(stderr, "uinput: UI_DEV_DESTROY: %s\n", strerror(errno));
  if (close(fd) < 0)
    fprintf(stderr, "uinput: close: %s\n", strerror(errno));
}

void uinput_close(struct uinput_devs *devs) {
  if (!devs)
    return;
  close_one(devs->pointer);
  close_one(devs->keyboard);
  devs->pointer = -1;
  devs->keyboard = -1;
}

/* One write() for a whole event frame, shared by every primitive.

   Single write, not one per event: the kernel treats each write as a
   batch and a partial write would leave the device holding half a frame
   — a pressed key with no release, or a motion with no SYN_REPORT — with
   no way to know how much landed. Short write is therefore an error and
   never a retry: retrying from an unknown offset is how you turn a
   glitch into a stuck key.

   `what` names the caller in the error, so a failure says which
   primitive failed rather than just "write". */
static int write_event_frame(int fd, const struct input_event *evs, size_t n,
                             const char *what) {
  size_t bytes = n * sizeof(*evs);
  ssize_t w = write(fd, evs, bytes);
  if (w < 0) {
    fprintf(stderr, "uinput: %s: write: %s\n", what, strerror(errno));
    return -1;
  }
  if ((size_t)w != bytes) {
    fprintf(stderr, "uinput: %s: short write %zd of %zu bytes — device frame "
                    "is now incomplete\n",
            what, w, bytes);
    return -1;
  }
  return 0;
}

/* Is this fd the device we built, and does it have this capability?

   The fd alone says nothing — it is just a number, and M5.5 plans to
   split pointer and keyboard into two devices. When that lands, passing
   the pointer fd to a key primitive must fail loudly here rather than
   write EV_KEY events into a device that never declared them (which the
   kernel silently drops, producing "the key did nothing" with no error
   anywhere). Until then this also catches a caller that skipped
   uinput_open() entirely. */
static int device_supports(int fd, uint32_t cap, const char *what) {
  for (size_t i = 0; i < MAX_DEVS; i++) {
    if (fd < 0 || g_devs[i].fd != fd)
      continue;
    if (!(g_devs[i].caps & cap)) {
      /* The M5.5 case this check was written for a milestone early:
         the pointer fd handed to a key primitive, or the keyboard fd to
         a scroll. The kernel would silently drop those events, and the
         symptom — "it did nothing" with no error anywhere — is the one
         this refuses to produce. */
      fprintf(stderr,
              "uinput: %s: fd %d lacks capability 0x%x (has 0x%x) — wrong "
              "device for this primitive\n",
              what, fd, cap, g_devs[i].caps);
      return 0;
    }
    return 1;
  }
  fprintf(stderr, "uinput: %s: fd %d is not one of this module's devices\n",
          what, fd);
  return 0;
}

int uinput_move_abs(int fd, int32_t x, int32_t y) {
  if (!device_supports(fd, UINPUT_CAP_POINTER_ABS, "move_abs"))
    return -1;

  struct input_event evs[3] = {0};
  evs[0] = (struct input_event){.type = EV_ABS, .code = ABS_X, .value = x};
  evs[1] = (struct input_event){.type = EV_ABS, .code = ABS_Y, .value = y};
  evs[2] = (struct input_event){.type = EV_SYN, .code = SYN_REPORT, .value = 0};

  return write_event_frame(fd, evs, 3, "move_abs");
}

int uinput_move_rel(int fd, int32_t dx, int32_t dy) {
  if (!device_supports(fd, UINPUT_CAP_POINTER_REL, "move_rel"))
    return -1;
  /* A zero-zero nudge is refused rather than sent. The kernel drops
     no-op frames anyway; refusing here means a client that computed a
     delta wrong learns it instead of watching nothing happen. */
  if (dx == 0 && dy == 0) {
    fprintf(stderr, "uinput: move_rel: both deltas are zero\n");
    return -1;
  }

  /* Only the non-zero axes are emitted. A REL_Y 0 in the frame is not
     harmful, but real hardware does not send it, and a consumer counting
     events per frame sees a shape it recognises. */
  struct input_event evs[3] = {0};
  size_t n = 0;
  if (dx)
    evs[n++] = (struct input_event){.type = EV_REL, .code = REL_X, .value = dx};
  if (dy)
    evs[n++] = (struct input_event){.type = EV_REL, .code = REL_Y, .value = dy};
  evs[n++] = (struct input_event){.type = EV_SYN, .code = SYN_REPORT, .value = 0};
  return write_event_frame(fd, evs, n, "move_rel");
}

int uinput_scroll(int fd, int32_t notches_v, int32_t notches_h) {
  if (!device_supports(fd, UINPUT_CAP_POINTER_REL, "scroll"))
    return -1;
  if (notches_v == 0 && notches_h == 0) {
    fprintf(stderr, "uinput: scroll: both axes are zero\n");
    return -1;
  }

  /* Notch and hi-res together, in one frame, per axis. The hi-res value
     is the authoritative one for modern libinput and the notch is what
     everything older reads; sending one without the other means either
     coarse jumps or nothing at all depending on the consumer. */
  struct input_event evs[5] = {0};
  size_t n = 0;
  if (notches_v) {
    evs[n++] = (struct input_event){
        .type = EV_REL, .code = REL_WHEEL, .value = notches_v};
    evs[n++] = (struct input_event){
        .type = EV_REL,
        .code = REL_WHEEL_HI_RES,
        .value = notches_v * UINPUT_WHEEL_HI_RES_PER_NOTCH};
  }
  if (notches_h) {
    evs[n++] = (struct input_event){
        .type = EV_REL, .code = REL_HWHEEL, .value = notches_h};
    evs[n++] = (struct input_event){
        .type = EV_REL,
        .code = REL_HWHEEL_HI_RES,
        .value = notches_h * UINPUT_WHEEL_HI_RES_PER_NOTCH};
  }
  evs[n++] = (struct input_event){.type = EV_SYN, .code = SYN_REPORT, .value = 0};
  return write_event_frame(fd, evs, n, "scroll");
}

int uinput_button(int fd, uint16_t code, int down) {
  if (!device_supports(fd, UINPUT_CAP_BUTTONS, "button"))
    return -1;
  /* Device-layer validity, not policy: this device registered exactly
     five button codes and the kernel would drop anything else without a
     word. Which buttons a *client* may press is decided one layer up. */
  if (!uinput_is_button(code)) {
    fprintf(stderr, "uinput: button: 0x%x is not a registered button\n", code);
    return -1;
  }
  struct input_event evs[2] = {0};
  evs[0] = (struct input_event){
      .type = EV_KEY, .code = code, .value = down ? 1 : 0};
  evs[1] = (struct input_event){.type = EV_SYN, .code = SYN_REPORT, .value = 0};
  return write_event_frame(fd, evs, 2, "button");
}

/* ---- destructive-key deny-list (M4 step 6) --------------------------
   Default-DENY is not what this is. This is a static blocklist of keys
   that are destructive or system-controlling; the per-user allowlist
   (step 8) is the default-deny half, and a key will have to pass both.
   Shipping the blocklist first means the dangerous set is unreachable
   from the moment injection exists, rather than after configuration.

   Written as ranges because several of these come in contiguous blocks,
   and a range is one line that cannot drift out of sync with itself the
   way twelve singles can. `why` is what the audit log records.

   Adding to this list is cheap and safe. REMOVING from it is the
   dangerous direction and should be a deliberate, argued change. */
static const struct {
  uint16_t lo;
  uint16_t hi;
  const char *why;
} key_deny[] = {
    /* Power and session control: one keystroke, session gone. */
    {KEY_POWER, KEY_POWER, "power"},
    {KEY_POWER2, KEY_POWER2, "power"},
    {KEY_SLEEP, KEY_SLEEP, "suspend"},
    {KEY_SUSPEND, KEY_SUSPEND, "suspend"},
    {KEY_RESTART, KEY_RESTART, "restart"},
    {KEY_LOGOFF, KEY_LOGOFF, "logoff"},

    /* SysRq. Alt+SysRq+<letter> talks straight to the kernel — reboot,
       kill everything, remount read-only. A virtual keyboard that can
       press it is a virtual keyboard that can end the machine. */
    {KEY_SYSRQ, KEY_SYSRQ, "sysrq"},

    /* Radios: turning these off can disconnect the very session an
       operator would use to stop the daemon. */
    {KEY_RFKILL, KEY_RFKILL, "rfkill"},
    {KEY_BLUETOOTH, KEY_BLUETOOTH, "radio"},
    {KEY_WLAN, KEY_WLAN, "radio"},
    {KEY_UWB, KEY_UWB, "radio"},

    /* Physical actuation of hardware. */
    {KEY_EJECTCD, KEY_EJECTCLOSECD, "eject"},

    /* Brightness: zero brightness is indistinguishable from a dead
       display, and recovering needs the screen you just turned off. */
    {KEY_BRIGHTNESSDOWN, KEY_BRIGHTNESSUP, "brightness"},
    {KEY_BRIGHTNESS_CYCLE, KEY_BRIGHTNESS_AUTO, "brightness"},
    {KEY_BRIGHTNESS_MIN, KEY_BRIGHTNESS_MAX, "brightness"},

    /* Firmware/EC-level function keys — vendor-defined, unpredictable,
       and not something a broker should be able to synthesise. */
    {KEY_FN, KEY_FN_RIGHT_SHIFT, "fn block"},

    /* Braille and phone-numeric blocks: no legitimate consumer here, and
       an unused surface is a surface worth closing. */
    {KEY_BRL_DOT1, KEY_BRL_DOT10, "braille block"},
    {KEY_NUMERIC_0, KEY_NUMERIC_D, "numeric block"},
};

#define KEY_DENY_COUNT (sizeof(key_deny) / sizeof(key_deny[0]))

int uinput_denylist_selftest(void) {
  int bad = 0;
  for (size_t i = 0; i < KEY_DENY_COUNT; i++) {
    /* A swapped lo/hi silently denies nothing — the loop below would
       never match — so a typo would quietly disarm an entry. Catch it
       at startup instead. */
    if (key_deny[i].lo > key_deny[i].hi) {
      fprintf(stderr, "uinput: deny entry %zu inverted (%u > %u, '%s')\n", i,
              key_deny[i].lo, key_deny[i].hi, key_deny[i].why);
      bad = 1;
    }
    if (key_deny[i].hi > KEY_MAX) {
      fprintf(stderr, "uinput: deny entry %zu exceeds KEY_MAX (%u > %u)\n", i,
              key_deny[i].hi, (unsigned)KEY_MAX);
      bad = 1;
    }
    if (key_deny[i].lo == KEY_RESERVED) {
      fprintf(stderr, "uinput: deny entry %zu starts at 0\n", i);
      bad = 1;
    }
    if (!key_deny[i].why || !key_deny[i].why[0]) {
      fprintf(stderr, "uinput: deny entry %zu has no reason string\n", i);
      bad = 1;
    }
  }
  return bad;
}

int uinput_keycode_denied(uint16_t code, const char **why_out) {
  for (size_t i = 0; i < KEY_DENY_COUNT; i++) {
    if (code >= key_deny[i].lo && code <= key_deny[i].hi) {
      if (why_out)
        *why_out = key_deny[i].why;
      return 1;
    }
  }
  return 0;
}

int uinput_key_seq(int fd, const struct uinput_key_event *evs, size_t n) {
  if (!device_supports(fd, UINPUT_CAP_KEYBOARD, "key_seq"))
    return -1;
  if (n == 0 || n > UINPUT_SEQ_MAX_EVENTS) {
    fprintf(stderr, "uinput: key_seq: %zu events, allowed 1..%d\n", n,
            UINPUT_SEQ_MAX_EVENTS);
    return -1;
  }

  /* +1 for the trailing SYN_REPORT: one frame, one report, however many
     transitions it carries. That is M3 decision 5 doing the work it was
     written for — the whole reason SYN is emitted per *request* and not
     per event is so a modifier and its key land together. */
  struct input_event frame[UINPUT_SEQ_MAX_EVENTS + 1] = {0};
  for (size_t i = 0; i < n; i++) {
    if (evs[i].code == KEY_RESERVED || evs[i].code > KEY_MAX) {
      fprintf(stderr, "uinput: key_seq: keycode %u out of range 1..%u\n",
              evs[i].code, KEY_MAX);
      return -1;
    }
    if (evs[i].value > 1) {
      fprintf(stderr, "uinput: key_seq: value %u is not 0 or 1\n",
              evs[i].value);
      return -1;
    }
    frame[i] = (struct input_event){
        .type = EV_KEY, .code = evs[i].code, .value = evs[i].value};
  }
  frame[n] =
      (struct input_event){.type = EV_SYN, .code = SYN_REPORT, .value = 0};

  return write_event_frame(fd, frame, n + 1, "key_seq");
}

int uinput_key_tap(int fd, uint16_t code) {
  if (!device_supports(fd, UINPUT_CAP_KEYBOARD, "key_tap"))
    return -1;
  /* Range only. Whether this key is *allowed* is not decided here —
     that is the daemon's deny-list, one layer up. This rejects what the
     kernel itself could not accept, so a bug shows up as a named error
     instead of an EINVAL from write(). */
  if (code == KEY_RESERVED || code > KEY_MAX) {
    fprintf(stderr, "uinput: key_tap: keycode %u out of range 1..%u\n", code,
            KEY_MAX);
    return -1;
  }

  struct input_event evs[3] = {0};
  evs[0] = (struct input_event){.type = EV_KEY, .code = code, .value = 1};
  evs[1] = (struct input_event){.type = EV_KEY, .code = code, .value = 0};
  evs[2] = (struct input_event){.type = EV_SYN, .code = SYN_REPORT, .value = 0};

  /* One SYN_REPORT at the end, not one after the press — M3 decision 5:
     the daemon emits exactly one per *request*, never per event, which
     is what makes M4's modifier-then-key-then-release atomic later.
     Press and release therefore land in the same event frame, i.e. a
     zero-duration tap.

     Known risk, worth remembering rather than discovering: real hardware
     always separates press from release by a SYN and by milliseconds,
     and a consumer that measures key duration or filters zero-length
     presses could ignore this. If step 7's `key-tap 30` → 'a' demo shows
     nothing on a real compositor, splitting this into two frames is the
     first thing to try — the primitive is the only place that changes. */
  return write_event_frame(fd, evs, 3, "key_tap");
}
