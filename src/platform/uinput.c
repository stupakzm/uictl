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

/* The one device this module owns, recorded at uinput_open() and cleared
   at uinput_close(). Not a convenience: it is what lets every primitive
   check that the fd handed to it is really our device and really has the
   capability being used, instead of writing events into whatever fd the
   caller passed. See device_supports(). */
static int g_dev_fd = -1;
static uint32_t g_dev_caps;

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

int uinput_open(uint32_t *caps_out) {
  /* Before anything else: a malformed deny table means keys we believe
     are blocked are not, and the daemon must not run in that state. */
  if (uinput_denylist_selftest() != 0) {
    fprintf(stderr, "uinput: key deny-list is malformed, refusing to start\n");
    return -1;
  }
  if (!caps_out) {
    fprintf(stderr, "uinput: uinput_open() needs somewhere to report caps\n");
    return -1;
  }
  /* Zeroed up front and only written on full success: a caller that
     ignores the return value still cannot end up advertising abilities
     the device does not have. */
  *caps_out = 0;

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

  if (set_evbit(fd, EV_ABS) < 0)
    goto fail;
  if (set_evbit(fd, EV_SYN) < 0)
    goto fail;
  if (set_absbit(fd, ABS_X) < 0)
    goto fail;
  if (set_absbit(fd, ABS_Y) < 0)
    goto fail;
  if (abs_setup(fd, ABS_X) < 0)
    goto fail;
  if (abs_setup(fd, ABS_Y) < 0)
    goto fail;
  uint32_t caps = UINPUT_CAP_POINTER_ABS;

  /* Ordering is load-bearing: the kernel snapshots the device's
     capabilities at UI_DEV_CREATE, so a UI_SET_*BIT after it is silently
     too late. Everything that declares an ability must be above the
     UI_DEV_SETUP/UI_DEV_CREATE pair below, and verify_capabilities()
     re-checks that from sysfs afterwards rather than trusting it. */
  if (set_all_keybits(fd) < 0)
    goto fail;
  caps |= UINPUT_CAP_KEYBOARD;

  struct uinput_setup setup = {0};
  setup.id.bustype = BUS_VIRTUAL;
  setup.id.vendor = 0x1d6b;
  setup.id.product = 0x0001;
  setup.id.version = 1;
  strncpy(setup.name, "uictl virtual pointer", UINPUT_MAX_NAME_SIZE - 1);
  if (ioctl(fd, UI_DEV_SETUP, &setup) < 0) {
    fprintf(stderr, "uinput: UI_DEV_SETUP: %s\n", strerror(errno));
    goto fail;
  }
  if (ioctl(fd, UI_DEV_CREATE) < 0) {
    fprintf(stderr, "uinput: UI_DEV_CREATE: %s\n", strerror(errno));
    goto fail;
  }

  (void)wait_for_device_ready(fd);

  /* Fatal, not a warning. A device missing a capability produces
     dropped or EINVAL-ing input later, far from the cause. */
  if (verify_capabilities(fd, caps) < 0) {
    ioctl(fd, UI_DEV_DESTROY);
    goto fail;
  }

  g_dev_fd = fd;
  g_dev_caps = caps;
  *caps_out = caps;
  return fd;

fail: {
  int save = errno;
  close(fd);
  errno = save;
  return -1;
}
}

void uinput_close(int fd) {
  if (fd < 0)
    return;
  if (fd == g_dev_fd) {
    /* Cleared before the fd is closed: an fd number is reused almost
       immediately, and a stale g_dev_fd would let a primitive accept a
       completely unrelated fd that happens to reuse the number. */
    g_dev_fd = -1;
    g_dev_caps = 0;
  }
  if (ioctl(fd, UI_DEV_DESTROY) < 0) {
    fprintf(stderr, "uinput: UI_DEV_DESTROY: %s\n", strerror(errno));
  }
  if (close(fd) < 0) {
    fprintf(stderr, "uinput: close: %s\n", strerror(errno));
  }
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
  if (fd < 0 || fd != g_dev_fd) {
    fprintf(stderr, "uinput: %s: fd %d is not this module's device (%d)\n",
            what, fd, g_dev_fd);
    return 0;
  }
  if (!(g_dev_caps & cap)) {
    fprintf(stderr, "uinput: %s: device lacks capability 0x%x (has 0x%x)\n",
            what, cap, g_dev_caps);
    return 0;
  }
  return 1;
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
