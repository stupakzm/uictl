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
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>
#include <stddef.h>


#define UINPUT_READY_TIMEOUT_MS 500
#define UINPUT_READY_POLL_MS 10
#define SYSNAME_BUF_SIZE 64

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

int uinput_open(void) {
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
  if (ioctl(fd, UI_DEV_DESTROY) < 0) {
    fprintf(stderr, "uinput: UI_DEV_DESTROY: %s\n", strerror(errno));
  }
  if (close(fd) < 0) {
    fprintf(stderr, "uinput: close: %s\n", strerror(errno));
  }
}

int uinput_move_abs(int fd, int32_t x, int32_t y) {
  struct input_event evs[3] = {0};
 
 
  evs[0] = (struct input_event){ .type = EV_ABS, .code = ABS_X, .value=x };
  evs[1] = (struct input_event){ .type = EV_ABS, .code = ABS_Y, .value=y };
  evs[2] = (struct input_event){ .type = EV_SYN, .code = SYN_REPORT, .value = 0};
  
  ssize_t w = write(fd, evs, sizeof(evs));
  if (w != (ssize_t)sizeof(evs)) {
    fprintf(stderr, "uinput: move_abs write frame %s\n", strerror(errno));
    return -1;
  }
  
  return 0;
}
