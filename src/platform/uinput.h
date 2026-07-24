#pragma once

#include <stdint.h>

#define ABS_RANGE_MAX INT16_MAX

int uinput_open(void);

void uinput_close(int fd);

int uinput_move_abs(int fd, int32_t x, int32_t y);
