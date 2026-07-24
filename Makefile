CC ?= cc
override CFLAGS += -D_FORTIFY_SOURCE=2 -fstack-protector-strong \
	-Wformat -Wformat-security -Werror=format-security \
	-fPIE -Wall -Wextra -Wconversion -g -std=c11 -D_GNU_SOURCE
override LDFLAGS += -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack

all: uictl uictld

UICTLD_SRCS = src/uictld.c src/platform/uinput.c
UICTLD_HDRS = src/proto.h src/platform/uinput.h

uictl: src/uictl.c src/proto.h
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

uictld:	$(UICTLD_SRCS) $(UICTLD_HDRS)
	$(CC) $(CFLAGS) $(UICTLD_SRCS) -o $@ $(LDFLAGS)

.PHONY: all clean
clean:
	rm -f uictl uictld 
