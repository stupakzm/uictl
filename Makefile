CC ?= cc
override CFLAGS += -D_FORTIFY_SOURCE=2 -fstack-protector-strong \
	-Wformat -Wformat-security -Werror=format-security \
	-fPIE -Wall -Wextra -Wconversion -g -std=c11 -D_GNU_SOURCE
override LDFLAGS += -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack

all: uictl uictld

uictl: src/uictl.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

uictld: src/uictld.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

.PHONY: all clean
clean:
	rm -f uictl uictld 
