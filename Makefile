CC ?= cc
override CFLAGS += -D_FORTIFY_SOURCE=2 -fstack-protector-strong \
	-Wformat -Wformat-security -Werror=format-security \
	-fPIE -Wall -Wextra -Wconversion -g -std=c11 -D_GNU_SOURCE
override LDFLAGS += -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack

# Three binaries now, not two. The daemon and the CLI have different
# threat profiles (plan.md), and uictl-confirm has a third: it is the
# only client the daemon ever pushes to, and it is the piece a human
# looks at. Same flags for all three -- a helper compiled without the
# hardening block would be the soft target.
all: uictl uictld uictl-confirm

UICTLD_SRCS = src/uictld.c src/platform/uinput.c
UICTLD_HDRS = src/proto.h src/platform/uinput.h

uictl: src/uictl.c src/proto.h
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

uictl-confirm: src/uictl-confirm.c src/proto.h
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

uictld:	$(UICTLD_SRCS) $(UICTLD_HDRS)
	$(CC) $(CFLAGS) $(UICTLD_SRCS) -o $@ $(LDFLAGS)

# WIRE.md §9's conformance vectors are generated from src/proto.h rather
# than typed, so a field that moves in the header moves in the document.
# Not part of `all`: it is a documentation tool, not a shipped binary,
# and tests/test_wire9_vectors.py builds it itself.
gen-vectors: tests/gen_vectors.c src/proto.h
	@$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS) && ./$@ && rm -f $@

.PHONY: all clean gen-vectors
clean:
	rm -f uictl uictld uictl-confirm gen-vectors
