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

LIB_SRCS = src/lib/libuictl.c
LIB_HDRS = src/lib/uictl.h src/proto.h

# The CLI links libuictl rather than encoding frames itself (M-lib
# task 2). One encoder in this tree, and it is the one WIRE.md §9's
# vectors are checked against.
uictl: src/uictl.c libuictl.a $(LIB_HDRS)
	$(CC) $(CFLAGS) src/uictl.c libuictl.a -o $@ $(LDFLAGS)

uictl-confirm: src/uictl-confirm.c src/proto.h
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

uictld:	$(UICTLD_SRCS) $(UICTLD_HDRS)
	$(CC) $(CFLAGS) $(UICTLD_SRCS) -o $@ $(LDFLAGS)

# libuictl (M-lib task 2). Not in `all`: nothing in this repo links it
# yet -- the CLI predates it -- so building it by default would only
# produce artefacts nobody consumes. `make lib` builds both forms.
lib: libuictl.a libuictl.so

libuictl.a: $(LIB_SRCS) $(LIB_HDRS)
	$(CC) $(CFLAGS) -c $(LIB_SRCS) -o src/lib/libuictl.o
	$(AR) rcs $@ src/lib/libuictl.o

# -fPIC replaces -fPIE and -shared replaces -pie, and the swap is the
# whole reason this rule is separate rather than reusing the object
# above. Everything else in the hardening block is kept verbatim: RELRO,
# BIND_NOW, noexecstack and the stack protector all apply to a shared
# object exactly as they do to an executable, and a library built softer
# than the binaries that link it is the soft target.
libuictl.so: $(LIB_SRCS) $(LIB_HDRS)
	$(CC) $(filter-out -fPIE,$(CFLAGS)) -fPIC -shared $(LIB_SRCS) -o $@ \
		$(filter-out -pie,$(LDFLAGS))

# ---- user-scope systemd install (M6) --------------------------------
# User units only. There is deliberately no system-wide install target:
# the daemon runs as the user and its only privilege is `input` group
# membership, and a system unit would have to run it as root or as a
# dedicated user -- which turns "the broker is the only thing that needs
# that membership" into "the broker needs more than the user has".
#
# ExecStart is rewritten rather than templated, so the file in systemd/
# stays a valid unit that `systemd-analyze verify` can check as shipped.
USER_UNIT_DIR ?= $(HOME)/.config/systemd/user

install-user: uictld uictl uictl-confirm systemd/uictld.socket systemd/uictld.service
	install -d -m 0755 $(USER_UNIT_DIR)
	install -m 0644 systemd/uictld.socket $(USER_UNIT_DIR)/uictld.socket
	sed -e 's|^ExecStart=.*|ExecStart=$(CURDIR)/uictld|' \
	    -e 's|^Documentation=file:.*|Documentation=file:$(CURDIR)/WIRE.md|' \
	    systemd/uictld.service > $(USER_UNIT_DIR)/uictld.service
	chmod 0644 $(USER_UNIT_DIR)/uictld.service
	@echo
	@echo "installed to $(USER_UNIT_DIR), ExecStart=$(CURDIR)/uictld"
	@echo "next:  systemctl --user daemon-reload"
	@echo "       systemctl --user enable --now uictld.socket"
	@echo
	@echo "note:  enable the SOCKET, not the service. the socket exists"
	@echo "       from login and the daemon starts on the first connect."

uninstall-user:
	rm -f $(USER_UNIT_DIR)/uictld.socket $(USER_UNIT_DIR)/uictld.service
	@echo "removed the units. run: systemctl --user daemon-reload"

# proto.json (M-lib task 3) -- the machine-readable schema. Generated,
# committed, and checked: layout comes from src/proto.h, result classes
# and hints come from libuictl by calling it, so the three consumers
# (client opcode tables, the spec's op list, and auto-c v2.x's LLM tool
# definitions) all descend from one source instead of three copies.
proto.json: tests/gen_proto_json.c $(LIB_HDRS) libuictl.a
	@$(CC) $(CFLAGS) $< libuictl.a -o gen-proto-json $(LDFLAGS) \
		&& ./gen-proto-json > $@ && rm -f gen-proto-json
	@echo "wrote $@"

# WIRE.md §9's conformance vectors are generated from src/proto.h rather
# than typed, so a field that moves in the header moves in the document.
# Not part of `all`: it is a documentation tool, not a shipped binary,
# and tests/test_wire9_vectors.py builds it itself.
gen-vectors: tests/gen_vectors.c src/proto.h
	@$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS) && ./$@ && rm -f $@

.PHONY: all clean lib gen-vectors install-user uninstall-user
clean:
	rm -f uictl uictld uictl-confirm gen-vectors \
	  libuictl.a libuictl.so src/lib/libuictl.o lib-smoke \
	  gen-proto-json
