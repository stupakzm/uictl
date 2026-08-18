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

# ---- system install (M8) ---------------------------------------------
# The split closes ydotool-analysis §B5. The daemon goes to libexecdir,
# not bindir, and that is not tidiness: /usr/libexec is for programs
# started by other programs, and uictld is started by systemd or by a
# developer, never typed by a user. Putting it on $PATH invites someone
# to run a second copy by hand next to the socket-activated one -- which
# the flock singleton refuses, but only after both have been started and
# one has confused somebody.
#
# It is also the path M7's AppArmor profile attaches to. A profile keys
# on the executable's path, so until the daemon lives at
# /usr/libexec/uictld the profile confines nothing.
#
# DESTDIR and the *dir variables follow the GNU conventions so a
# packager can stage into a build root without patching this file.
prefix ?= /usr
exec_prefix ?= $(prefix)
bindir ?= $(exec_prefix)/bin
libexecdir ?= $(exec_prefix)/libexec
libdir ?= $(exec_prefix)/lib
includedir ?= $(prefix)/include
datarootdir ?= $(prefix)/share
datadir ?= $(datarootdir)
sysconfdir ?= /etc
# Units shipped by a package go under $(prefix)/lib, never /etc: /etc is
# the administrator's, and a package that writes there takes away their
# ability to override.
systemduserdir ?= $(prefix)/lib/systemd/user
apparmordir ?= $(sysconfdir)/apparmor.d

INSTALL ?= install

install: all lib proto.json
	$(INSTALL) -d -m 0755 $(DESTDIR)$(libexecdir)
	$(INSTALL) -m 0755 uictld $(DESTDIR)$(libexecdir)/uictld
	$(INSTALL) -d -m 0755 $(DESTDIR)$(bindir)
	$(INSTALL) -m 0755 uictl $(DESTDIR)$(bindir)/uictl
	$(INSTALL) -m 0755 uictl-confirm $(DESTDIR)$(bindir)/uictl-confirm
	$(INSTALL) -d -m 0755 $(DESTDIR)$(libdir)
	$(INSTALL) -m 0644 libuictl.a $(DESTDIR)$(libdir)/libuictl.a
	$(INSTALL) -m 0755 libuictl.so $(DESTDIR)$(libdir)/libuictl.so
	$(INSTALL) -d -m 0755 $(DESTDIR)$(includedir)/uictl
	$(INSTALL) -m 0644 src/lib/uictl.h $(DESTDIR)$(includedir)/uictl/uictl.h
	$(INSTALL) -d -m 0755 $(DESTDIR)$(libdir)/pkgconfig
	sed -e 's|@prefix@|$(prefix)|g' -e 's|@libdir@|$(libdir)|g' \
	    -e 's|@includedir@|$(includedir)|g' \
	    packaging/uictl.pc.in > $(DESTDIR)$(libdir)/pkgconfig/uictl.pc
	chmod 0644 $(DESTDIR)$(libdir)/pkgconfig/uictl.pc
	$(INSTALL) -d -m 0755 $(DESTDIR)$(datadir)/uictl
	$(INSTALL) -m 0644 proto.json $(DESTDIR)$(datadir)/uictl/proto.json
	$(INSTALL) -m 0644 WIRE.md $(DESTDIR)$(datadir)/uictl/WIRE.md
	$(INSTALL) -d -m 0755 $(DESTDIR)$(systemduserdir)
	$(INSTALL) -m 0644 systemd/uictld.socket \
	  $(DESTDIR)$(systemduserdir)/uictld.socket
	sed -e 's|^ExecStart=.*|ExecStart=$(libexecdir)/uictld|' \
	    -e 's|^Documentation=file:.*|Documentation=file:$(datadir)/uictl/WIRE.md|' \
	    systemd/uictld.service > $(DESTDIR)$(systemduserdir)/uictld.service
	chmod 0644 $(DESTDIR)$(systemduserdir)/uictld.service
	$(INSTALL) -d -m 0755 $(DESTDIR)$(apparmordir)
	$(INSTALL) -m 0644 apparmor/usr.libexec.uictld \
	  $(DESTDIR)$(apparmordir)/usr.libexec.uictld

uninstall:
	rm -f $(DESTDIR)$(libexecdir)/uictld
	rm -f $(DESTDIR)$(bindir)/uictl $(DESTDIR)$(bindir)/uictl-confirm
	rm -f $(DESTDIR)$(libdir)/libuictl.a $(DESTDIR)$(libdir)/libuictl.so
	rm -f $(DESTDIR)$(libdir)/pkgconfig/uictl.pc
	rm -f $(DESTDIR)$(includedir)/uictl/uictl.h
	rm -f $(DESTDIR)$(datadir)/uictl/proto.json
	rm -f $(DESTDIR)$(datadir)/uictl/WIRE.md
	rm -f $(DESTDIR)$(systemduserdir)/uictld.socket
	rm -f $(DESTDIR)$(systemduserdir)/uictld.service
	rm -f $(DESTDIR)$(apparmordir)/usr.libexec.uictld
	-rmdir $(DESTDIR)$(includedir)/uictl $(DESTDIR)$(datadir)/uictl 2>/dev/null

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

# ---- fuzzing (M8, closes analysis §B3) -------------------------------
# The harness #includes src/uictld.c so it can reach the daemon's static
# functions and drive the REAL frame path. Both device fds point at
# /dev/null, so nothing is injected and this is safe on a desktop and in
# CI, where there is no /dev/uinput at all.
#
# clang only, because -fsanitize=fuzzer is a clang feature. The
# reproducer below builds with any compiler for the case where the
# machine that hit a crash is not the machine with clang on it.
FUZZ_CC ?= clang
FUZZ_CFLAGS ?= -D_GNU_SOURCE -std=c11 -g -O1 -Wall -Wextra \
	-fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer

fuzz: fuzz-frame

fuzz-frame: fuzz/fuzz_frame.c $(UICTLD_SRCS) $(UICTLD_HDRS)
	$(FUZZ_CC) $(FUZZ_CFLAGS) -I src fuzz/fuzz_frame.c \
		src/platform/uinput.c -o $@

# No sanitizer and no libFuzzer: replays files named on the command line.
fuzz-frame-repro: fuzz/fuzz_frame.c $(UICTLD_SRCS) $(UICTLD_HDRS)
	$(CC) -D_GNU_SOURCE -std=c11 -g -Wall -DUICTL_FUZZ_STANDALONE \
		-I src fuzz/fuzz_frame.c src/platform/uinput.c -o $@

# Seeds the corpus from WIRE.md §9's vectors. Real frames reach the
# opcode handlers on the first run; random bytes spend the early campaign
# failing the header check.
fuzz-corpus:
	@mkdir -p fuzz/corpus
	@python3 fuzz/seed_corpus.py

# ---- static analysis --------------------------------------------------
# scan-build over the daemon, the library and both clients. Kept as a
# target rather than a CI-only invocation so it can be run before
# pushing, which is when a finding is cheap.
analyze:
	scan-build --status-bugs $(MAKE) -B all lib

# WIRE.md §9's conformance vectors are generated from src/proto.h rather
# than typed, so a field that moves in the header moves in the document.
# Not part of `all`: it is a documentation tool, not a shipped binary,
# and tests/test_wire9_vectors.py builds it itself.
gen-vectors: tests/gen_vectors.c src/proto.h
	@$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS) && ./$@ && rm -f $@

.PHONY: all clean lib gen-vectors install uninstall \
	 install-user uninstall-user fuzz fuzz-corpus analyze
clean:
	rm -f uictl uictld uictl-confirm gen-vectors \
	  libuictl.a libuictl.so src/lib/libuictl.o lib-smoke \
	  gen-proto-json fuzz-frame fuzz-frame-repro
