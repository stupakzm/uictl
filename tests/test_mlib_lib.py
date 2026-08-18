#!/usr/bin/env python3
"""M-lib 2: libuictl behaves the way WIRE.md says a client library must.

The library is a convenience for C consumers -- WIRE.md is the actual
deliverable -- but three of its behaviours are normative rather than
stylistic, and each one is a rule a library gets wrong by default:

  8.5  nothing with a device effect is ever replayed. A request in
       flight across a reconnect has an UNDEFINED outcome, so the
       library must hand it back as dropped and must not resend it. The
       natural implementation -- a queue that survives the reconnect and
       drains afterwards -- is the wrong one, and it is wrong in the
       direction of pressing keys the user never asked for.
  8.4  nothing negotiated survives a connection, so a reconnect
       re-handshakes rather than reusing the old capability set.
  8.8  a reconnect is visible. A callback fires on the way down and on
       the way up, because the user's held keys were released and their
       queued requests were dropped and they are entitled to know.

Plus the two things a library can check locally and should: a client
name the daemon would refuse (3.5) and an unbalanced key sequence
(5B.2). Both matter because the daemon charges the rate limit BEFORE it
validates -- a caller that learns about its own bad request from a round
trip has already paid for it out of a budget it may need to release a
key with.

Drives tests/lib_smoke.c, which links the library and prints one
KEY=value line per check. Injects NOTHING: every call is a handshake, a
probe, or a refusal, so this suite needs no EVIOCGRAB.

Shared mode: talks to a daemon that is already up.

LA  the library and its consumer build with the project's hardening
    flags, warnings and all.
LB  a bad client name is refused locally, with no socket opened.
LC  the handshake result is exposed: version, device caps, abs range,
    and a queryable opcode map.
LD  an opcode outside the daemon's map is refused by the library rather
    than sent.
LE  a daemon refusal arrives as a refusal, with the wire code and the
    4.2 class intact.
LF  three pipelined requests come back in request order.
LG  a synchronous call while requests are outstanding is a usage error,
    not a stolen response.
LH  a reconnect fires the callback both ways, re-handshakes, and hands
    back exactly one dropped request -- not a replayed one.
"""
import os, re, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
SOCK = os.path.join(os.environ["XDG_RUNTIME_DIR"], "uictld.sock")

# enum uictl_err, from src/lib/uictl.h. Duplicated here on purpose: a
# suite that parsed the header would agree with whatever the header said,
# including a renumbering that broke every consumer already compiled.
E_OK, E_ENV, E_SOCKET, E_IO, E_PROTO, E_REFUSED, E_DROPPED, E_USAGE, E_NOTSUP = range(9)
# enum uictl_class
CLASS_TERMINAL = 1
# WIRE.md 4.1
ERR_DENIED_BY_POLICY = 4

ok = True


def fail(msg):
    global ok
    ok = False
    print("FAIL: " + msg)


def skip(msg):
    print("SKIP: " + msg)
    sys.exit(0)


# ---- LA: it builds ----------------------------------------------------

b = subprocess.run(["make", "lib"], cwd=REPO, capture_output=True, text=True)
if b.returncode != 0:
    fail("LA: make lib failed:\n" + b.stderr[-2000:])
    print("\n== FAIL ==")
    sys.exit(1)

SMOKE = os.path.join(REPO, "lib-smoke")
cc = os.environ.get("CC", "cc")
b = subprocess.run([cc, "-D_FORTIFY_SOURCE=2", "-fstack-protector-strong",
                    "-fPIE", "-Wall", "-Wextra", "-Wconversion", "-g",
                    "-std=c11", "-D_GNU_SOURCE",
                    os.path.join(HERE, "lib_smoke.c"),
                    os.path.join(REPO, "libuictl.a"), "-o", SMOKE,
                    "-pie", "-Wl,-z,relro,-z,now"],
                   cwd=REPO, capture_output=True, text=True)
if b.returncode != 0:
    fail("LA: the consumer did not build:\n" + b.stderr[-2000:])
    print("\n== FAIL ==")
    sys.exit(1)
if b.stderr.strip():
    fail("LA: the consumer built with warnings:\n" + b.stderr[-2000:])
else:
    print("LA libuictl.a, libuictl.so and a consumer build clean")

if not os.path.exists(SOCK):
    skip("no daemon at %s (this suite is shared-mode)" % SOCK)

r = subprocess.run([SMOKE], cwd=REPO, capture_output=True, text=True,
                   timeout=60)
out = r.stdout
if r.returncode != 0:
    fail("LB-LH: the consumer exited %d\n%s%s" % (r.returncode, out, r.stderr))
    print("\n== FAIL ==")
    sys.exit(1)

V = dict(re.findall(r"^(\w+)=(.*)$", out, re.M))


def want(key, value, label):
    got = V.get(key)
    if got != value:
        fail("%s: %s=%r, want %r\n---\n%s" % (label, key, got, value, out))
        return False
    return True


# ---- LB ---------------------------------------------------------------
if want("BADNAME", str(E_USAGE), "LB"):
    print("LB a name the daemon would refuse is caught before a socket "
          "is opened")

# ---- LC ---------------------------------------------------------------
if V.get("CONNECT") != "ok":
    fail("LC: connect failed: %s" % out)
elif V.get("PROTO") != "1":
    fail("LC: proto_selected=%s, want 1" % V.get("PROTO"))
elif V.get("ABSMAX") != "32767":
    fail("LC: abs_range_max=%s, want 32767" % V.get("ABSMAX"))
elif V.get("HASPING") != "1" or V.get("HASBATCH") != "1":
    fail("LC: the opcode map does not report opcodes the daemon "
         "implements: %s" % out)
else:
    print("LC handshake exposed: proto=%s caps=%s absmax=%s, opcode map "
          "queryable" % (V["PROTO"], V["CAPS"], V["ABSMAX"]))

# ---- LD ---------------------------------------------------------------
if want("NOTSUP", str(E_NOTSUP), "LD"):
    print("LD an opcode outside the daemon's map is refused locally, "
          "not sent")

# ---- LE ---------------------------------------------------------------
if want("PING", "0", "LE") and want("UNBALANCED", str(E_USAGE), "LE"):
    m = re.search(r"^DUPHELLO=(\d+) result=(\d+) class=(\d+)$", out, re.M)
    if not m:
        fail("LE: no DUPHELLO line: %s" % out)
    elif int(m.group(1)) != E_REFUSED:
        fail("LE: a daemon refusal came back as err=%s, want %d"
             % (m.group(1), E_REFUSED))
    elif int(m.group(2)) != ERR_DENIED_BY_POLICY:
        fail("LE: wire result %s, want %d" % (m.group(2),
                                              ERR_DENIED_BY_POLICY))
    elif int(m.group(3)) != CLASS_TERMINAL:
        fail("LE: class %s, want terminal (%d)" % (m.group(3),
                                                   CLASS_TERMINAL))
    else:
        print("LE a refusal keeps its wire code and its 4.2 class; an "
              "unbalanced sequence never reaches the wire")

# ---- LF ---------------------------------------------------------------
if want("PIPEOUT", "3", "LF"):
    if V.get("PIPE") != "0,0,0 order=1":
        fail("LF: pipelined results %r, want three OKs in request order"
             % V.get("PIPE"))
    else:
        print("LF three pipelined requests answered in request order")

# ---- LG ---------------------------------------------------------------
if want("MIXED", str(E_USAGE), "LG"):
    print("LG a sync call with requests outstanding is refused, not "
          "answered with someone else's reply")

# ---- LH ---------------------------------------------------------------
m = re.search(r"^RECONNECT=(\d+) up=(\d+) down=(\d+)$", out, re.M)
d = re.search(r"^DROPPED=(\d+) count=(\d+)$", out, re.M)
if not m or not d:
    fail("LH: no reconnect lines: %s" % out)
elif m.group(1) != "0":
    fail("LH: reconnect failed err=%s" % m.group(1))
elif (m.group(2), m.group(3)) != ("1", "1"):
    fail("LH: state callback fired up=%s down=%s, want 1 and 1 "
         "(8.8 requires both edges)" % (m.group(2), m.group(3)))
elif V.get("PENDING") != "1":
    fail("LH: %s requests outstanding after the reconnect, want 1"
         % V.get("PENDING"))
elif int(d.group(1)) != E_DROPPED or d.group(2) != "1":
    fail("LH: drained %s request(s) with err=%s, want exactly 1 dropped "
         "(8.5 forbids replaying it)" % (d.group(2), d.group(1)))
elif V.get("REPROTO") != "1" or V.get("REPING") != "0":
    fail("LH: the reconnected connection did not re-handshake: %s" % out)
else:
    print("LH reconnect: callback both edges, one request dropped and "
          "not replayed, fresh handshake")

print("\n== PASS ==" if ok else "\n== FAIL ==")
sys.exit(0 if ok else 1)
