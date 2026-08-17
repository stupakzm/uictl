#!/usr/bin/env python3
"""M3.6 task 2: the OP_HELLO handshake frame (gap G2, first half).

L  a well-formed HELLO is accepted, audited with name and proto range,
   and shows up in the SIGUSR1 dump as the connection's name.
M  a second HELLO on the same connection is refused with
   ERR_DENIED_BY_POLICY (terminal -- renaming mid-connection is the
   per-frame self-assertion G2 exists to kill), and the first name
   survives.
N  malformed payloads are refused with ERR_PAYLOAD_INVALID and the
   connection stays usable: wrong size, empty name, unterminated name,
   junk after the NUL, inverted proto range.
O  **audit-log injection**: a client_name containing a newline must not
   be able to forge an audit line. This is the reason the character set
   is restricted at all.
P  task 7: PING stays usable without a handshake (liveness probe) but
   MOVE_ABS -- and any unknown opcode -- is refused with
   ERR_HANDSHAKE_REQUIRED, which is correctable: HELLO on the same
   connection and the same request then succeeds.
Q  task 3: the HELLO response carries the capability payload, the
   advertised opcode/capability bits match what the daemon actually
   implements, and `reserved` is zero -- an unnamed padding word would
   be uninitialised stack bytes on the wire.
R  task 3: an *error* response carries no payload, so a client never has
   to wonder whether a failed HELLO left it a half-filled struct.
"""
import os, signal, socket, struct, subprocess, sys, time
import uictl_expect          # the advertised opcode set, shared

SOCK = os.path.join(os.environ["XDG_RUNTIME_DIR"], "uictld.sock")
AUDIT = os.path.expanduser("~/.local/state/uictl/audit.log")
HDR = "<HHIII"
OP_PING, OP_MOVE_ABS, OP_HELLO = 1, 2, 3
OK, ERR_PAYLOAD_INVALID, ERR_DENIED_BY_POLICY = 0, 3, 4
NAME_MAX = 32
ok = True

# This suite injects device opcodes but never reads a device, so it has
# no reason to open a node -- which is exactly why it was missed. The
# grab is purely to keep those events off the live session; MOVE_ABS is
# not policy-gated, and an ungrabbed one moves the real pointer. Held
# for the whole run and released by process exit, including on a crash.
# run_all.py deliberately does not do this on the suite's behalf: then
# running this file directly would still inject into the session.
_GRABS = uictl_expect.grab_all()


def fail(msg):
    global ok
    print("FAIL:", msg)
    ok = False


def hello_payload(name: bytes, lo=1, hi=1, pad=b""):
    body = name + b"\x00" * (NAME_MAX - len(name) - len(pad)) + pad
    return struct.pack("<HH", lo, hi) + body


def frame(op, payload=b"", seq=1, ver=1):
    return struct.pack(HDR, ver, op, 1, seq, len(payload)) + payload


def conn():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(SOCK)
    s.settimeout(5)
    return s


def reply(s):
    """Read one whole response frame -> (result, data bytes)."""
    h = s.recv(16)
    if len(h) != 16:
        return None, b""
    plen = struct.unpack(HDR, h)[4]
    body = b""
    while len(body) < plen:
        chunk = s.recv(plen - len(body))
        if not chunk:
            break
        body += chunk
    if len(body) < 2:
        return None, b""
    return struct.unpack_from("<H", body, 0)[0], body[2:]


def result_of(s):
    return reply(s)[0]


audit0 = open(AUDIT).read()

# --- L: a good handshake ---------------------------------------------
a = conn()
a.sendall(frame(OP_HELLO, hello_payload(b"muvor-test"), seq=11))
res, data = reply(a)
if res != OK:
    fail("L: well-formed HELLO refused with result=%s" % res)
else:
    print("L HELLO accepted")

# --- Q: the capability answer ----------------------------------------
CAP_POINTER_ABS, CAP_KEYBOARD = 1 << 0, 1 << 1
CAP_POINTER_REL, CAP_BUTTONS = 1 << 2, 1 << 3   # M5.5
if len(data) < 24:
    fail("Q: HELLO response carried %d bytes, expected >= 24" % len(data))
else:
    (proto_sel, caps, absmax, opmap, dver,
     reserved) = struct.unpack_from("<HHIQII", data, 0)
    print("Q caps: proto=%d device=0x%x abs=0..%d opcodes=0x%x daemon=%d.%d.%d"
          % (proto_sel, caps, absmax, opmap,
             (dver >> 16) & 0xff, (dver >> 8) & 0xff, dver & 0xff))
    if proto_sel != 1:
        fail("Q: proto_selected=%d, expected 1" % proto_sel)
    if absmax != 32767:
        fail("Q: abs_range_max=%d, expected 32767 (INT16_MAX)" % absmax)
    # advertised opcodes must be the ones that actually work
    if opmap != uictl_expect.EXPECTED_BITMAP:
        fail("Q: opcode_bitmap=0x%x does not match the implemented set (%s)"
             % (opmap, uictl_expect.describe(opmap)))
    if opmap & 1:
        fail("Q: bit 0 (OP_INVALID) is set")
    # device_caps tracks the real device, so it grows as milestones land:
    # CAP_KEYBOARD arrived with M4 step 1. What must NOT grow with it is
    # the opcode bitmap above -- capability is not permission.
    if caps != (CAP_POINTER_ABS | CAP_KEYBOARD | CAP_POINTER_REL |
                CAP_BUTTONS):
        fail("Q: device_caps=0x%x -- expected all four (M5.5 added "
             "pointer-rel and buttons) "
             "(buttons/rel are M5.5)" % caps)
    # the whole reason `reserved` is a named field rather than padding
    if reserved != 0:
        fail("Q: reserved=0x%x -- uninitialised bytes are leaking onto the "
             "wire" % reserved)
    # An unadvertised opcode must actually be refused. Since task 7 this
    # needs a handshake first -- pre-handshake every opcode answers
    # ERR_HANDSHAKE_REQUIRED, which is case P's job to check.
    u = conn()
    u.sendall(frame(OP_HELLO, hello_payload(b"probe")))
    result_of(u)
    u.sendall(frame(63, b"", seq=2))
    if result_of(u) != 2:            # ERR_OPCODE_UNKNOWN
        fail("Q: an opcode outside the bitmap was not refused")
    u.close()

# --- M: only one HELLO per connection --------------------------------
a.sendall(frame(OP_HELLO, hello_payload(b"renamed"), seq=12))
res, errdata = reply(a)
if res != ERR_DENIED_BY_POLICY:
    fail("M: duplicate HELLO got result=%s, expected ERR_DENIED_BY_POLICY" % res)
else:
    print("M duplicate HELLO refused (terminal, not retryable)")

# --- R: errors carry no payload --------------------------------------
if errdata:
    fail("R: error response carried %d bytes of payload" % len(errdata))
else:
    print("R error response is a bare result code")

# --- O: the audit log must not be forgeable --------------------------
inject = conn()
forged = b"evil\npid=1 uid=0 src=0x0 op=MOVE_ABS seq=1 result=0 args=owned"
inject.sendall(frame(OP_HELLO, hello_payload(forged[:NAME_MAX - 1])))
res = result_of(inject)
if res != ERR_PAYLOAD_INVALID:
    fail("O: newline in client_name got result=%s, expected "
         "ERR_PAYLOAD_INVALID" % res)
else:
    print("O newline in client_name refused")
inject.close()

# --- N: the rest of the malformed set --------------------------------
cases = [
    ("wrong payload size", frame(OP_HELLO, b"\x01\x00\x01\x00short")),
    ("empty name", frame(OP_HELLO, hello_payload(b""))),
    ("unterminated name", frame(OP_HELLO, struct.pack("<HH", 1, 1) +
                                b"a" * NAME_MAX)),
    ("junk past the NUL", frame(OP_HELLO, hello_payload(b"ok", pad=b"\x01"))),
    ("inverted proto range", frame(OP_HELLO, hello_payload(b"ok", lo=9, hi=2))),
    ("shell metachars", frame(OP_HELLO, hello_payload(b"a;rm -rf /"))),
    ("terminal escape", frame(OP_HELLO, hello_payload(b"a\x1b[2J"))),
]
for label, f in cases:
    c = conn()
    c.sendall(f)
    res = result_of(c)
    if res != ERR_PAYLOAD_INVALID:
        fail("N: %s got result=%s, expected ERR_PAYLOAD_INVALID" % (label, res))
    else:
        # connection must survive a bad payload -- it is a per-frame error,
        # not a framing error, so the next frame boundary is still known
        c.sendall(frame(OP_PING, seq=2))
        if result_of(c) != OK:
            fail("N: connection unusable after %s" % label)
    c.close()
if ok:
    print("N %d malformed HELLOs refused, connections stayed usable"
          % len(cases))

# --- L (cont): SIGUSR1 shows the name --------------------------------
pids = subprocess.run(["pgrep", "-x", "uictld"], capture_output=True,
                      text=True).stdout.split()
dumped = None
if len(pids) == 1:
    # the daemon prints to its own stderr; we can only check it does not
    # die and that the audit trail is right, unless we own the process.
    os.kill(int(pids[0]), signal.SIGUSR1)
    time.sleep(0.3)
    dumped = subprocess.run(["pgrep", "-x", "uictld"],
                            capture_output=True, text=True).stdout.split()
    if dumped != pids:
        fail("L: daemon died on SIGUSR1 after HELLO")
    else:
        print("L SIGUSR1 dump survived (name column: see daemon stderr)")

# --- S: version range intersection (task 4) --------------------------
# This daemon declares 1-1, so only the no-overlap and self-contradiction
# paths are reachable here; test_m36_version.py builds a daemon with a
# wider range to exercise selection and pinning.
ERR_VERSION = 1
v = conn()
# stamped v2, inside its own declared range: HELLO is the version-invariant
# bootstrap frame, so the daemon admits it and answers the *real* objection
v.sendall(frame(OP_HELLO, hello_payload(b"fromfuture", lo=2, hi=5), ver=2))
res, vdata = reply(v)
if res != ERR_VERSION:
    fail("S: non-overlapping range got result=%s, expected ERR_VERSION" % res)
elif vdata:
    fail("S: ERR_VERSION response carried a payload")
else:
    print("S non-overlapping proto range refused with ERR_VERSION")

# a failed negotiation is per-frame, not fatal: the connection lives and
# the client may try again with a range it can actually offer
v.sendall(frame(OP_HELLO, hello_payload(b"retry", lo=1, hi=5), seq=2))
res, rdata = reply(v)
if res != OK:
    fail("S: retry after a failed negotiation got result=%s" % res)
elif struct.unpack_from("<H", rdata, 0)[0] != 1:
    fail("S: selected proto %d, expected 1" %
         struct.unpack_from("<H", rdata, 0)[0])
else:
    print("S overlapping range accepted on retry, selected proto=1")
v.close()

# a frame whose own header version falls outside the range it declares
t = conn()
t.sendall(struct.pack(HDR, 1, OP_HELLO, 1, 1, 36) +
          hello_payload(b"liar", lo=2, hi=5)[:36])
res = result_of(t)
# header v1 is inside the daemon's range so the frame is admitted, then
# rejected by the handler for contradicting itself
if res != ERR_PAYLOAD_INVALID:
    fail("T: self-contradicting HELLO got result=%s, expected "
         "ERR_PAYLOAD_INVALID" % res)
else:
    print("T HELLO whose header version is outside its own range refused")
t.close()

# --- P: handshake enforcement (task 7) -------------------------------
# Inverted from what it asserted before task 7, on purpose: MOVE_ABS
# without a handshake used to be fine and is now refused.
ERR_HANDSHAKE_REQUIRED = 8
p = conn()
p.sendall(frame(OP_PING, seq=3))
if result_of(p) != OK:
    fail("P: PING without HELLO refused -- PING is the exempt liveness probe")
else:
    print("P PING is still usable as a bare liveness probe")

p.sendall(frame(OP_MOVE_ABS, struct.pack("<ii", 300, 400), seq=4))
if result_of(p) != ERR_HANDSHAKE_REQUIRED:
    fail("P: MOVE_ABS without HELLO was not refused with "
         "ERR_HANDSHAKE_REQUIRED")
else:
    print("P MOVE_ABS before HELLO refused with ERR_HANDSHAKE_REQUIRED")

# an unknown opcode pre-handshake must ALSO say "handshake first", not
# leak which opcodes exist
p.sendall(frame(63, b"", seq=5))
if result_of(p) != ERR_HANDSHAKE_REQUIRED:
    fail("P: unknown opcode pre-handshake leaked ERR_OPCODE_UNKNOWN")
else:
    print("P pre-handshake refusal does not reveal the opcode surface")

# correctable, not terminal: say HELLO on this same connection and the
# same request now works
p.sendall(frame(OP_HELLO, hello_payload(b"late"), seq=6))
if result_of(p) != OK:
    fail("P: HELLO after a refused op was itself refused")
p.sendall(frame(OP_MOVE_ABS, struct.pack("<ii", 300, 400), seq=7))
if result_of(p) != OK:
    fail("P: MOVE_ABS still refused after a successful handshake")
else:
    print("P the same request succeeds once the handshake is done")
p.close()
a.close()

# --- audit assertions ------------------------------------------------
new = open(AUDIT).read()[len(audit0):]
lines = new.splitlines()

good = [l for l in lines if "op=HELLO" in l and "name=muvor-test" in l]
if not good:
    fail("L: no audit line for the accepted HELLO")
elif "proto=1 asked=1-1" not in good[0]:
    fail("L: audit line missing the selected version or the asked range: %s"
         % good[0])
elif "class=" not in good[0]:
    fail("L: audit line missing the derived class: %s" % good[0])
else:
    print("L audited:", good[0].split("op=")[1].strip())

if not [l for l in lines if "duplicate hello" in l]:
    fail("M: duplicate HELLO was not audited")

# O is the real assertion: no forged line, and the rejected name is not
# echoed into the log even in sanitised form.
if [l for l in lines if "args=owned" in l or "uid=0" in l]:
    fail("O: FORGED AUDIT LINE -- newline in client_name reached the log")
elif [l for l in lines if "evil" in l]:
    fail("O: rejected client_name was echoed into the audit log")
else:
    print("O no forged audit line, rejected name never echoed")

print("\n== PASS ==" if ok else "\n== FAIL ==")
sys.exit(0 if ok else 1)
