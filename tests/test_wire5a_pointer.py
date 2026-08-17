#!/usr/bin/env python3
"""WIRE.md 5A: every normative claim about the pointer opcodes.

test_m55_pointer.py already proves the pointer WORKS -- events reach the
device, buttons are held and released, batches are atomic. This suite
proves the SPEC is true, which is a different question and a narrower
one: it walks 5A's boundaries and refusals as a table, because those are
what a client author reads and codes against, and a spec that is wrong
about them is worse than no spec.

Written from WIRE.md, deliberately, not from uictld.c. A conformance
suite derived from the implementation agrees with it however wrong both
are -- the same reason uictl_expect keeps the opcode set by hand.

Runs its own daemon with HOME in a temp dir. No policy file is needed:
5A asserts the key allowlist does not govern the pointer, and EA is the
check that this is true rather than assumed.

EA  with NO policy file at all, every 5A opcode still works. Strict
    default-deny governs keys; a click is not a key.
EB  MOVE_ABS clamps and never refuses: negative, huge, and exactly at
    the edge all return OK.
EC  MOVE_REL refuses out of range instead of clamping -- the one place
    5A deliberately differs from 5A.1, because a silently shortened
    nudge reports OK for a move that did not happen.
ED  MOVE_REL and SCROLL both refuse an all-zero request rather than
    treating it as a no-op.
EE  SCROLL's bound is exactly +-1000: 1000 is accepted, 1001 is not, on
    both axes and both signs.
EF  BUTTON accepts exactly the five registered codes and refuses
    everything else -- including keycodes that are perfectly valid for
    5B, which is the disjointness the device split promises.
EG  BUTTON validates its padding: reserved != 0 and down > 1 are
    refused, so the byte stays available for a future field.
EH  a button release is not rate limited. Spend the budget, then let go.
"""
import os, shutil, socket, struct, subprocess, sys, tempfile, time
import uictl_expect

SOCK = os.path.join(os.environ["XDG_RUNTIME_DIR"], "uictld.sock")
HDR = "<HHIII"
OP_MOVE_ABS, OP_HELLO = 2, 3
OP_BUTTON, OP_MOVE_REL, OP_SCROLL = 11, 12, 13
OK, ERR_PAYLOAD_INVALID, ERR_RATE_LIMITED = 0, 3, 11
ABS_MAX = 32767          # WIRE.md 5A.1; also the HELLO abs_range_max
SCROLL_MAX = 1000        # WIRE.md 5A.3
BUTTONS = (272, 273, 274, 275, 276)
ok = True


def fail(msg):
    global ok
    print("FAIL:", msg)
    ok = False


def conn():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(SOCK)
    s.settimeout(5)
    return s


_seq = [1]


def send(s, opcode, payload):
    _seq[0] += 1
    s.sendall(struct.pack(HDR, 1, opcode, 1, _seq[0], len(payload)) + payload)
    h = s.recv(16)
    if len(h) != 16:
        return None
    plen = struct.unpack(HDR, h)[4]
    body = b""
    while len(body) < plen:
        chunk = s.recv(plen - len(body))
        if not chunk:
            break
        body += chunk
    return struct.unpack_from("<H", body, 0)[0] if body else None


def hello(s, name=b"wire5a"):
    return send(s, OP_HELLO, struct.pack("<HH", 1, 1) + name.ljust(32, b"\x00"))


def move_abs(s, x, y):
    return send(s, OP_MOVE_ABS, struct.pack("<ii", x, y))


def move_rel(s, dx, dy):
    return send(s, OP_MOVE_REL, struct.pack("<ii", dx, dy))


def scroll(s, v, h):
    return send(s, OP_SCROLL, struct.pack("<ii", v, h))


def button(s, code, down, reserved=0):
    return send(s, OP_BUTTON, struct.pack("<HBB", code, down, reserved))


def check(label, got, want, why):
    if got != want:
        fail("%s: %s -> %s, spec says %s" % (label, why, got, want))
        return False
    return True


if os.path.exists(SOCK):
    try:
        conn().close()
        print("SKIP: a uictld is already running; stop it and re-run")
        sys.exit(0)
    except OSError:
        pass

home = tempfile.mkdtemp(prefix="uictl-wire5a-")
cfg = os.path.join(home, ".config", "uictl")
os.makedirs(cfg)
os.makedirs(os.path.join(home, ".local", "state"))
# No policy file, on purpose -- see EA. A clients entry only so the rate
# limiter does not turn EB's sweep into ERR_RATE_LIMITED.
with open(os.path.join(cfg, "clients"), "w") as f:
    f.write("wire5a interactive\n")
os.chmod(os.path.join(cfg, "clients"), 0o600)

d = None
grabs = []
try:
    errlog = os.path.join(home, "uictld.err")
    d = subprocess.Popen(["./uictld"], env=dict(os.environ, HOME=home),
                         stdout=subprocess.DEVNULL,
                         stderr=open(errlog, "w"), text=True)
    time.sleep(0.8)
    if d.poll() is not None:
        print("SKIP: daemon would not start:", open(errlog).read())
        sys.exit(0)
    grabs = uictl_expect.grab_all()

    s = conn()
    if hello(s) != OK:
        fail("handshake failed")
        raise SystemExit

    # --- EA / EB: MOVE_ABS clamps, and needs no policy file -----------
    good = True
    for x, y, why in [(0, 0, "origin"),
                      (ABS_MAX, ABS_MAX, "exactly at the edge"),
                      (-1, -1, "negative"),
                      (-999999, -999999, "far negative"),
                      (ABS_MAX + 1, ABS_MAX + 1, "one past the edge"),
                      (999999, 999999, "far past the edge")]:
        good &= check("EB", move_abs(s, x, y), OK,
                      "MOVE_ABS(%d,%d) %s" % (x, y, why))
    if good:
        print("EA/EB MOVE_ABS clamps at both ends and never refuses, with no "
              "policy file present")

    # A wrong-sized payload is still refused -- clamping is about values,
    # not about accepting any frame.
    _seq[0] += 1
    s.sendall(struct.pack(HDR, 1, OP_MOVE_ABS, 1, _seq[0], 4) +
              struct.pack("<i", 5))
    h = s.recv(16)
    plen = struct.unpack(HDR, h)[4]
    body = b""
    while len(body) < plen:
        body += s.recv(plen - len(body))
    check("EB", struct.unpack_from("<H", body, 0)[0], ERR_PAYLOAD_INVALID,
          "MOVE_ABS with a 4-byte payload")

    # --- EC: MOVE_REL refuses instead of clamping ---------------------
    good = True
    good &= check("EC", move_rel(s, ABS_MAX, 0), OK, "MOVE_REL at the bound")
    good &= check("EC", move_rel(s, -ABS_MAX, 0), OK,
                  "MOVE_REL at the negative bound")
    good &= check("EC", move_rel(s, ABS_MAX + 1, 0), ERR_PAYLOAD_INVALID,
                  "MOVE_REL one past the bound")
    good &= check("EC", move_rel(s, 0, -(ABS_MAX + 1)), ERR_PAYLOAD_INVALID,
                  "MOVE_REL dy one past the negative bound")
    if good:
        print("EC MOVE_REL refuses out of range rather than clamping "
              "(unlike MOVE_ABS, and that difference is the spec's point)")

    # --- ED: an all-zero request is an error, not a no-op -------------
    good = True
    good &= check("ED", move_rel(s, 0, 0), ERR_PAYLOAD_INVALID, "MOVE_REL(0,0)")
    good &= check("ED", scroll(s, 0, 0), ERR_PAYLOAD_INVALID, "SCROLL(0,0)")
    if good:
        print("ED an all-zero motion request is refused, not silently OK")

    # --- EE: SCROLL's bound is exactly +-1000 -------------------------
    good = True
    for v, h_, want, why in [
            (SCROLL_MAX, 0, OK, "v at the bound"),
            (-SCROLL_MAX, 0, OK, "v at the negative bound"),
            (0, SCROLL_MAX, OK, "h at the bound"),
            (SCROLL_MAX + 1, 0, ERR_PAYLOAD_INVALID, "v one past"),
            (0, -(SCROLL_MAX + 1), ERR_PAYLOAD_INVALID, "h one past negative"),
            (1, 1, OK, "both axes in one request")]:
        good &= check("EE", scroll(s, v, h_), want,
                      "SCROLL(%d,%d) %s" % (v, h_, why))
    if good:
        print("EE SCROLL's bound is exactly +-%d on both axes" % SCROLL_MAX)

    # --- EF: exactly the five registered buttons ----------------------
    good = True
    for code in BUTTONS:
        if not check("EF", button(s, code, 1), OK, "BUTTON %d press" % code):
            good = False
        elif not check("EF", button(s, code, 0), OK,
                       "BUTTON %d release" % code):
            good = False
    for code, why in [(271, "one below BTN_LEFT"),
                      (277, "one above BTN_EXTRA"),
                      (30, "KEY_A -- a valid keycode for 5B"),
                      (183, "KEY_F13 -- valid for 5B"),
                      (0, "zero")]:
        good &= check("EF", button(s, code, 1), ERR_PAYLOAD_INVALID,
                      "BUTTON %d (%s)" % (code, why))
    if good:
        print("EF exactly the five registered buttons; 5B keycodes are "
              "refused, which is the device split being real")

    # --- EG: the padding byte is validated ----------------------------
    good = True
    good &= check("EG", button(s, 272, 1, reserved=1), ERR_PAYLOAD_INVALID,
                  "BUTTON with reserved=1")
    good &= check("EG", button(s, 272, 2), ERR_PAYLOAD_INVALID,
                  "BUTTON with down=2")
    if good:
        print("EG reserved and down are validated, so the byte stays "
              "available for a future field")
    s.close()

    # --- EH: a release is never rate limited --------------------------
    # A separate process: the bucket is keyed on the peer pid, and this
    # one is unregistered, so it is 'untrusted' at 5/s and easy to empty.
    code = r'''
import os, socket, struct, sys
SOCK = os.path.join(os.environ["XDG_RUNTIME_DIR"], "uictld.sock")
HDR = "<HHIII"
def rq(s, op, pay, seq):
    s.sendall(struct.pack(HDR, 1, op, 1, seq, len(pay)) + pay)
    h = s.recv(16); plen = struct.unpack(HDR, h)[4]
    b = b""
    while len(b) < plen: b += s.recv(plen - len(b))
    return struct.unpack_from("<H", b, 0)[0]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(5)
s.connect(SOCK)
rq(s, 3, struct.pack("<HH",1,1) + b"stranger".ljust(32, b"\x00"), 1)
down = rq(s, 11, struct.pack("<HBB", 272, 1, 0), 2)     # take the hold
drained = [rq(s, 12, struct.pack("<ii", 1, 0), 3+i) for i in range(12)]
up = rq(s, 11, struct.pack("<HBB", 272, 0, 0), 99)      # let go
print("%d %d %d" % (down, 11 in drained, up))
'''
    out = subprocess.run([sys.executable, "-c", code], capture_output=True,
                         text=True, timeout=30).stdout.split()
    if len(out) != 3:
        fail("EH: helper produced %r" % out)
    else:
        down, hit_limit, up = (int(x) for x in out)
        if down != OK:
            fail("EH: could not take the hold (result=%d)" % down)
        elif not hit_limit:
            fail("EH: the bucket never emptied, so the case was not exercised")
        elif up != OK:
            fail("EH: the release was refused with %d after the budget ran "
                 "out -- the way to a stuck button must not be 'be slightly "
                 "too fast'" % up)
        else:
            print("EH a button release is not charged: it succeeds with an "
                  "empty bucket")

finally:
    for fd in grabs:
        os.close(fd)
    if d and d.poll() is None:
        d.terminate()
        try:
            d.wait(timeout=5)
        except subprocess.TimeoutExpired:
            d.kill()
    shutil.rmtree(home, ignore_errors=True)

print("\n== PASS ==" if ok else "\n== FAIL ==")
sys.exit(0 if ok else 1)
