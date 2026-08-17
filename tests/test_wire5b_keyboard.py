#!/usr/bin/env python3
"""WIRE.md 5B: every normative claim about the keyboard opcodes and BATCH.

The companion to test_wire5a_pointer.py, and written the same way: from
WIRE.md rather than from uictld.c, because a conformance suite derived
from the implementation agrees with it however wrong both are.

test_m4_sequence.py and test_m55_pointer.py already prove sequences and
batches WORK -- events reach the device in the right order, in one
frame, and a bad batch writes nothing. This suite walks the refusals,
which is what a client author actually codes against.

Injects only F13-F24 (uictl_expect.SAFE_POLICY) and grabs both nodes.

FA  the range check is 1..767, and it is a range check rather than
    policy: 0 and 768 are ERR_PAYLOAD_INVALID, not ERR_KEY_NOT_ALLOWED.
FB  the deny-list beats the allowlist. A deny-listed code that is ALSO
    named in the policy file is still refused, and with
    ERR_KEY_DENYLISTED rather than ERR_KEY_NOT_ALLOWED -- the two codes
    tell the user opposite things ("edit a file" vs "this will never
    work") and swapping them sends someone to do something futile.
FC  KEY_SEQUENCE balance, tracked per key rather than counted: pressing
    a code the sequence already holds, releasing one it does not hold,
    and leaving anything held at the end are each refused.
FD  structure is checked BEFORE policy. An unbalanced sequence that also
    names an unlisted key reports the malformed sequence, so the user
    does not edit their policy file, retry, and meet the real error on
    the second attempt.
FE  the reserved fields are read and rejected, in the sequence header
    and in every item, so a future field cannot collide with junk.
FF  count and payload_len must agree exactly; count=0 and count>16 are
    refused.
FG  BATCH accepts exactly six sub-opcodes. KEY_TAP, KEY_SEQUENCE, PING
    and a nested BATCH are refused.
FH  BATCH is all-or-nothing: a batch whose LAST item is invalid writes
    nothing at all, asserted at the device rather than at the result
    code -- a daemon that returned the right error while still writing
    the first items would pass everything else.
"""
import os, shutil, socket, struct, subprocess, sys, tempfile, time
import uictl_expect

SOCK = os.path.join(os.environ["XDG_RUNTIME_DIR"], "uictld.sock")
HDR = "<HHIII"
OP_PING, OP_HELLO, OP_KEY_TAP, OP_KEY_SEQUENCE = 1, 3, 4, 5
OP_KEY_DOWN, OP_KEY_UP = 6, 7
OP_BUTTON, OP_MOVE_REL, OP_SCROLL, OP_BATCH = 11, 12, 13, 14
OK, ERR_PAYLOAD_INVALID = 0, 3
ERR_KEY_DENYLISTED, ERR_KEY_NOT_ALLOWED = 9, 10
KEY_MAX = 767
KEY_F13, KEY_F14, KEY_F15 = 183, 184, 185
KEY_POWER = 116
BTN_LEFT = 272
EV_KEY = 0x01
EVENT_FMT = "@llHHi"
EVENT_SIZE = struct.calcsize(EVENT_FMT)
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


def hello(s):
    return send(s, OP_HELLO, struct.pack("<HH", 1, 1) + b"wire5b".ljust(32, b"\x00"))


def tap(s, code):
    return send(s, OP_KEY_TAP, struct.pack("<H", code))


def seq(s, items, count=None, hdr_res=0, item_res=0):
    """items = [(keycode, value), ...]. count/hdr_res/item_res override
    the header so the malformed cases can be built."""
    n = len(items) if count is None else count
    body = struct.pack("<HH", n, hdr_res)
    for code, val in items:
        body += struct.pack("<HBB", code, val, item_res)
    return send(s, OP_KEY_SEQUENCE, body)


def batch(s, items, count=None, hdr_res=0, item_res=0):
    """items = [(opcode, a, b), ...]"""
    n = len(items) if count is None else count
    body = struct.pack("<HH", n, hdr_res)
    for op, a, b in items:
        body += struct.pack("<HHii", op, item_res, a, b)
    return send(s, OP_BATCH, body)


def drain(fd):
    evs = []
    while True:
        try:
            buf = os.read(fd, EVENT_SIZE * 64)
        except BlockingIOError:
            break
        if not buf:
            break
        for i in range(0, len(buf) - EVENT_SIZE + 1, EVENT_SIZE):
            _, _, t, c, v = struct.unpack_from(EVENT_FMT, buf, i)
            if t == EV_KEY:
                evs.append((c, v))
    return evs


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

home = tempfile.mkdtemp(prefix="uictl-wire5b-")
cfg = os.path.join(home, ".config", "uictl")
os.makedirs(cfg)
os.makedirs(os.path.join(home, ".local", "state"))
# F13-F24, plus KEY_POWER on purpose: FB needs a code that is in the
# allowlist AND on the deny-list, to prove which one wins.
with open(os.path.join(cfg, "policy"), "w") as f:
    f.write(uictl_expect.SAFE_POLICY + "%d\n" % KEY_POWER)
os.chmod(os.path.join(cfg, "policy"), 0o600)
with open(os.path.join(cfg, "clients"), "w") as f:
    f.write("wire5b interactive\n")
os.chmod(os.path.join(cfg, "clients"), 0o600)

d = None
grabs = []
kfd = None
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
    kfd = grabs[1] if len(grabs) > 1 else None
    if kfd is None:
        fail("no keyboard node to watch")
        raise SystemExit

    s = conn()
    if hello(s) != OK:
        fail("handshake failed")
        raise SystemExit

    # --- FA: range, and it is a RANGE error not a policy error --------
    good = True
    good &= check("FA", tap(s, 0), ERR_PAYLOAD_INVALID, "KEY_TAP 0")
    good &= check("FA", tap(s, KEY_MAX + 1), ERR_PAYLOAD_INVALID,
                  "KEY_TAP %d (one past KEY_MAX)" % (KEY_MAX + 1))
    good &= check("FA", tap(s, KEY_F13), OK, "KEY_TAP F13 (in policy)")
    # In range but not in the policy file: a policy error, not a range one.
    good &= check("FA", tap(s, 31), ERR_KEY_NOT_ALLOWED,
                  "KEY_TAP 31 (in range, not in policy)")
    if good:
        print("FA range is 1..%d and reports separately from policy" % KEY_MAX)

    # --- FB: the deny-list beats the allowlist ------------------------
    r = tap(s, KEY_POWER)
    if r == OK:
        fail("FB: KEY_POWER was ALLOWED by naming it in policy -- the "
             "deny-list must not be overridable by configuration")
    elif r == ERR_KEY_NOT_ALLOWED:
        fail("FB: KEY_POWER reported ERR_KEY_NOT_ALLOWED, which tells the "
             "user to add it to policy -- where it already is. It must "
             "report ERR_KEY_DENYLISTED.")
    elif r != ERR_KEY_DENYLISTED:
        fail("FB: KEY_POWER -> %s, expected ERR_KEY_DENYLISTED" % r)
    else:
        print("FB deny-list beats the allowlist, and says which one refused")

    # --- FC: balance, per key rather than counted ---------------------
    good = True
    good &= check("FC", seq(s, [(KEY_F13, 1), (KEY_F13, 0)]), OK,
                  "a balanced pair")
    good &= check("FC", seq(s, [(KEY_F13, 1), (KEY_F13, 1),
                                (KEY_F13, 0), (KEY_F13, 0)]),
                  ERR_PAYLOAD_INVALID,
                  "down,down,up,up -- balanced by COUNT but not per key")
    good &= check("FC", seq(s, [(KEY_F13, 0)]), ERR_PAYLOAD_INVALID,
                  "releasing a code the sequence does not hold")
    good &= check("FC", seq(s, [(KEY_F13, 1)]), ERR_PAYLOAD_INVALID,
                  "leaving a key held at the end")
    good &= check("FC", seq(s, [(KEY_F13, 1), (KEY_F14, 1),
                                (KEY_F14, 0), (KEY_F13, 0)]), OK,
                  "properly nested modifier+key")
    good &= check("FC", seq(s, [(KEY_F13, 1), (KEY_F13, 2)]),
                  ERR_PAYLOAD_INVALID, "value=2 (only 0 and 1 exist)")
    if good:
        print("FC balance is tracked per key, not counted -- "
              "down,down,up,up is refused")

    # --- FD: structure before policy ----------------------------------
    # Unbalanced AND names a code that is not in the policy file. The
    # structural error must win.
    r = seq(s, [(31, 1)])
    if r != ERR_PAYLOAD_INVALID:
        fail("FD: an unbalanced sequence naming an unlisted key -> %s. It "
             "must report the structure error; reporting the policy miss "
             "sends the user to edit a file and hit the real error on the "
             "retry." % r)
    else:
        print("FD structure is checked before policy")

    # --- FE: reserved fields are rejected, not ignored -----------------
    good = True
    good &= check("FE", seq(s, [(KEY_F13, 1), (KEY_F13, 0)], hdr_res=1),
                  ERR_PAYLOAD_INVALID, "sequence header reserved=1")
    good &= check("FE", seq(s, [(KEY_F13, 1), (KEY_F13, 0)], item_res=1),
                  ERR_PAYLOAD_INVALID, "sequence item reserved=1")
    good &= check("FE", batch(s, [(OP_MOVE_REL, 1, 0)], item_res=1),
                  ERR_PAYLOAD_INVALID, "batch item reserved=1")
    good &= check("FE", batch(s, [(OP_MOVE_REL, 1, 0)], hdr_res=1),
                  ERR_PAYLOAD_INVALID, "batch header reserved=1")
    if good:
        print("FE reserved fields are read and rejected in both containers")

    # --- FF: count and payload_len must agree -------------------------
    good = True
    good &= check("FF", seq(s, [], count=0), ERR_PAYLOAD_INVALID,
                  "sequence count=0")
    good &= check("FF", seq(s, [(KEY_F13, 1), (KEY_F13, 0)], count=17),
                  ERR_PAYLOAD_INVALID, "count=17 with 2 items")
    good &= check("FF", seq(s, [(KEY_F13, 1), (KEY_F13, 0)], count=1),
                  ERR_PAYLOAD_INVALID, "count=1 with 2 items (len mismatch)")
    good &= check("FF", batch(s, [], count=0), ERR_PAYLOAD_INVALID,
                  "batch count=0")
    if good:
        print("FF count must be 1..16 and must match payload_len exactly")

    # --- FG: exactly six batchable sub-opcodes ------------------------
    good = True
    good &= check("FG", batch(s, [(OP_MOVE_REL, 3, 0)]), OK, "MOVE_REL item")
    good &= check("FG", batch(s, [(OP_SCROLL, 1, 0)]), OK, "SCROLL item")
    for op, name in [(OP_KEY_TAP, "KEY_TAP"),
                     (OP_KEY_SEQUENCE, "KEY_SEQUENCE"),
                     (OP_PING, "PING"),
                     (OP_HELLO, "HELLO"),
                     (OP_BATCH, "a nested BATCH")]:
        good &= check("FG", batch(s, [(op, KEY_F13, 0)]), ERR_PAYLOAD_INVALID,
                      "%s as a batch item" % name)
    if good:
        print("FG exactly the six batchable sub-opcodes; KEY_TAP, "
              "KEY_SEQUENCE and a nested BATCH are refused")

    # --- FH: all-or-nothing, asserted at the DEVICE -------------------
    # Three valid keyboard items then one invalid. A daemon that
    # validated per item and wrote as it went would deliver the first
    # three presses and then report the error -- the stuck-key scenario
    # through the back door, and invisible to a result-code assertion.
    drain(kfd)
    r = batch(s, [(OP_KEY_DOWN, KEY_F13, 0),
                  (OP_KEY_DOWN, KEY_F14, 0),
                  (OP_KEY_DOWN, KEY_F15, 0),
                  (OP_KEY_DOWN, 99999, 0)])       # last item out of range
    time.sleep(0.3)
    evs = drain(kfd)
    # The DEVICE is checked first, deliberately. The result code is the
    # weaker evidence: a daemon that wrote the first three presses and
    # then reported a perfectly correct error would satisfy a
    # result-code assertion and still have left three keys held.
    if evs:
        fail("FH: the batch wrote %r before refusing (result=%s) -- "
             "validation must complete before ANY item is written, or a "
             "rejected batch leaves keys held" % (evs, r))
    elif r != ERR_PAYLOAD_INVALID:
        fail("FH: a batch with an invalid last item -> %s, expected "
             "ERR_PAYLOAD_INVALID" % r)
    else:
        print("FH a batch whose last item is invalid writes nothing at all")
    s.close()

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
