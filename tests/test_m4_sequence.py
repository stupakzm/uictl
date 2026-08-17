#!/usr/bin/env python3
"""M4 step 9 (partial): OP_KEY_SEQUENCE, atomic and self-balancing.

OP_KEY_DOWN / OP_KEY_UP are NOT here and stay blocked on M4.5 -- they are
the ones that can strand a held key. A sequence cannot: the daemon
refuses any request that does not release everything it presses, so
nothing survives the request that created it.

Runs its own daemon with HOME in a temp dir so it owns the policy file,
and reads /dev/input/eventN to check what actually reached the device.
Requires no uictld running, plus read access to the event node.

ZZ  a balanced sequence lands as ONE frame: every key event, then a
    single SYN_REPORT. That is the atomicity modifier+key depends on.
AB  the press order is preserved and the releases run in reverse, which
    is what `uictl key-combo` builds.
AC  unbalanced requests are refused -- leftover press, double press,
    release of an unheld key -- and refused as ERR_PAYLOAD_INVALID,
    *before* any policy question, so the user is told about the real bug
    rather than a policy miss they would fix first for nothing.
AD  a rejected sequence emits NOTHING. Not the valid prefix, not a
    stray SYN. All-or-nothing is the entire safety argument.
AE  the deny-list and allowlist apply per item, with their own codes.
"""
import os, re, shutil, signal, socket, struct, subprocess, sys, tempfile, time
import uictl_expect          # shared: device nodes, opcode set

SOCK = os.path.join(os.environ["XDG_RUNTIME_DIR"], "uictld.sock")
DEVICES = "/proc/bus/input/devices"
DEV_NAME = "uictl virtual pointer"
HDR = "<HHIII"
OP_HELLO, OP_KEY_SEQUENCE = 3, 5
OK, ERR_PAYLOAD_INVALID = 0, 3
ERR_KEY_DENYLISTED, ERR_KEY_NOT_ALLOWED = 9, 10
EV_SYN, EV_KEY = 0x00, 0x01
SYN_REPORT = 0
CTRL, SHIFT, F13, F14, POWER = 29, 42, 183, 184, 116
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


def reply(s):
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


def send_seq(items, count=None, res0=0, res1=0):
    s = conn()
    b = struct.pack("<HH", 1, 1) + b"seqtest" + b"\x00" * 25
    s.sendall(struct.pack(HDR, 1, OP_HELLO, 1, 1, len(b)) + b)
    reply(s)
    n = len(items) if count is None else count
    pay = struct.pack("<HH", n, res0) + b"".join(
        struct.pack("<HBB", c, v, res1) for c, v in items)
    s.sendall(struct.pack(HDR, 1, OP_KEY_SEQUENCE, 1, 2, len(pay)) + pay)
    res = reply(s)
    s.close()
    return res


def event_node():
    """The KEYBOARD node since M5.5: key events moved there when the one
    hybrid device became a pointer and a keyboard. MOVE_ABS cases use
    pointer_node() instead."""
    return uictl_expect.keyboard_node()


def pointer_node():
    return uictl_expect.pointer_node()


def drain(fd, seconds=0.6):
    evs = []
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            buf = os.read(fd, EVENT_SIZE * 64)
        except BlockingIOError:
            time.sleep(0.02)
            continue
        for i in range(0, len(buf) - EVENT_SIZE + 1, EVENT_SIZE):
            _, _, typ, code, val = struct.unpack_from(EVENT_FMT, buf, i)
            evs.append((typ, code, val))
    return evs


if os.path.exists(SOCK):
    try:
        conn().close()
        print("SKIP: a uictld is already running; stop it and re-run")
        sys.exit(0)
    except OSError:
        pass

home = tempfile.mkdtemp(prefix="uictl-seq-")
d = None
try:
    cfg = os.path.join(home, ".config", "uictl")
    os.makedirs(cfg)
    os.makedirs(os.path.join(home, ".local", "state"))
    # Modifiers and F13/F14 only: a bare modifier does nothing and F13+
    # is unbound, so a full run is invisible on a real desktop.
    with open(os.path.join(cfg, "policy"), "w") as f:
        f.write("29 42 183 184\n")
    os.chmod(os.path.join(cfg, "policy"), 0o600)

    d = subprocess.Popen(["./uictld"], env=dict(os.environ, HOME=home),
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         text=True)
    time.sleep(0.8)
    if d.poll() is not None:
        print("SKIP: daemon would not start:", d.stderr.read())
        sys.exit(0)

    node = event_node()
    efd = None
    if node:
        try:
            efd = uictl_expect.open_node(node)
        except PermissionError:
            pass
    if efd is None:
        print("SKIP: cannot read the device's event node (need input group)")
        sys.exit(0)

    # --- ZZ / AB: one atomic frame, order preserved -------------------
    drain(efd, 0.2)
    combo = [(CTRL, 1), (F13, 1), (F13, 0), (CTRL, 0)]
    res = send_seq(combo)
    evs = drain(efd)
    if res != OK:
        fail("ZZ: balanced sequence refused (result=%s)" % res)
    else:
        want = [(EV_KEY, CTRL, 1), (EV_KEY, F13, 1), (EV_KEY, F13, 0),
                (EV_KEY, CTRL, 0), (EV_SYN, SYN_REPORT, 0)]
        if evs != want:
            fail("ZZ: device saw %s, expected %s" % (evs, want))
        else:
            print("ZZ ctrl+F13 landed as one frame: 4 key events, 1 SYN")
        syns = [e for e in evs if e[0] == EV_SYN]
        if len(syns) != 1:
            fail("ZZ: %d SYN_REPORTs -- a sequence must be ONE report, or it "
                 "is not atomic" % len(syns))
        elif evs[-1][0] != EV_SYN:
            fail("AB: the SYN did not come last")
        else:
            print("AB press order preserved, releases in reverse, SYN last")

    # --- AC / AD: refusals, and nothing reaching the device -----------
    cases = [
        ("leftover press", [(CTRL, 1), (F13, 1), (F13, 0)], ERR_PAYLOAD_INVALID),
        ("double press", [(CTRL, 1), (CTRL, 1), (CTRL, 0), (CTRL, 0)],
         ERR_PAYLOAD_INVALID),
        ("release unheld", [(CTRL, 0)], ERR_PAYLOAD_INVALID),
        ("value 2", [(CTRL, 2), (CTRL, 0)], ERR_PAYLOAD_INVALID),
        ("keycode 0", [(0, 1), (0, 0)], ERR_PAYLOAD_INVALID),
        ("denylisted", [(POWER, 1), (POWER, 0)], ERR_KEY_DENYLISTED),
        ("not in policy", [(30, 1), (30, 0)], ERR_KEY_NOT_ALLOWED),
    ]
    for label, items, want in cases:
        drain(efd, 0.2)
        got = send_seq(items)
        evs = drain(efd, 0.4)
        if got != want:
            fail("AC: %s got result=%s, expected %s" % (label, got, want))
        elif evs:
            fail("AD: %s was REFUSED but %s reached the device -- a rejected "
                 "sequence must emit nothing at all" % (label, evs))
    if ok:
        print("AC %d malformed/denied sequences refused with the right codes"
              % len(cases))
        print("AD none of them put a single event on the device")

    # a sequence whose FIRST item is fine and second is denied is the
    # dangerous one: a check-then-write loop would already have pressed
    # the first key.
    drain(efd, 0.2)
    got = send_seq([(CTRL, 1), (POWER, 1), (POWER, 0), (CTRL, 0)])
    evs = drain(efd, 0.4)
    if got != ERR_KEY_DENYLISTED:
        fail("AD: mixed sequence got result=%s, expected ERR_KEY_DENYLISTED"
             % got)
    elif evs:
        fail("AD: THE VALID PREFIX WAS INJECTED: %s -- ctrl is now held down "
             "with no release, which is exactly the stuck-key failure this "
             "design refuses to allow" % evs)
    else:
        print("AD a valid prefix before a denied key emits nothing either")

    # --- header validation --------------------------------------------
    hdr_cases = [
        ("count 0", ([], 0, 0, 0), ERR_PAYLOAD_INVALID),
        ("count mismatch", ([(CTRL, 1), (CTRL, 0)], 4, 0, 0),
         ERR_PAYLOAD_INVALID),
        ("header reserved", ([(CTRL, 1), (CTRL, 0)], None, 7, 0),
         ERR_PAYLOAD_INVALID),
        ("item reserved", ([(CTRL, 1), (CTRL, 0)], None, 0, 9),
         ERR_PAYLOAD_INVALID),
        ("over UICTL_SEQ_MAX", ([(183, 1), (183, 0)] * 9, None, 0, 0),
         ERR_PAYLOAD_INVALID),
    ]
    for label, (items, cnt, r0, r1), want in hdr_cases:
        got = send_seq(items, count=cnt, res0=r0, res1=r1)
        if got != want:
            fail("AC: %s got result=%s, expected %s" % (label, got, want))
    if ok:
        print("AC header/reserved/bounds violations refused too")

    os.close(efd)
    d.send_signal(signal.SIGTERM)
    try:
        d.wait(timeout=5)
    except subprocess.TimeoutExpired:
        d.kill()
    err, d = d.stderr.read(), None

    audit = open(os.path.join(home, ".local", "state", "uictl",
                              "audit.log")).read()
    if "op=KEY_SEQUENCE" not in audit:
        fail("no KEY_SEQUENCE audit lines")
    elif not re.search(r"op=KEY_SEQUENCE .*args=seq n=4: 29v 183v 183\^ 29\^",
                       audit):
        fail("the accepted sequence was not audited with its transitions")
    elif not [l for l in audit.splitlines() if "unbalanced" in l]:
        fail("an unbalanced sequence was not audited as such")
    else:
        print("-- audited with the actual transitions "
              "(29v 183v 183^ 29^) and the refusal reasons")
finally:
    if d is not None:
        d.terminate()
        try:
            d.wait(timeout=5)
        except subprocess.TimeoutExpired:
            d.kill()
    shutil.rmtree(home, ignore_errors=True)

print("\n== PASS ==" if ok else "\n== FAIL ==")
sys.exit(0 if ok else 1)
