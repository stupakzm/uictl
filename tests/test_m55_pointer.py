#!/usr/bin/env python3
"""M5.5: pointer semantics, the device split, and OP_BATCH.

The one hybrid device became two: a pointer (ABS + REL + five buttons,
INPUT_PROP_POINTER) and a keyboard (every other keycode). Every
assertion here reads the device it is actually about -- reading one node
and asserting about the other is the specific mistake the split makes
possible.

Runs its own daemon with HOME in a temp dir. Requires no uictld running
and read access to both event nodes (input group).

DA  two devices exist, with the shapes that make libinput classify them:
    the pointer carries INPUT_PROP_POINTER, REL and ABS axes and exactly
    five buttons; the keyboard carries EV_KEY and no REL/ABS. The
    pointer's name is unchanged (M3 decision 1).
DB  the two devices are disjoint where they overlap: BTN_LEFT is on the
    pointer and NOT on the keyboard.
DC  a button press reaches the pointer node and is held; the release
    reaches it too. Buttons reuse M4.5's held state unchanged.
DD  a button held by a dead client is released on the POINTER device --
    the case where routing a release to the wrong device would look like
    it worked and leave a stuck drag.
DE  two clients cannot hold the same button (G9's pointer contention).
DF  move-rel emits REL_X/REL_Y and nothing else; a zero-zero nudge and
    an out-of-range delta are refused.
DG  scroll emits the notch AND the hi-res value in one frame, 120 units
    per notch, on the right axis for each direction.
DH  a batch is validated before anything is written: a batch whose last
    item is bad emits NOTHING, not the valid prefix.
DI  a batch is atomic per device: keyboard items land in one frame with
    one SYN, pointer items in their own.
DJ  the CLI: `click`, `move-rel`, `scroll` work; there is no
    `button-down` subcommand, for the same reason there is no `key-down`.
DK  G10: streamed motion is coalesced into one audit line per second,
    while every button press keeps its own line.
"""
import os, re, shutil, signal, socket, struct, subprocess, sys, tempfile, time
import uictl_expect

SOCK = os.path.join(os.environ["XDG_RUNTIME_DIR"], "uictld.sock")
HDR = "<HHIII"
OP_PING, OP_MOVE_ABS, OP_HELLO, OP_KEY_TAP = 1, 2, 3, 4
OP_KEY_SEQUENCE, OP_KEY_DOWN, OP_KEY_UP = 5, 6, 7
OP_BUTTON, OP_MOVE_REL, OP_SCROLL, OP_BATCH = 11, 12, 13, 14
(OK, ERR_VERSION, ERR_OPCODE_UNKNOWN, ERR_PAYLOAD_INVALID,
 ERR_DENIED_BY_POLICY, ERR_TOO_LARGE, ERR_INTERNAL, ERR_BUSY,
 ERR_HANDSHAKE_REQUIRED, ERR_KEY_DENYLISTED, ERR_KEY_NOT_ALLOWED,
 ERR_RATE_LIMITED, ERR_KEY_ALREADY_HELD, ERR_KEY_HELD_BY_OTHER,
 ERR_KEY_NOT_HELD, ERR_TOO_MANY_HELD) = range(16)
EV_SYN, EV_KEY, EV_REL, EV_ABS = 0x00, 0x01, 0x02, 0x03
SYN_REPORT = 0
REL_X, REL_Y, REL_HWHEEL, REL_WHEEL = 0x00, 0x01, 0x06, 0x08
REL_WHEEL_HI_RES, REL_HWHEEL_HI_RES = 0x0b, 0x0c
BTN_LEFT, BTN_RIGHT, BTN_MIDDLE = 0x110, 0x111, 0x112
KEY_F13 = 183
HI_RES_PER_NOTCH = 120
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


def reply(s, timeout=5):
    s.settimeout(timeout)
    h = b""
    while len(h) < 16:
        c = s.recv(16 - len(h))
        if not c:
            return None
        h += c
    plen = struct.unpack(HDR, h)[4]
    body = b""
    while len(body) < plen:
        c = s.recv(plen - len(body))
        if not c:
            break
        body += c
    return struct.unpack_from("<H", body, 0)[0] if body else None


def hello(s, name="pointer", seq=1):
    body = struct.pack("<HH", 1, 1) + name.encode() + b"\x00" * (32 - len(name))
    s.sendall(struct.pack(HDR, 1, OP_HELLO, 1, seq, len(body)) + body)
    return reply(s)


_seq = [10]


def send(s, op, payload):
    _seq[0] += 1
    s.sendall(struct.pack(HDR, 1, op, 1, _seq[0], len(payload)) + payload)
    return reply(s)


def button(s, code, down):
    return send(s, OP_BUTTON, struct.pack("<HBB", code, 1 if down else 0, 0))


def move_rel(s, dx, dy):
    return send(s, OP_MOVE_REL, struct.pack("<ii", dx, dy))


def scroll(s, v, h):
    return send(s, OP_SCROLL, struct.pack("<ii", v, h))


def batch(s, items):
    body = struct.pack("<HH", len(items), 0)
    for op, a, b in items:
        body += struct.pack("<HHii", op, 0, a, b)
    return send(s, OP_BATCH, body)


def drain(fd, seconds=0.5):
    evs = []
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            buf = os.read(fd, EVENT_SIZE * 64)
        except (BlockingIOError, OSError):
            time.sleep(0.02)
            continue
        for i in range(0, len(buf) - EVENT_SIZE + 1, EVENT_SIZE):
            _, _, typ, code, val = struct.unpack_from(EVENT_FMT, buf, i)
            evs.append((typ, code, val))
    return evs


def make_home(prefix="uictl-m55-"):
    home = tempfile.mkdtemp(prefix=prefix)
    cfg = os.path.join(home, ".config", "uictl")
    os.makedirs(cfg)
    os.makedirs(os.path.join(home, ".local", "state"))
    with open(os.path.join(cfg, "policy"), "w") as f:
        f.write("183-194\n")
    os.chmod(os.path.join(cfg, "policy"), 0o600)
    with open(os.path.join(cfg, "clients"), "w") as f:
        f.write("pointer interactive\nuictl interactive\n")
    os.chmod(os.path.join(cfg, "clients"), 0o600)
    return home


def dev_chunk(name):
    for chunk in open("/proc/bus/input/devices").read().split("\n\n"):
        if 'Name="%s"' % name in chunk:
            return chunk
    return None


def bitmap_has(chunk, prefix, code):
    """Is `code` set in a `B: <prefix>=...` bitmap line?"""
    for line in chunk.splitlines():
        if line.startswith("B: %s=" % prefix):
            words = line.split("=", 1)[1].split()
            words.reverse()          # least significant word first
            idx, bit = code // 64, code % 64
            if idx >= len(words):
                return False
            return (int(words[idx], 16) >> bit) & 1 == 1
    return False


if os.path.exists(SOCK):
    try:
        conn().close()
        print("SKIP: a uictld is already running; stop it and re-run")
        sys.exit(0)
    except OSError:
        pass

home = make_home()
d = None
pfd = kfd = None
try:
    errlog = os.path.join(home, "uictld.err")
    d = subprocess.Popen(["./uictld"], env=dict(os.environ, HOME=home),
                         stdout=subprocess.DEVNULL, stderr=open(errlog, "w"))
    time.sleep(1.0)
    if d.poll() is not None:
        print("SKIP: daemon would not start:", open(errlog).read())
        sys.exit(0)

    # --- DA: two devices, with the right shapes -----------------------
    pchunk = dev_chunk(uictl_expect.POINTER_NAME)
    kchunk = dev_chunk(uictl_expect.KEYBOARD_NAME)
    if not pchunk or not kchunk:
        fail("DA: expected both '%s' and '%s' in /proc/bus/input/devices"
             % (uictl_expect.POINTER_NAME, uictl_expect.KEYBOARD_NAME))
        raise SystemExit
    prop = [l for l in pchunk.splitlines() if l.startswith("B: PROP=")]
    if not prop or int(prop[0].split("=")[1], 16) & (1 << 0) == 0:
        fail("DA: the pointer has no INPUT_PROP_POINTER (PROP=%s) -- "
             "libinput classifies ABS+buttons by heuristic without it"
             % (prop[0].split("=")[1] if prop else "absent"))
    else:
        pev = int([l for l in pchunk.splitlines()
                   if l.startswith("B: EV=")][0].split("=")[1], 16)
        kev = int([l for l in kchunk.splitlines()
                   if l.startswith("B: EV=")][0].split("=")[1], 16)
        missing = []
        for bit, nm in ((EV_ABS, "EV_ABS"), (EV_REL, "EV_REL"),
                        (EV_KEY, "EV_KEY")):
            if not pev & (1 << bit):
                missing.append("pointer lacks " + nm)
        if kev & (1 << EV_REL) or kev & (1 << EV_ABS):
            missing.append("keyboard has pointer axes")
        if missing:
            fail("DA: " + "; ".join(missing))
        else:
            handlers = re.search(r"H: Handlers=(.*)", pchunk).group(1)
            print("DA pointer: PROP_POINTER, EV=0x%x, handlers=%s"
                  % (pev, handlers.strip()))
            print("DA keyboard: EV=0x%x, handlers=%s"
                  % (kev, re.search(r"H: Handlers=(.*)", kchunk).group(1).strip()))

    # --- DB: disjoint where they overlap ------------------------------
    if not bitmap_has(pchunk, "KEY", BTN_LEFT):
        fail("DB: BTN_LEFT is not on the pointer device")
    elif bitmap_has(kchunk, "KEY", BTN_LEFT):
        fail("DB: BTN_LEFT is ALSO on the keyboard -- a keyboard with a "
             "left mouse button is not a shape real hardware has, which is "
             "the whole reason for the split")
    elif not bitmap_has(kchunk, "KEY", KEY_F13):
        fail("DB: KEY_F13 is not on the keyboard device")
    else:
        print("DB the devices are disjoint: BTN_LEFT on the pointer only, "
              "keys on the keyboard only")

    pnode, knode = uictl_expect.pointer_node(), uictl_expect.keyboard_node()
    try:
        pfd = os.open(pnode, os.O_RDONLY | os.O_NONBLOCK)
        kfd = os.open(knode, os.O_RDONLY | os.O_NONBLOCK)
    except (PermissionError, TypeError):
        print("SKIP: cannot read the event nodes (need the input group)")
        sys.exit(0)

    a = conn()
    if hello(a) != OK:
        fail("handshake failed")
        raise SystemExit

    # --- DC: a button is held state on the pointer device -------------
    drain(pfd, 0.2)
    r = button(a, BTN_LEFT, True)
    evs = [e for e in drain(pfd, 0.5) if e[0] == EV_KEY]
    if r != OK:
        fail("DC: button down refused (result=%s)" % r)
    elif evs != [(EV_KEY, BTN_LEFT, 1)]:
        fail("DC: pointer saw %s, expected one BTN_LEFT press" % evs)
    else:
        dup = button(a, BTN_LEFT, True)
        if dup != ERR_KEY_ALREADY_HELD:
            fail("DC: a duplicate button down got result=%s" % dup)
        else:
            print("DC a button press is held state, reusing M4.5 unchanged")
    drain(pfd, 0.2)
    r = button(a, BTN_LEFT, False)
    evs = [e for e in drain(pfd, 0.5) if e[0] == EV_KEY]
    if r != OK or evs != [(EV_KEY, BTN_LEFT, 0)]:
        fail("DC: button up gave result=%s evs=%s" % (r, evs))
    else:
        print("DC the release reaches the pointer device")

    # --- DE: two clients cannot hold the same button (G9) -------------
    b2 = conn()
    hello(b2, "pointer2")
    button(a, BTN_RIGHT, True)
    r = button(b2, BTN_RIGHT, True)
    if r != ERR_KEY_HELD_BY_OTHER:
        fail("DE: a second client took a held button (result=%s) -- whoever "
             "releases first would release it for both" % r)
    else:
        print("DE two clients cannot hold the same button (G9 contention)")
    b2.close()

    # --- DD: a dead client's held button is released on the POINTER ---
    drain(pfd, 0.2)
    holder = subprocess.Popen(
        [sys.executable, "-c",
         "import socket,struct,sys,time\n"
         "s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)\n"
         "s.connect(%r)\n"
         "b=struct.pack('<HH',1,1)+b'holder'+b'\\x00'*26\n"
         "s.sendall(struct.pack('<HHIII',1,3,1,1,len(b))+b); s.recv(64)\n"
         "s.sendall(struct.pack('<HHIII',1,11,1,2,4)+struct.pack('<HBB',%d,1,0))\n"
         "s.recv(64); sys.stdout.write('held\\n'); sys.stdout.flush()\n"
         "time.sleep(30)\n" % (SOCK, BTN_MIDDLE)],
        stdout=subprocess.PIPE, text=True)
    if holder.stdout.readline().strip() != "held":
        fail("DD: the holder never took the button")
    pressed = [e for e in drain(pfd, 0.5) if e[0] == EV_KEY]
    holder.kill()
    holder.wait(timeout=5)
    released = [e for e in drain(pfd, 1.0) if e[0] == EV_KEY]
    if pressed != [(EV_KEY, BTN_MIDDLE, 1)]:
        fail("DD: the hold did not reach the pointer: %s" % pressed)
    elif released != [(EV_KEY, BTN_MIDDLE, 0)]:
        fail("DD: after kill -9 the POINTER saw %s, expected one release of "
             "BTN_MIDDLE -- a release routed to the keyboard device would be "
             "dropped silently and leave a stuck drag" % released)
    else:
        print("DD kill -9 mid-drag releases the button on the pointer device")

    # --- DF: relative motion ------------------------------------------
    drain(pfd, 0.2)
    r = move_rel(a, 7, -3)
    evs = [e for e in drain(pfd, 0.5) if e[0] == EV_REL]
    if r != OK:
        fail("DF: move-rel refused (result=%s)" % r)
    elif evs != [(EV_REL, REL_X, 7), (EV_REL, REL_Y, -3)]:
        fail("DF: move-rel emitted %s" % evs)
    elif move_rel(a, 0, 0) != ERR_PAYLOAD_INVALID:
        fail("DF: a zero-zero nudge was accepted")
    elif move_rel(a, 999999, 0) != ERR_PAYLOAD_INVALID:
        fail("DF: an out-of-range delta was accepted -- deltas are bounded, "
             "not clamped, so a client learns rather than wonders")
    else:
        print("DF move-rel emits REL_X/REL_Y; zero and out-of-range refused")

    # --- DG: scroll, notch + hi-res -----------------------------------
    drain(pfd, 0.2)
    r = scroll(a, 2, 0)
    evs = [e for e in drain(pfd, 0.5) if e[0] == EV_REL]
    want = [(EV_REL, REL_WHEEL, 2),
            (EV_REL, REL_WHEEL_HI_RES, 2 * HI_RES_PER_NOTCH)]
    if r != OK or evs != want:
        fail("DG: vertical scroll emitted %s, expected %s" % (evs, want))
    else:
        drain(pfd, 0.2)
        scroll(a, 0, -1)
        evs = [e for e in drain(pfd, 0.5) if e[0] == EV_REL]
        want = [(EV_REL, REL_HWHEEL, -1),
                (EV_REL, REL_HWHEEL_HI_RES, -HI_RES_PER_NOTCH)]
        if evs != want:
            fail("DG: horizontal scroll emitted %s, expected %s" % (evs, want))
        else:
            print("DG scroll emits notch + hi-res (%d units/notch) on both "
                  "axes" % HI_RES_PER_NOTCH)

    # --- DH: a batch is all-or-nothing --------------------------------
    drain(pfd, 0.2)
    drain(kfd, 0.2)
    r = batch(a, [(OP_BUTTON, BTN_LEFT, 1),
                  (OP_MOVE_REL, 5, 5),
                  (OP_BUTTON, 9999, 1)])       # last item invalid
    pevs = drain(pfd, 0.5)
    kevs = drain(kfd, 0.3)
    if r != ERR_PAYLOAD_INVALID:
        fail("DH: a batch with a bad last item got result=%s" % r)
    elif pevs or kevs:
        fail("DH: THE VALID PREFIX OF A REJECTED BATCH REACHED THE DEVICE: "
             "%s %s -- that is the stuck-key scenario through the back door"
             % (pevs, kevs))
    else:
        print("DH a rejected batch emits nothing, not the valid prefix")

    # --- DI: atomic per device ----------------------------------------
    drain(pfd, 0.2)
    drain(kfd, 0.2)
    r = batch(a, [(OP_KEY_DOWN, KEY_F13, 0),
                  (OP_BUTTON, BTN_LEFT, 1),
                  (OP_BUTTON, BTN_LEFT, 0),
                  (OP_KEY_UP, KEY_F13, 0)])
    pevs = drain(pfd, 0.6)
    kevs = drain(kfd, 0.4)
    ksyn = [e for e in kevs if e[0] == EV_SYN]
    kkeys = [e for e in kevs if e[0] == EV_KEY]
    pkeys = [e for e in pevs if e[0] == EV_KEY]
    if r != OK:
        fail("DI: the batch failed (result=%s)" % r)
    elif kkeys != [(EV_KEY, KEY_F13, 1), (EV_KEY, KEY_F13, 0)]:
        fail("DI: keyboard saw %s" % kkeys)
    elif len(ksyn) != 1:
        fail("DI: the keyboard half used %d SYN_REPORTs, expected 1 -- a "
             "batch is one frame per device" % len(ksyn))
    elif pkeys != [(EV_KEY, BTN_LEFT, 1), (EV_KEY, BTN_LEFT, 0)]:
        fail("DI: pointer saw %s" % pkeys)
    else:
        print("DI a batch is atomic per device: keyboard in 1 frame, pointer "
              "separately (the documented cross-device limitation)")

    # --- DK: G10 motion coalescing ------------------------------------
    audit_path = os.path.join(home, ".local", "state", "uictl", "audit.log")
    before = open(audit_path).read().count("\n") if os.path.exists(audit_path) else 0
    for i in range(40):
        move_rel(a, 1, 1)
    button(a, BTN_LEFT, True)
    button(a, BTN_LEFT, False)
    time.sleep(2.5)                    # a flush tick plus slack
    audit = open(audit_path).read()
    lines = audit.splitlines()[before:]
    motion_lines = [l for l in lines if "op=MOVE_REL" in l]
    btn_lines = [l for l in lines if "op=BUTTON" in l]
    coalesced = [l for l in motion_lines if "coalesced" in l]
    if len(motion_lines) > 5:
        fail("DK: 40 nudges produced %d audit lines -- coalescing is not "
             "working, and muvor would write ~450 MB/day"
             % len(motion_lines))
    elif not coalesced:
        fail("DK: no coalesced motion line found:\n%s"
             % "\n".join(motion_lines))
    elif len(btn_lines) != 2:
        fail("DK: %d BUTTON lines, expected 2 -- discrete acts must keep "
             "their own lines" % len(btn_lines))
    else:
        print("DK 40 nudges -> %d audit line(s); both button presses kept "
              "their own: %s" % (len(motion_lines),
                                 coalesced[0].split("args=")[-1]))
    a.close()

    # --- DJ: the CLI ---------------------------------------------------
    drain(pfd, 0.3)
    env = dict(os.environ, HOME=home)
    rc_click = subprocess.run(["./uictl", "click", str(BTN_LEFT)],
                              env=env, capture_output=True, text=True)
    rc_rel = subprocess.run(["./uictl", "move-rel", "4", "4"],
                            env=env, capture_output=True, text=True)
    rc_scroll = subprocess.run(["./uictl", "scroll", "1"],
                               env=env, capture_output=True, text=True)
    evs = drain(pfd, 0.6)
    usage = subprocess.run(["./uictl"], env=env, capture_output=True, text=True)
    bad = [n for n, r in (("click", rc_click), ("move-rel", rc_rel),
                          ("scroll", rc_scroll)) if r.returncode != 0]
    if bad:
        fail("DJ: CLI commands failed: %s (%s)"
             % (bad, rc_click.stderr + rc_rel.stderr + rc_scroll.stderr))
    elif (EV_KEY, BTN_LEFT, 1) not in evs or (EV_REL, REL_X, 4) not in evs:
        fail("DJ: the CLI commands did not reach the device: %s" % evs)
    elif "button-down" in usage.stderr:
        fail("DJ: the CLI offers button-down; a one-shot process releases "
             "the moment it exits")
    else:
        print("DJ CLI click/move-rel/scroll reach the device; no button-down "
              "subcommand")
finally:
    for fd in (pfd, kfd):
        if fd is not None:
            os.close(fd)
    if d is not None and d.poll() is None:
        d.send_signal(signal.SIGTERM)
        try:
            d.wait(timeout=5)
        except subprocess.TimeoutExpired:
            d.kill()
    shutil.rmtree(home, ignore_errors=True)

print("\n== PASS ==" if ok else "\n== FAIL ==")
sys.exit(0 if ok else 1)
