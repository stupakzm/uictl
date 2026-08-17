#!/usr/bin/env python3
"""WIRE.md 8.3.1: the first release on a connection is forgiving.

A connection that has never held anything may send a release for a code
it does not hold and get OK. Once it has held something, the same
request is ERR_KEY_NOT_HELD again.

Why the asymmetry is worth testing rather than simplifying: the two
cases are indistinguishable from the client's side but not from the
daemon's. A release arriving on a brand-new connection cannot be
separated from a client whose previous connection died mid-gesture --
8.3 released its holds, and its in-flight "finish the drag" release
lands on the reconnection. There is no client bug there to report. A
release arriving after that same connection has held something is a
client that lost track of its own state within one connection, which is
a real bug and keeps its error. Collapsing the two either spams a
correct client with errors after every daemon restart, or deletes a
diagnostic that catches unbalanced down/up pairs.

Runs with HOME in a temp dir so it owns ~/.config/uictl/policy.
Requires: no uictld running, read access to both event nodes (input
group).

BA  a fresh connection releasing a key it never held gets OK, and the
    keyboard device receives NOTHING.
BB  same for a button it never held, at the pointer device.

    KNOWN LIMIT of BA and BB, found by a negative control rather than by
    reasoning: a build patched to return OK *and* still write the
    redundant value-0 event passes both. The kernel's input core drops a
    value-0 EV_KEY for a code it does not have down, and drops the
    now-empty frame with it, so no EV_KEY and no SYN_REPORT reach the
    node either way -- the two builds are indistinguishable here. BA/BB
    therefore prove the outcome that matters to a consumer (nothing
    spurious is delivered) but do NOT prove the daemon skipped the
    write. BF is the check that can tell the branches apart.
BF  the audit log names the forgiven release specifically, which is the
    only externally visible evidence of *which* branch ran.
BC  the window closes: hold a key, release it properly, then release it
    again -> ERR_KEY_NOT_HELD. held_ever is sticky and does not come
    back when held_count returns to zero.
BD  the window is per-connection, not per-code: after holding F13, a
    release for F14 -- never held, never touched -- is also refused.
    A per-code flag would forgive this one and reopen the hole BC closes.
BE  the motivating case end to end: hold a button, drop the connection,
    reconnect, send the release. OK, and the pointer device sees exactly
    one release (the daemon's synthesized one from 8.3), not two.
"""
import os, socket, struct, subprocess, sys, tempfile, time
import uictl_expect

SOCK = os.path.join(os.environ["XDG_RUNTIME_DIR"], "uictld.sock")
HDR = "<HHIII"
OP_HELLO, OP_KEY_DOWN, OP_KEY_UP, OP_BUTTON = 3, 6, 7, 11
OK, ERR_KEY_NOT_HELD = 0, 14
EV_KEY = 0x01
KEY_F13, KEY_F14 = 183, 184
BTN_LEFT = 272
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


def send(s, opcode, payload=b"", seq=1):
    s.sendall(struct.pack(HDR, 1, opcode, 1, seq, len(payload)) + payload)
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
    return struct.unpack_from("<H", body, 0)[0]


def hello(s, name=b"forgive"):
    p = struct.pack("<HH", 1, 1) + name.ljust(32, b"\x00")
    return send(s, OP_HELLO, p)


def key(s, opcode, code, seq=1):
    return send(s, opcode, struct.pack("<H", code), seq)


def button(s, code, down, seq=1):
    return send(s, OP_BUTTON, struct.pack("<HBB", code, down, 0), seq)


def drain(fd):
    """Every event queued on the node since the last drain."""
    evs = []
    while True:
        try:
            buf = os.read(fd, EVENT_SIZE * 64)
        except BlockingIOError:
            break
        if not buf:
            break
        for i in range(0, len(buf) - EVENT_SIZE + 1, EVENT_SIZE):
            _, _, typ, code, val = struct.unpack_from(EVENT_FMT, buf, i)
            evs.append((typ, code, val))
    return evs


def keys_only(evs):
    return [e for e in evs if e[0] == EV_KEY]


def make_home():
    home = tempfile.mkdtemp(prefix="uictl-forgive-")
    cfg = os.path.join(home, ".config", "uictl")
    os.makedirs(cfg)
    os.makedirs(os.path.join(home, ".local", "state"))
    # F13-F24. Never widen this -- the suite injects for real, and the
    # codes just above F24 are Super and a level-5 shift once XKB is done
    # with them. See uictl_expect.SAFE_POLICY.
    with open(os.path.join(cfg, "policy"), "w") as f:
        f.write(uictl_expect.SAFE_POLICY)
    os.chmod(os.path.join(cfg, "policy"), 0o600)
    with open(os.path.join(cfg, "clients"), "w") as f:
        f.write("forgive interactive\n")
    os.chmod(os.path.join(cfg, "clients"), 0o600)
    return home


if os.path.exists(SOCK):
    try:
        conn().close()
        print("SKIP: a uictld is already running; stop it and re-run")
        sys.exit(0)
    except OSError:
        pass

home = make_home()
d = None
kfd = pfd = None
try:
    errlog = os.path.join(home, "uictld.err")
    d = subprocess.Popen(["./uictld"], env=dict(os.environ, HOME=home),
                         stdout=subprocess.DEVNULL,
                         stderr=open(errlog, "w"), text=True)
    time.sleep(0.8)
    if d.poll() is not None:
        print("SKIP: daemon would not start:", open(errlog).read())
        sys.exit(0)

    knode, pnode = uictl_expect.keyboard_node(), uictl_expect.pointer_node()
    if not knode or not pnode:
        fail("missing an event node (keyboard=%s pointer=%s)" % (knode, pnode))
        raise SystemExit
    try:
        kfd = os.open(knode, os.O_RDONLY | os.O_NONBLOCK)
        pfd = os.open(pnode, os.O_RDONLY | os.O_NONBLOCK)
    except PermissionError:
        print("SKIP: cannot read the event nodes (need the input group)")
        sys.exit(0)

    # --- BA: fresh connection, key never held -------------------------
    a = conn()
    if hello(a) != OK:
        fail("handshake failed")
        raise SystemExit
    drain(kfd)
    r = key(a, OP_KEY_UP, KEY_F13)
    if r != OK:
        fail("BA: KEY_UP on a virgin connection gave %d, want OK" % r)
    time.sleep(0.15)
    stray = keys_only(drain(kfd))
    if stray:
        fail("BA: forgiven release still wrote to the device: %r" % stray)
    if ok:
        print("BA forgiven KEY_UP: OK, and no event reached the keyboard")

    # --- BB: same for a button ----------------------------------------
    b = conn()
    if hello(b) != OK:
        fail("BB: handshake failed")
        raise SystemExit
    drain(pfd)
    r = button(b, BTN_LEFT, 0)
    if r != OK:
        fail("BB: BUTTON up on a virgin connection gave %d, want OK" % r)
    time.sleep(0.15)
    stray = keys_only(drain(pfd))
    if stray:
        fail("BB: forgiven button release still wrote: %r" % stray)
    else:
        print("BB forgiven BUTTON up: OK, and no event reached the pointer")
    b.close()

    # --- BC: the window closes after the first real hold --------------
    # Same connection as BA, which has now sent a forgiven release and
    # still held nothing -- so the window must still be open until the
    # KEY_DOWN below lands.
    if key(a, OP_KEY_DOWN, KEY_F13, 2) != OK:
        fail("BC: KEY_DOWN refused; is the policy file being read?")
        raise SystemExit
    if key(a, OP_KEY_UP, KEY_F13, 3) != OK:
        fail("BC: the matching KEY_UP was refused")
    r = key(a, OP_KEY_UP, KEY_F13, 4)
    if r != ERR_KEY_NOT_HELD:
        fail("BC: double release gave %d, want ERR_KEY_NOT_HELD (%d)"
             % (r, ERR_KEY_NOT_HELD))
    else:
        print("BC window closed: double release is ERR_KEY_NOT_HELD again")

    # --- BD: sticky per-connection, not per-code ----------------------
    r = key(a, OP_KEY_UP, KEY_F14, 5)
    if r != ERR_KEY_NOT_HELD:
        fail("BD: release of an untouched code gave %d, want ERR_KEY_NOT_HELD"
             % r)
    else:
        print("BD flag is per-connection: an untouched code is refused too")
    a.close()

    # --- BE: the reconnect story, end to end --------------------------
    c = conn()
    if hello(c) != OK:
        fail("BE: handshake failed")
        raise SystemExit
    drain(pfd)
    if button(c, BTN_LEFT, 1) != OK:
        fail("BE: could not take the button down")
        raise SystemExit
    c.close()                       # 8.3: the daemon releases it here
    time.sleep(0.3)
    after_drop = keys_only(drain(pfd))
    if (EV_KEY, BTN_LEFT, 0) not in after_drop:
        fail("BE: no synthesized release on disconnect: %r" % after_drop)

    e = conn()                      # the reconnection
    if hello(e) != OK:
        fail("BE: handshake failed on reconnect")
        raise SystemExit
    drain(pfd)
    r = button(e, BTN_LEFT, 0)      # the in-flight "finish the drag"
    if r != OK:
        fail("BE: the reconnect release gave %d, want OK" % r)
    time.sleep(0.15)
    stray = keys_only(drain(pfd))
    if stray:
        fail("BE: the reconnect release wrote a second release: %r" % stray)
    elif ok:
        print("BE reconnect after a dropped drag: OK, exactly one release")
    e.close()

    # --- BF: the audit log distinguishes the branches -----------------
    # The one discriminator BA/BB do not have. A forgiven release and a
    # normal one both end result=0 with no device event, so without a
    # distinct args= string there is nothing outside the daemon that can
    # tell a reviewer which path a request took.
    time.sleep(0.3)
    audit = os.path.join(home, ".local", "state", "uictl", "audit.log")
    try:
        lines = open(audit).read().splitlines()
    except OSError as e2:
        fail("BF: cannot read the audit log: %s" % e2)
        lines = []
    forgiven = [l for l in lines if "forgiven" in l]
    if len(forgiven) != 3:          # BA, BB, BE
        fail("BF: %d forgiven audit lines, want 3 (BA, BB, BE)"
             % len(forgiven))
    elif any("result=0" not in l for l in forgiven):
        fail("BF: a forgiven line is not result=0: %r" % forgiven)
    else:
        print("BF audit names the forgiven releases: %d lines, all result=0"
              % len(forgiven))

finally:
    for fd in (kfd, pfd):
        if fd is not None:
            os.close(fd)
    if d and d.poll() is None:
        d.terminate()
        try:
            d.wait(timeout=5)
        except subprocess.TimeoutExpired:
            d.kill()
    import shutil
    shutil.rmtree(home, ignore_errors=True)

print("\n== PASS ==" if ok else "\n== FAIL ==")
sys.exit(0 if ok else 1)
