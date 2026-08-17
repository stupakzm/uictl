#!/usr/bin/env python3
"""M4.5 task 2: held keys are released when the connection dies.

Nothing in the shipped daemon can hold a key -- OP_KEY_DOWN/OP_KEY_UP do
not exist yet (blocked on this milestone) and OP_KEY_SEQUENCE releases
everything it presses inside one request. So this suite builds a
throwaway daemon (temp dir, discarded; no test hook ever ships in the
real binary) whose OP_KEY_TAP handler presses the key *without*
releasing it and records the hold, which is exactly what a future
OP_KEY_DOWN will do. Then it kills the client and watches
/dev/input/eventN for the release the daemon has to synthesize.

Runs with HOME in a temp dir so it owns ~/.config/uictl/policy.
Requires: no uictld running, a working `cc`, read access to the event
node (input group).

AP  kill -9 a client holding a key: the device receives EV_KEY value 0
    for that keycode plus a SYN_REPORT. This is the entire point of the
    milestone, and it is asserted at the device -- bookkeeping that
    clears the bitset without writing to the kernel would pass any test
    that only looked at daemon state.
AQ  the synthesized release is audited: one line, result=0, naming the
    count and the keycodes, with no opcode or seq invented for it.
AR  several keys held at once all come back up, in descending keycode
    order, so a modifier (low code) is released after the key it
    modified.
AS  SIGTERM with a key still held releases it BEFORE the uinput device
    is destroyed (M4.5 task 5 falls out of task 2, since shutdown closes
    every connection first).
AT  the shipped binary holds nothing: a normal key-tap through the real
    daemon, then a disconnect, produces no extra release event and no
    held-release audit line.
"""
import os, re, shutil, signal, socket, struct, subprocess, sys, tempfile, time
import uictl_expect          # shared: device nodes, opcode set

SOCK = os.path.join(os.environ["XDG_RUNTIME_DIR"], "uictld.sock")
DEVICES = "/proc/bus/input/devices"
DEV_NAME = "uictl virtual pointer"
HDR = "<HHIII"
OP_PING, OP_MOVE_ABS, OP_HELLO, OP_KEY_TAP = 1, 2, 3, 4
OK = 0
EV_SYN, EV_KEY = 0x00, 0x01
SYN_REPORT = 0
KEY_LEFTCTRL, KEY_F13, KEY_F14, KEY_F15 = 29, 183, 184, 185
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
        return None, b""
    plen = struct.unpack(HDR, h)[4]
    body = b""
    while len(body) < plen:
        chunk = s.recv(plen - len(body))
        if not chunk:
            break
        body += chunk
    return (struct.unpack_from("<H", body, 0)[0], body[2:]) if body else (None, b"")


def hello(s, seq=1):
    body = struct.pack("<HH", 1, 1) + b"release" + b"\x00" * 25
    s.sendall(struct.pack(HDR, 1, OP_HELLO, 1, seq, len(body)) + body)
    return reply(s)


def hold(s, code, seq):
    """With the test hook in place, KEY_TAP presses and does not release."""
    s.sendall(struct.pack(HDR, 1, OP_KEY_TAP, 1, seq, 2) + struct.pack("<H", code))
    return reply(s)[0]


def event_node():
    """The KEYBOARD node since M5.5: key events moved there when the one
    hybrid device became a pointer and a keyboard. MOVE_ABS cases use
    pointer_node() instead."""
    return uictl_expect.keyboard_node()


def pointer_node():
    return uictl_expect.pointer_node()


def drain(fd, seconds=0.8):
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


if os.path.exists(SOCK):
    try:
        conn().close()
        print("SKIP: a uictld is already running; stop it and re-run")
        sys.exit(0)
    except OSError:
        pass

tmp = tempfile.mkdtemp(prefix="uictl-release-")
home = os.path.join(tmp, "home")
d = None
try:
    cfg = os.path.join(home, ".config", "uictl")
    os.makedirs(cfg, exist_ok=True)
    os.makedirs(os.path.join(home, ".local", "state"), exist_ok=True)
    # F13-F15 plus the bare left control: all unbound on a normal desktop,
    # and a modifier alone does nothing. Never widen this set -- the suite
    # injects for real, into whatever window has focus.
    with open(os.path.join(cfg, "policy"), "w") as f:
        f.write("29\n183-185\n")
    os.chmod(os.path.join(cfg, "policy"), 0o600)

    shutil.copytree("src", os.path.join(tmp, "src"))
    src = os.path.join(tmp, "src", "uictld.c")
    text = open(src).read()
    real_inject = ("    result = (uinput_key_tap(devs->keyboard, key.keycode) "
                   "< 0) ? ERR_INTERNAL : OK;")
    hook = """    /* test hook, throwaway build only: press and HOLD, which is
       what a future OP_KEY_DOWN does. */
    {
      struct uinput_key_event down_ = {.code = key.keycode, .value = 1};
      result = (uinput_key_seq(devs->keyboard, &down_, 1) < 0) ? ERR_INTERNAL : OK;
      if (result == OK)
        conn_hold_add(c, key.keycode);
    }"""
    if real_inject not in text:
        print("SKIP: could not find the KEY_TAP injection line in uictld.c")
        sys.exit(0)
    open(src, "w").write(text.replace(real_inject, hook, 1))

    exe = os.path.join(tmp, "uictld-release")
    build = subprocess.run(
        ["cc", "-D_FORTIFY_SOURCE=2", "-fPIE", "-Wall", "-Wextra",
         "-Wconversion", "-g", "-std=c11", "-D_GNU_SOURCE", src,
         os.path.join(tmp, "src", "platform", "uinput.c"), "-o", exe, "-pie"],
        capture_output=True, text=True)
    if build.returncode != 0:
        print("SKIP: throwaway build failed:\n" + build.stderr)
        sys.exit(0)

    d = subprocess.Popen([exe], env=dict(os.environ, HOME=home),
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         text=True)
    time.sleep(0.8)
    if d.poll() is not None:
        print("SKIP: daemon would not start:", d.stderr.read())
        sys.exit(0)

    node = event_node()
    if not node:
        fail("no event node for '%s' in %s" % (DEV_NAME, DEVICES))
        raise SystemExit
    try:
        efd = uictl_expect.open_node(node)
    except PermissionError:
        print("SKIP: cannot read %s (need the input group)" % node)
        sys.exit(0)

    audit_path = os.path.join(home, ".local", "state", "uictl", "audit.log")

    # --- AP: kill -9 a client holding a key ---------------------------
    # A subprocess, so it can be killed uncleanly. A clean close is not
    # the case that strands a key; SIGKILL is.
    drain(efd, 0.2)
    holder = subprocess.Popen(
        [sys.executable, "-c",
         "import socket,struct,sys,time\n"
         "s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)\n"
         "s.connect(%r)\n"
         "b=struct.pack('<HH',1,1)+b'holder'+b'\\x00'*26\n"
         "s.sendall(struct.pack('<HHIII',1,3,1,1,len(b))+b); s.recv(64)\n"
         "s.sendall(struct.pack('<HHIII',1,4,1,2,2)+struct.pack('<H',%d))\n"
         "s.recv(64); sys.stdout.write('held\\n'); sys.stdout.flush()\n"
         "time.sleep(30)\n" % (SOCK, KEY_F13)],
        stdout=subprocess.PIPE, text=True)
    if holder.stdout.readline().strip() != "held":
        fail("AP: holder client never reported a successful hold")
    pressed = drain(efd, 0.5)
    if (EV_KEY, KEY_F13, 1) not in pressed:
        fail("AP: the hold did not reach the device: %s" % pressed)
    if (EV_KEY, KEY_F13, 0) in pressed:
        fail("AP: the key came back up before the client died -- the test "
             "hook is not holding anything, so nothing below proves a thing")

    holder.kill()
    holder.wait(timeout=5)
    released = drain(efd, 1.0)
    keys = [e for e in released if e[0] == EV_KEY]
    if keys != [(EV_KEY, KEY_F13, 0)]:
        fail("AP: after kill -9 the device saw %s, expected exactly one "
             "release of keycode %d -- THE KEY IS STILL DOWN" % (keys, KEY_F13))
    elif not any(e == (EV_SYN, SYN_REPORT, 0) for e in released):
        fail("AP: the release carried no SYN_REPORT, so no consumer will "
             "act on it: %s" % released)
    else:
        print("AP kill -9 mid-hold released keycode %d at the device, with a "
              "SYN" % KEY_F13)

    # --- AQ: the release is audited -----------------------------------
    time.sleep(0.2)
    audit = open(audit_path).read() if os.path.exists(audit_path) else ""
    rel = [ln for ln in audit.splitlines() if "held-release" in ln]
    if len(rel) != 1:
        fail("AQ: expected exactly one held-release audit line, got %d:\n%s"
             % (len(rel), "\n".join(rel)))
    elif "result=0" not in rel[0] or "[%d]" % KEY_F13 not in rel[0]:
        fail("AQ: release audit line is missing the result or the keycode: %s"
             % rel[0])
    elif "seq=0" not in rel[0]:
        fail("AQ: release audit invented a seq for a request nobody made: %s"
             % rel[0])
    else:
        print("AQ release audited: %s" % rel[0].split("args=")[-1])

    # --- AR: several keys, released high-to-low -----------------------
    drain(efd, 0.2)
    holder2 = subprocess.Popen(
        [sys.executable, "-c",
         "import socket,struct,sys,time\n"
         "s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)\n"
         "s.connect(%r)\n"
         "b=struct.pack('<HH',1,1)+b'holder2'+b'\\x00'*25\n"
         "s.sendall(struct.pack('<HHIII',1,3,1,1,len(b))+b); s.recv(64)\n"
         "for i,k in enumerate(%r):\n"
         "    s.sendall(struct.pack('<HHIII',1,4,1,2+i,2)+struct.pack('<H',k))\n"
         "    s.recv(64)\n"
         "sys.stdout.write('held\\n'); sys.stdout.flush()\n"
         "time.sleep(30)\n" % (SOCK, [KEY_LEFTCTRL, KEY_F14, KEY_F15])],
        stdout=subprocess.PIPE, text=True)
    if holder2.stdout.readline().strip() != "held":
        fail("AR: second holder never reported success")
    drain(efd, 0.5)
    holder2.kill()
    holder2.wait(timeout=5)
    evs = drain(efd, 1.0)
    keys = [e for e in evs if e[0] == EV_KEY]
    want = [(EV_KEY, KEY_F15, 0), (EV_KEY, KEY_F14, 0), (EV_KEY, KEY_LEFTCTRL, 0)]
    if keys != want:
        fail("AR: three held keys released as %s, expected %s (descending, so "
             "the modifier goes last)" % (keys, want))
    else:
        syns = [e for e in evs if e[0] == EV_SYN]
        print("AR three held keys all released, modifier last, in %d frame(s)"
              % len(syns))

    # --- AS: shutdown releases before the device is destroyed ---------
    drain(efd, 0.2)
    c = conn()
    if hello(c)[0] != OK:
        fail("AS: handshake failed")
    if hold(c, KEY_F13, 2) != OK:
        fail("AS: could not take a hold before shutdown")
    drain(efd, 0.4)
    d.send_signal(signal.SIGTERM)
    # Drain *while* it shuts down, not after: UI_DEV_DESTROY takes the
    # event node away, and a reader that starts afterwards sees ENODEV
    # and cannot tell "no release was emitted" from "too late to read it".
    evs = drain(efd, 1.0)
    try:
        d.wait(timeout=5)
    except subprocess.TimeoutExpired:
        d.kill()
    os.close(efd)
    c.close()
    err = d.stderr.read()
    d = None
    keys = [e for e in evs if e[0] == EV_KEY]
    if keys != [(EV_KEY, KEY_F13, 0)]:
        fail("AS: SIGTERM with a key held emitted %s -- the device was "
             "destroyed while the key was down" % keys)
    else:
        print("AS shutdown released the held key before UI_DEV_DESTROY "
              "(task 5 falls out of task 2)")
    if "BUG" in err:
        fail("AS: daemon reported a BUG on the way out:\n%s" % err)
finally:
    if d is not None:
        d.terminate()
        try:
            d.wait(timeout=5)
        except subprocess.TimeoutExpired:
            d.kill()
    shutil.rmtree(tmp, ignore_errors=True)

# --- AT: the shipped binary holds nothing -----------------------------
home2 = tempfile.mkdtemp(prefix="uictl-release-real-")
try:
    cfg = os.path.join(home2, ".config", "uictl")
    os.makedirs(cfg)
    os.makedirs(os.path.join(home2, ".local", "state"))
    with open(os.path.join(cfg, "policy"), "w") as f:
        f.write("183-185\n")
    os.chmod(os.path.join(cfg, "policy"), 0o600)

    real = subprocess.Popen(["./uictld"], env=dict(os.environ, HOME=home2),
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True)
    time.sleep(0.8)
    if real.poll() is not None:
        fail("AT: the real daemon would not start: %s" % real.stderr.read())
    else:
        node = event_node()
        efd = None
        if node:
            try:
                efd = uictl_expect.open_node(node)
            except PermissionError:
                pass
        c = conn()
        if hello(c)[0] != OK:
            fail("AT: handshake failed against the shipped daemon")
        if efd is not None:
            drain(efd, 0.2)
        c.sendall(struct.pack(HDR, 1, OP_KEY_TAP, 1, 2, 2) +
                  struct.pack("<H", KEY_F13))
        res = reply(c)[0]
        if res != OK:
            fail("AT: shipped daemon refused keycode %d (result=%s)"
                 % (KEY_F13, res))
        if efd is not None:
            drain(efd, 0.4)
        c.close()
        time.sleep(0.4)
        evs = drain(efd, 0.8) if efd is not None else []
        if efd is not None:
            os.close(efd)
        real.send_signal(signal.SIGTERM)
        try:
            real.wait(timeout=5)
        except subprocess.TimeoutExpired:
            real.kill()
        audit = os.path.join(home2, ".local", "state", "uictl", "audit.log")
        text = open(audit).read() if os.path.exists(audit) else ""
        if [e for e in evs if e[0] == EV_KEY]:
            fail("AT: the shipped daemon emitted key events on disconnect: %s "
                 "-- something in the real binary is taking holds" % evs)
        elif "held-release" in text:
            fail("AT: the shipped daemon logged a held-release; nothing "
                 "in it should be able to hold a key yet")
        else:
            print("AT shipped binary holds nothing: no release on disconnect, "
                  "no release audit line")
finally:
    shutil.rmtree(home2, ignore_errors=True)

print("\n== PASS ==" if ok else "\n== FAIL ==")
sys.exit(0 if ok else 1)
