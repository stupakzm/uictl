#!/usr/bin/env python3
"""M4 step 2: the uinput_key_tap() primitive, read back from the kernel.

The primitive is deliberately UNWIRED -- no opcode reaches it until step
7, after the deny-list. So this suite builds a throwaway daemon (in a
temp dir, discarded afterwards; no test hook ever ships in the real
binary) whose SIGUSR1 handler also taps a few keycodes, and reads the
resulting events straight off /dev/input/eventN.

Requires: no uictld running (it starts its own), a working `cc`, and read
access to the device's event node (input group).

KK  a tap emits exactly EV_KEY down, EV_KEY up, SYN_REPORT -- in that
    order, for the requested keycode.
LL  the range guard rejects KEY_RESERVED and anything past KEY_MAX,
    loudly, and emits nothing.
MM  MOVE_ABS still emits its own frame, i.e. the shared write path did
    not break the pointer.
NN  step 7, and the strongest assertion in the milestone, checked at the
    device rather than in the code: an ALLOWED keycode sent to the real
    daemon produces exactly one down/up pair on /dev/input/eventN, and a
    DENIED one produces **nothing at all** -- no down, no up, no SYN. A
    deny-list that returns the right error code while still writing to
    the device would pass every other test in this repo.
"""
import os, re, shutil, signal, socket, struct, subprocess, sys, tempfile, time
import uictl_expect          # the advertised opcode set, shared

SOCK = os.path.join(os.environ["XDG_RUNTIME_DIR"], "uictld.sock")
DEVICES = "/proc/bus/input/devices"
DEV_NAME = "uictl virtual pointer"
HDR = "<HHIII"
OP_PING, OP_MOVE_ABS, OP_HELLO, OP_KEY_TAP, OP_KEY_SEQUENCE = 1, 2, 3, 4, 5
OK, ERR_KEY_DENYLISTED, ERR_KEY_NOT_ALLOWED = 0, 9, 10
EV_SYN, EV_KEY, EV_ABS = 0x00, 0x01, 0x03
SYN_REPORT, ABS_X, ABS_Y = 0, 0x00, 0x01
KEY_A, KEY_F13, KEY_POWER = 30, 183, 116
EVENT_FMT = "@llHHi"                  # timeval + type + code + value
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
    body = struct.pack("<HH", 1, 1) + b"keytap" + b"\x00" * 26
    s.sendall(struct.pack(HDR, 1, OP_HELLO, 1, seq, len(body)) + body)
    return reply(s)


def event_node():
    """The KEYBOARD node since M5.5: key events moved there when the one
    hybrid device became a pointer and a keyboard. MOVE_ABS cases use
    pointer_node() instead."""
    return uictl_expect.keyboard_node()


def pointer_node():
    return uictl_expect.pointer_node()


def drain(fd, seconds=1.0):
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

tmp = tempfile.mkdtemp(prefix="uictl-keytap-")
d = None
try:
    shutil.copytree("src", os.path.join(tmp, "src"))
    src = os.path.join(tmp, "src", "uictld.c")
    text = open(src).read()
    hook = """          conn_dump_table();
          /* test hook, throwaway build only */
          uinput_key_tap(devices.keyboard, 30);
          uinput_key_tap(devices.keyboard, 0);
          uinput_key_tap(devices.keyboard, 9999);
          uinput_move_abs(devices.pointer, 111, 222);
"""
    if "          conn_dump_table();\n" not in text:
        print("SKIP: could not find the SIGUSR1 hook point in uictld.c")
        sys.exit(0)
    open(src, "w").write(text.replace("          conn_dump_table();\n", hook, 1))

    exe = os.path.join(tmp, "uictld-keytap")
    build = subprocess.run(
        ["cc", "-D_FORTIFY_SOURCE=2", "-fPIE", "-Wall", "-Wextra",
         "-Wconversion", "-g", "-std=c11", "-D_GNU_SOURCE", src,
         os.path.join(tmp, "src", "platform", "uinput.c"), "-o", exe, "-pie"],
        capture_output=True, text=True)
    if build.returncode != 0:
        print("SKIP: throwaway build failed:\n" + build.stderr)
        sys.exit(0)

    d = subprocess.Popen([exe], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
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
        d.terminate()
        sys.exit(0)

    # Two nodes since M5.5: the hook taps keys (keyboard) and moves the
    # pointer (pointer). Reading one and asserting about the other is the
    # mistake the split makes possible, so each case reads its own.
    pnode = pointer_node()
    pfd = uictl_expect.open_node(pnode) if pnode else None
    drain(efd, 0.2)                    # discard anything already queued
    if pfd is not None:
        drain(pfd, 0.2)
    d.send_signal(signal.SIGUSR1)
    evs = drain(efd, 1.0)
    pevs = drain(pfd, 0.5) if pfd is not None else []
    os.close(efd)
    if pfd is not None:
        os.close(pfd)

    # --- KK: the tap frame -------------------------------------------
    keys = [e for e in evs if e[0] == EV_KEY]
    if keys != [(EV_KEY, KEY_A, 1), (EV_KEY, KEY_A, 0)]:
        fail("KK: key events were %s, expected down then up for keycode %d"
             % (keys, KEY_A))
    else:
        print("KK tap emitted EV_KEY %d down then up" % KEY_A)

    # ordering: the SYN must follow both key events
    try:
        i_down = evs.index((EV_KEY, KEY_A, 1))
        i_up = evs.index((EV_KEY, KEY_A, 0))
        i_syn = next(i for i, e in enumerate(evs)
                     if i > i_up and e == (EV_SYN, SYN_REPORT, 0))
        if not (i_down < i_up < i_syn):
            fail("KK: ordering was down=%d up=%d syn=%d" % (i_down, i_up, i_syn))
        else:
            print("KK SYN_REPORT follows both, one frame per request "
                  "(M3 decision 5)")
    except (ValueError, StopIteration):
        fail("KK: no SYN_REPORT after the key events: %s" % evs)

    # --- LL: the range guard ------------------------------------------
    err = ""
    d.send_signal(signal.SIGTERM)
    try:
        d.wait(timeout=5)
    except subprocess.TimeoutExpired:
        d.kill()
    err = d.stderr.read()
    d = None
    rejects = re.findall(r"key_tap: keycode (\d+) out of range", err)
    if sorted(rejects) != ["0", "9999"]:
        fail("LL: range guard reported %s, expected keycodes 0 and 9999\n%s"
             % (rejects, err))
    elif len(keys) != 2:
        fail("LL: an out-of-range keycode still emitted events: %s" % keys)
    else:
        print("LL keycodes 0 and 9999 refused loudly, no events emitted")

    # --- MM: the pointer still works through the shared write path ----
    moves = [e for e in pevs if e[0] == EV_ABS]
    if moves != [(EV_ABS, ABS_X, 111), (EV_ABS, ABS_Y, 222)]:
        fail("MM: MOVE_ABS emitted %s on the pointer node -- the shared "
             "write path broke the pointer" % moves)
    else:
        print("MM MOVE_ABS still emits its own frame unchanged")
finally:
    if d is not None:
        d.terminate()
        try:
            d.wait(timeout=5)
        except subprocess.TimeoutExpired:
            d.kill()
    shutil.rmtree(tmp, ignore_errors=True)

# --- NN: the shipped daemon exposes none of this ----------------------
real = subprocess.Popen(["./uictld"], stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, text=True)
time.sleep(0.8)
if real.poll() is not None:
    fail("NN: the real daemon would not start: %s" % real.stderr.read())
else:
    c = conn()
    res, data = hello(c)
    if res != OK or len(data) < 24:
        fail("NN: handshake failed")
    else:
        opmap = struct.unpack_from("<HHIQII", data, 0)[3]
        expected = uictl_expect.EXPECTED_BITMAP
        if opmap != expected:
            fail("NN: opcode_bitmap=0x%x, expected 0x%x (%s)"
                 % (opmap, expected, uictl_expect.describe(opmap)))
        else:
            print("NN shipped daemon advertises key-tap (bitmap 0x%x)" % opmap)

        node = event_node()
        efd = None
        if node:
            try:
                efd = uictl_expect.open_node(node)
            except PermissionError:
                pass
        if efd is None:
            print("NN (skipped the device-level check: event node unreadable)")
        else:
            # allowed: exactly one down/up pair reaches the device.
            # KEY_F13 is bound to nothing on a normal desktop, so this
            # injects for real without doing anything to the session.
            drain(efd, 0.2)
            c.sendall(struct.pack(HDR, 1, OP_KEY_TAP, 1, 2, 2) +
                      struct.pack("<H", KEY_F13))
            acked = reply(c)[0]
            evs = drain(efd, 0.6)
            keys = [e for e in evs if e[0] == EV_KEY]
            # Since step 8 the key also has to be in ~/.config/uictl/policy,
            # which this suite does not own -- the real HOME's policy is the
            # user's. A refusal here is default-deny working, not a bug;
            # test_m4_policy.py owns the allowlist.
            if acked == ERR_KEY_NOT_ALLOWED and not keys:
                print("NN (allowed-key case skipped: keycode %d is not in "
                      "~/.config/uictl/policy)" % KEY_F13)
            elif acked != OK:
                fail("NN: allowed key was not accepted (result=%s)" % acked)
            elif keys != [(EV_KEY, KEY_F13, 1), (EV_KEY, KEY_F13, 0)]:
                fail("NN: allowed key produced %s, expected one down/up pair "
                     "for %d" % (keys, KEY_F13))
            else:
                print("NN allowed key reached the device (one down/up pair)")

            # denied: the device must see NOTHING. Not a down without an
            # up, not a stray SYN -- nothing.
            drain(efd, 0.2)
            c.sendall(struct.pack(HDR, 1, OP_KEY_TAP, 1, 3, 2) +
                      struct.pack("<H", KEY_POWER))
            denied = reply(c)[0]
            evs = drain(efd, 0.6)
            os.close(efd)
            if denied != ERR_KEY_DENYLISTED:
                fail("NN: KEY_POWER got result=%s, expected "
                     "ERR_KEY_DENYLISTED" % denied)
            elif evs:
                fail("NN: A DENIED KEY REACHED THE DEVICE: %s -- the "
                     "deny-list returns the right code but does not stop "
                     "the write" % evs)
            else:
                print("NN denied key reached the device NOT AT ALL "
                      "(no events, not even a SYN)")
    c.close()
    real.send_signal(signal.SIGTERM)
    try:
        real.wait(timeout=5)
    except subprocess.TimeoutExpired:
        real.kill()

print("\n== PASS ==" if ok else "\n== FAIL ==")
sys.exit(0 if ok else 1)
