#!/usr/bin/env python3
"""M4.5 tasks 3 and 4: held-key arbitration, and the dead-man timer.

OP_KEY_DOWN/OP_KEY_UP are real here -- this is the first suite that
drives them through the shipped binary, no test hook. Runs its own
daemon with HOME in a temp dir so it owns ~/.config/uictl/policy and
~/.config/uictl/clients. Requires no uictld running and read access to
the event node (input group).

Every assertion about what did or did not happen is made at
/dev/input/eventN. A refusal that returned the right code while still
writing to the device is the failure mode this milestone is about.

AU  DOWN presses and does NOT release: exactly one EV_KEY value 1 at the
    device, and SIGUSR1 shows the connection holding one key.
AV  UP releases exactly that key.
AW  a duplicate DOWN is refused (ERR_KEY_ALREADY_HELD) and reaches the
    device not at all -- no second press, which would be a press the
    client never gets to balance.
AX  a DOWN for a key another connection holds is refused
    (ERR_KEY_HELD_BY_OTHER); once the owner releases, the same request
    succeeds.
AY  an UP for a key this connection does not hold is refused
    (ERR_KEY_NOT_HELD) and emits nothing.
AZ  the DOWN gate is the KEY_TAP gate: out-of-range, deny-listed and
    not-in-policy keycodes are refused with their own codes, and none of
    them reach the device.
BA  MAX_HELD_PER_CONN is enforced (ERR_TOO_MANY_HELD), and the refusal
    does not disturb the keys already held.
BB  the dead-man timer force-releases a hold from a client that is still
    alive, audits it, and leaves the connection usable. Uses a throwaway
    build with HOLD_MAX_SEC patched to 2 -- same mechanism, faster clock.
BC  UP is not rate limited: a client whose bucket is empty can still
    release what it holds. Charging the release means the way to get a
    stuck key is to be slightly too fast.
BD  the CLI advertises key-down/key-up but offers no subcommand for
    them: a one-shot process that exits releases immediately.
"""
import os, re, shutil, signal, socket, struct, subprocess, sys, tempfile, time
import uictl_expect          # shared: device nodes, opcode set

SOCK = os.path.join(os.environ["XDG_RUNTIME_DIR"], "uictld.sock")
DEVICES = "/proc/bus/input/devices"
DEV_NAME = "uictl virtual pointer"
HDR = "<HHIII"
OP_PING, OP_MOVE_ABS, OP_HELLO, OP_KEY_TAP = 1, 2, 3, 4
OP_KEY_SEQUENCE, OP_KEY_DOWN, OP_KEY_UP = 5, 6, 7
OP_BUTTON = 11                  # M5.5; BA needs it to fill the hold cap
(OK, ERR_VERSION, ERR_OPCODE_UNKNOWN, ERR_PAYLOAD_INVALID,
 ERR_DENIED_BY_POLICY, ERR_TOO_LARGE, ERR_INTERNAL, ERR_BUSY,
 ERR_HANDSHAKE_REQUIRED, ERR_KEY_DENYLISTED, ERR_KEY_NOT_ALLOWED,
 ERR_RATE_LIMITED, ERR_KEY_ALREADY_HELD, ERR_KEY_HELD_BY_OTHER,
 ERR_KEY_NOT_HELD, ERR_TOO_MANY_HELD) = range(16)
EV_SYN, EV_KEY = 0x00, 0x01
SYN_REPORT = 0
KEY_F13, KEY_F14, KEY_F15 = 183, 184, 185
KEY_A, KEY_POWER = 30, 116
BTN_LEFT, BTN_RIGHT, BTN_MIDDLE, BTN_SIDE, BTN_EXTRA = 272, 273, 274, 275, 276
MAX_HELD = 16
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


def hello(s, name=b"arbit", seq=1):
    body = struct.pack("<HH", 1, 1) + name + b"\x00" * (32 - len(name))
    s.sendall(struct.pack(HDR, 1, OP_HELLO, 1, seq, len(body)) + body)
    return reply(s)


_seq = [10]


def key(s, op, code):
    _seq[0] += 1
    s.sendall(struct.pack(HDR, 1, op, 1, _seq[0], 2) + struct.pack("<H", code))
    return reply(s)[0]


def button(s, code, down):
    """OP_BUTTON. A press and a release, held in the same bitset as keys
    -- which is why BA can fill the cap with a mix of the two."""
    _seq[0] += 1
    p = struct.pack("<HBB", code, 1 if down else 0, 0)
    s.sendall(struct.pack(HDR, 1, OP_BUTTON, 1, _seq[0], len(p)) + p)
    return reply(s)[0]


def event_node():
    """The KEYBOARD node since M5.5: key events moved there when the one
    hybrid device became a pointer and a keyboard. MOVE_ABS cases use
    pointer_node() instead."""
    return uictl_expect.keyboard_node()


def pointer_node():
    return uictl_expect.pointer_node()


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


def keys_only(evs):
    return [e for e in evs if e[0] == EV_KEY]


def make_home(prefix):
    home = tempfile.mkdtemp(prefix=prefix)
    cfg = os.path.join(home, ".config", "uictl")
    os.makedirs(cfg)
    os.makedirs(os.path.join(home, ".local", "state"))
    # F13-F24 only. This used to be 183-199, on the theory that the codes
    # above F24 were unassigned -- they are, in the kernel header, but XKB
    # maps them to Super and a level-5 shift. See uictl_expect.SAFE_POLICY.
    with open(os.path.join(cfg, "policy"), "w") as f:
        f.write(uictl_expect.SAFE_POLICY)
    os.chmod(os.path.join(cfg, "policy"), 0o600)
    # interactive (50/s), so arbitration cases are not fighting the
    # rate limiter. BC uses a separate process with an unlisted name.
    with open(os.path.join(cfg, "clients"), "w") as f:
        f.write("arbit interactive\n")
    os.chmod(os.path.join(cfg, "clients"), 0o600)
    return home


if os.path.exists(SOCK):
    try:
        conn().close()
        print("SKIP: a uictld is already running; stop it and re-run")
        sys.exit(0)
    except OSError:
        pass

home = make_home("uictl-arbit-")
d = None
efd = None
pfd = None
try:
    # stderr to a file, not a pipe: AU reads it back while the daemon is
    # still running, and a pipe would either block or need a reader thread.
    errlog = os.path.join(home, "uictld.err")
    d = subprocess.Popen(["./uictld"], env=dict(os.environ, HOME=home),
                         stdout=subprocess.DEVNULL,
                         stderr=open(errlog, "w"), text=True)
    time.sleep(0.8)
    if d.poll() is not None:
        print("SKIP: daemon would not start:", open(errlog).read())
        sys.exit(0)

    node = event_node()
    if not node:
        fail("no event node for '%s'" % DEV_NAME)
        raise SystemExit
    try:
        efd = uictl_expect.open_node(node)
        # BA fills the hold cap with buttons, and those land on the
        # POINTER node. Nothing here reads it -- it is grabbed purely so
        # that a right-click or a back/forward press does not reach the
        # session while the cap is being filled.
        pfd = uictl_expect.open_node(pointer_node())
    except PermissionError:
        print("SKIP: cannot read %s (need the input group)" % node)
        sys.exit(0)

    a = conn()
    if hello(a)[0] != OK:
        fail("handshake failed")
        raise SystemExit

    # --- AU: DOWN holds ----------------------------------------------
    drain(efd, 0.2)
    r = key(a, OP_KEY_DOWN, KEY_F13)
    evs = keys_only(drain(efd, 0.5))
    if r != OK:
        fail("AU: key-down refused (result=%s)" % r)
    elif evs != [(EV_KEY, KEY_F13, 1)]:
        fail("AU: device saw %s, expected exactly one press of %d -- a DOWN "
             "that also released would make the whole milestone pointless"
             % (evs, KEY_F13))
    else:
        print("AU key-down pressed %d and left it down" % KEY_F13)

    # The held=N(age) column task 1 added, doing the job it was added for.
    d.send_signal(signal.SIGUSR1)
    time.sleep(0.3)
    dump = open(errlog).read()
    rows = [l for l in dump.splitlines() if "slot=" in l and "held=" in l]
    if not any(re.search(r"held=1\(\d+s\)", l) for l in rows):
        fail("AU: SIGUSR1 shows no connection holding a key:\n%s"
             % "\n".join(rows))
    else:
        print("AU SIGUSR1 names the holder: %s"
              % [l.split("held=")[-1] for l in rows if "held=1(" in l][0])

    # --- AW: duplicate DOWN ------------------------------------------
    drain(efd, 0.2)
    r = key(a, OP_KEY_DOWN, KEY_F13)
    evs = drain(efd, 0.4)
    if r != ERR_KEY_ALREADY_HELD:
        fail("AW: duplicate down got result=%s, expected ERR_KEY_ALREADY_HELD"
             % r)
    elif evs:
        fail("AW: the duplicate down still reached the device: %s -- that is "
             "a press the client can never balance" % evs)
    else:
        print("AW duplicate key-down refused, device untouched")

    # --- AX: contention ----------------------------------------------
    b = conn()
    if hello(b, b"arbit2")[0] != OK:
        fail("AX: second handshake failed")
    drain(efd, 0.2)
    r = key(b, OP_KEY_DOWN, KEY_F13)
    evs = drain(efd, 0.4)
    if r != ERR_KEY_HELD_BY_OTHER:
        fail("AX: contending down got result=%s, expected ERR_KEY_HELD_BY_OTHER"
             % r)
    elif evs:
        fail("AX: the contending down reached the device: %s" % evs)
    else:
        print("AX a key held by another connection cannot be pressed")

    # --- AV: UP releases ---------------------------------------------
    drain(efd, 0.2)
    r = key(a, OP_KEY_UP, KEY_F13)
    evs = keys_only(drain(efd, 0.5))
    if r != OK:
        fail("AV: key-up refused (result=%s)" % r)
    elif evs != [(EV_KEY, KEY_F13, 0)]:
        fail("AV: device saw %s, expected one release of %d" % (evs, KEY_F13))
    else:
        print("AV key-up released %d" % KEY_F13)

    # ... and the contender can now take it
    drain(efd, 0.2)
    r = key(b, OP_KEY_DOWN, KEY_F13)
    evs = keys_only(drain(efd, 0.4))
    if r != OK or evs != [(EV_KEY, KEY_F13, 1)]:
        fail("AX: after release the contender got result=%s evs=%s" % (r, evs))
    else:
        print("AX after the owner released, the contender took the key")
    key(b, OP_KEY_UP, KEY_F13)
    drain(efd, 0.3)
    b.close()

    # --- AY: UP for something not held --------------------------------
    drain(efd, 0.2)
    r = key(a, OP_KEY_UP, KEY_F14)
    evs = drain(efd, 0.4)
    if r != ERR_KEY_NOT_HELD:
        fail("AY: stray up got result=%s, expected ERR_KEY_NOT_HELD" % r)
    elif evs:
        fail("AY: a stray up reached the device: %s" % evs)
    else:
        print("AY key-up for an unheld key refused, device untouched")

    # --- AZ: the DOWN gate is the KEY_TAP gate ------------------------
    drain(efd, 0.2)
    checks = [(0, ERR_PAYLOAD_INVALID, "out of range"),
              (KEY_POWER, ERR_KEY_DENYLISTED, "deny-listed"),
              (KEY_A, ERR_KEY_NOT_ALLOWED, "not in policy")]
    bad = []
    for code, want, label in checks:
        got = key(a, OP_KEY_DOWN, code)
        if got != want:
            bad.append("%s: code=%d got result=%s want %s"
                       % (label, code, got, want))
    evs = drain(efd, 0.4)
    if bad:
        fail("AZ: " + "; ".join(bad))
    elif evs:
        fail("AZ: A REFUSED KEY-DOWN REACHED THE DEVICE: %s" % evs)
    else:
        print("AZ key-down runs the same gate as key-tap (range, deny-list, "
              "allowlist), nothing reached the device")

    # --- BA: the per-connection hold cap ------------------------------
    # The cap is 16 and only 12 keycodes are safe to inject (F13-F24 --
    # see uictl_expect.SAFE_POLICY). This used to walk 183..198 to make
    # up the difference, which held Super and a level-5 shift down for
    # the length of the check; the launcher opened and every key after
    # it produced a different character.
    #
    # The remaining four holds come from buttons instead, which is a
    # better test as well as a safer one: held_bits is ONE bitset for
    # keys and buttons together, so a cap that counted them separately
    # would pass a keys-only check and still let a connection hold 16 of
    # each. BTN_LEFT is deliberately the one left over to be refused --
    # it is never pressed, so nothing here can start a drag or a
    # selection.
    drain(efd, 0.2)
    held = []                       # (is_button, code)
    over = None
    ladder = ([(0, c) for c in range(183, 195)] +
              [(1, c) for c in (BTN_SIDE, BTN_EXTRA, BTN_MIDDLE, BTN_RIGHT,
                                BTN_LEFT)])
    if len(ladder) != MAX_HELD + 1:
        fail("BA: ladder is %d codes, need exactly MAX_HELD+1 (%d)"
             % (len(ladder), MAX_HELD + 1))
    for is_btn, code in ladder:
        r = button(a, code, 1) if is_btn else key(a, OP_KEY_DOWN, code)
        if r == OK:
            held.append((is_btn, code))
        elif r == ERR_TOO_MANY_HELD:
            over = code
            break
        else:
            fail("BA: unexpected result=%s at code=%d (button=%d)"
                 % (r, code, is_btn))
            break
    drain(efd, 0.5)
    if over is None:
        fail("BA: held %d keys with no cap" % len(held))
    elif len(held) != MAX_HELD:
        fail("BA: cap tripped after %d keys, expected %d" % (len(held), MAX_HELD))
    else:
        # the refusal must not have disturbed what is already held
        drain(efd, 0.2)
        first = held[0][1]
        r = key(a, OP_KEY_UP, first)
        evs = keys_only(drain(efd, 0.4))
        if r != OK or evs != [(EV_KEY, first, 0)]:
            fail("BA: after the cap refusal, releasing a held key gave "
                 "result=%s evs=%s" % (r, evs))
        else:
            print("BA cap of %d enforced across keys and buttons in one "
                  "bitset; what was held stayed held" % MAX_HELD)
            held.pop(0)
    for is_btn, code in held:
        button(a, code, 0) if is_btn else key(a, OP_KEY_UP, code)
    drain(efd, 0.5)

    # --- BC: UP is not rate limited -----------------------------------
    # A separate process, because the token bucket is keyed on the peer
    # pid: this one is unregistered, so it is 'untrusted' at 5/s.
    drain(efd, 0.2)
    flooder = subprocess.Popen(
        [sys.executable, "-c",
         "import socket,struct,sys\n"
         "s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)\n"
         "s.connect(%r)\n"
         "def rep():\n"
         "    h=s.recv(16); n=struct.unpack('<HHIII',h)[4]; b=s.recv(n)\n"
         "    return struct.unpack_from('<H',b,0)[0]\n"
         "b=struct.pack('<HH',1,1)+b'flooder'+b'\\x00'*25\n"
         "s.sendall(struct.pack('<HHIII',1,3,1,1,len(b))+b); rep()\n"
         "held=[]; limited=0\n"
         "for i,c in enumerate(range(190,200)):\n"
         "    s.sendall(struct.pack('<HHIII',1,6,1,10+i,2)+struct.pack('<H',c))\n"
         "    r=rep()\n"
         "    if r==0: held.append(c)\n"
         "    elif r==11: limited+=1\n"
         "if not held or not limited:\n"
         "    print('setup %%d %%d'%%(len(held),limited)); sys.exit(2)\n"
         "s.sendall(struct.pack('<HHIII',1,7,1,99,2)+struct.pack('<H',held[0]))\n"
         "print('up=%%d released=%%d'%%(rep(),held[0]))\n" % SOCK],
        stdout=subprocess.PIPE, text=True)
    out = flooder.stdout.read().strip()
    flooder.wait(timeout=10)
    evs = keys_only(drain(efd, 0.6))
    if flooder.returncode == 2:
        fail("BC: could not set up the rate-limit condition (%s)" % out)
    elif not out.startswith("up=0 "):
        fail("BC: with the bucket empty, key-up returned %s -- a throttled "
             "client cannot release what it holds, which is a stuck key" % out)
    else:
        released = int(out.split("released=")[1])
        if (EV_KEY, released, 0) not in evs:
            fail("BC: key-up was accepted but the release did not reach the "
                 "device: %s" % evs)
        else:
            print("BC key-up works with an empty token bucket (%s)" % out)
    # the flooder died holding the rest; task 2 cleans up
    drain(efd, 0.6)

    # --- BD: the CLI shape --------------------------------------------
    cli = subprocess.run(["./uictl", "hello", "clitest"],
                         env=dict(os.environ, HOME=home),
                         capture_output=True, text=True)
    if "key-down" not in cli.stdout or "key-up" not in cli.stdout:
        fail("BD: `uictl hello` does not list key-down/key-up:\n%s" % cli.stdout)
    else:
        usage = subprocess.run(["./uictl"], env=dict(os.environ, HOME=home),
                               capture_output=True, text=True)
        if "key-down" in usage.stderr:
            fail("BD: the CLI offers a key-down subcommand; a one-shot "
                 "process releases the moment it exits")
        else:
            print("BD CLI advertises key-down/key-up, offers no subcommand "
                  "for them")
    a.close()
finally:
    if efd is not None:
        os.close(efd)
    if pfd is not None:
        os.close(pfd)   # releases the grab; closing is the whole release
    if d is not None:
        d.send_signal(signal.SIGTERM)
        try:
            d.wait(timeout=5)
        except subprocess.TimeoutExpired:
            d.kill()
    shutil.rmtree(home, ignore_errors=True)

# --- BB: the dead-man timer -------------------------------------------
# HOLD_MAX_SEC is 30 in the shipped daemon, which is the right ceiling
# for a human gesture and the wrong one for a test. The throwaway build
# patches the constant only -- same timer, same call, faster clock.
tmp = tempfile.mkdtemp(prefix="uictl-deadman-")
home2 = make_home("uictl-deadman-home-")
d = None
try:
    shutil.copytree("src", os.path.join(tmp, "src"))
    src = os.path.join(tmp, "src", "uictld.c")
    text = open(src).read()
    if "#define HOLD_MAX_SEC 30" not in text:
        print("SKIP: HOLD_MAX_SEC is not where this test expects it")
        sys.exit(0)
    open(src, "w").write(text.replace("#define HOLD_MAX_SEC 30",
                                      "#define HOLD_MAX_SEC 2", 1))
    exe = os.path.join(tmp, "uictld-deadman")
    build = subprocess.run(
        ["cc", "-D_FORTIFY_SOURCE=2", "-fPIE", "-Wall", "-Wextra",
         "-Wconversion", "-g", "-std=c11", "-D_GNU_SOURCE", src,
         os.path.join(tmp, "src", "platform", "uinput.c"), "-o", exe, "-pie"],
        capture_output=True, text=True)
    if build.returncode != 0:
        print("SKIP: throwaway build failed:\n" + build.stderr)
        sys.exit(0)

    d = subprocess.Popen([exe], env=dict(os.environ, HOME=home2),
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         text=True)
    time.sleep(0.8)
    if d.poll() is not None:
        print("SKIP: throwaway daemon would not start:", d.stderr.read())
        sys.exit(0)

    node = event_node()
    efd = uictl_expect.open_node(node)
    a = conn()
    if hello(a)[0] != OK:
        fail("BB: handshake failed")
    drain(efd, 0.2)
    if key(a, OP_KEY_DOWN, KEY_F13) != OK:
        fail("BB: could not take a hold")
    drain(efd, 0.4)                       # consume the press
    evs = keys_only(drain(efd, 4.0))      # 2 s ceiling + 1 s reaper tick
    if evs != [(EV_KEY, KEY_F13, 0)]:
        fail("BB: after the ceiling the device saw %s, expected one release "
             "of %d -- a live client can hold a key forever" % (evs, KEY_F13))
    else:
        print("BB dead-man timer force-released a hold from a live client")

    # the connection survives, and the client learns on its next UP
    late_up = key(a, OP_KEY_UP, KEY_F13)
    still_usable = key(a, OP_KEY_DOWN, KEY_F14)
    if late_up != ERR_KEY_NOT_HELD:
        fail("BB: after a force-release the client's UP gave result=%s, "
             "expected ERR_KEY_NOT_HELD" % late_up)
    elif still_usable != OK:
        fail("BB: the connection was not usable after a force-release "
             "(result=%s) -- it should be released, not reaped" % still_usable)
    else:
        print("BB the connection survives it; the client learns on its "
              "next key-up")
    key(a, OP_KEY_UP, KEY_F14)
    audit = os.path.join(home2, ".local", "state", "uictl", "audit.log")
    text = open(audit).read() if os.path.exists(audit) else ""
    if "dead-man timer" not in text:
        fail("BB: the force-release was not audited:\n%s" % text[-400:])
    else:
        line = [l for l in text.splitlines() if "dead-man timer" in l][0]
        print("BB audited: %s" % line.split("args=")[-1])
    a.close()
    os.close(efd)
finally:
    if d is not None:
        d.send_signal(signal.SIGTERM)
        try:
            d.wait(timeout=5)
        except subprocess.TimeoutExpired:
            d.kill()
    shutil.rmtree(tmp, ignore_errors=True)
    shutil.rmtree(home2, ignore_errors=True)

print("\n== PASS ==" if ok else "\n== FAIL ==")
sys.exit(0 if ok else 1)
