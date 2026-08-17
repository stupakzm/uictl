#!/usr/bin/env python3
"""M5: the confirmation hook.

A client whose registry entry carries the `confirm` role has its
device-touching requests parked until a human answers. The prompt goes
to whichever connection holds the `confirmer` role -- the first frame in
this protocol the daemon ever sends unprompted.

Runs its own daemon with HOME in a temp dir. Requires no uictld running
and read access to the event node (input group).

CA  a flagged client's key-tap does not reach the device while it waits;
    the confirmer receives a prompt naming the client, its pid, its
    daemon-derived class and the keycode.
CB  "yes" completes the original request: the key reaches the device,
    the client gets OK for the seq it sent, and both the approval and
    the action are audited.
CC  "no" answers ERR_CONFIRM_DENIED and the device sees nothing.
CD  the gate keys on the daemon-derived role, NOT on source_tag: the
    same client sending SRC_CLI, SRC_HOTKEY or SRC_LLM is parked
    identically. This is the plan's original design being wrong (G2) and
    the fix being load-bearing.
CE  fails CLOSED: with no confirmer subscribed, a flagged client gets
    ERR_CONFIRM_UNAVAILABLE and the device stays silent.
CF  only a client with the `confirmer` role may subscribe, and only one
    at a time (ERR_NOT_CONFIRMER).
CG  a parked client is not read from: a second request pipelined behind
    the parked one is not answered until the first resolves, and then it
    is answered normally.
CH  a stale or forged token is refused, and does not resolve the live
    confirmation.
CI  the confirmer disconnecting mid-prompt denies the parked request
    immediately rather than leaving it to time out.
CJ  an unflagged client is not gated at all -- no prompt, no delay.
CK  the timeout denies. Uses a throwaway build with CONFIRM_TIMEOUT_SEC
    patched to 2: same timer, faster clock.
CL  the uictl-confirm binary itself works end to end, driven over a pipe.
"""
import os, re, shutil, signal, socket, struct, subprocess, sys, tempfile, time
import uictl_expect          # shared: device nodes, opcode set

SOCK = os.path.join(os.environ["XDG_RUNTIME_DIR"], "uictld.sock")
DEVICES = "/proc/bus/input/devices"
DEV_NAME = "uictl virtual pointer"
HDR = "<HHIII"
OP_PING, OP_MOVE_ABS, OP_HELLO, OP_KEY_TAP = 1, 2, 3, 4
OP_KEY_SEQUENCE, OP_KEY_DOWN, OP_KEY_UP = 5, 6, 7
OP_CONFIRM_SUBSCRIBE, OP_CONFIRM_REQUEST, OP_CONFIRM_DECIDE = 8, 9, 10
(OK, ERR_VERSION, ERR_OPCODE_UNKNOWN, ERR_PAYLOAD_INVALID,
 ERR_DENIED_BY_POLICY, ERR_TOO_LARGE, ERR_INTERNAL, ERR_BUSY,
 ERR_HANDSHAKE_REQUIRED, ERR_KEY_DENYLISTED, ERR_KEY_NOT_ALLOWED,
 ERR_RATE_LIMITED, ERR_KEY_ALREADY_HELD, ERR_KEY_HELD_BY_OTHER,
 ERR_KEY_NOT_HELD, ERR_TOO_MANY_HELD, ERR_CONFIRM_UNAVAILABLE,
 ERR_CONFIRM_DENIED, ERR_CONFIRM_TIMEOUT, ERR_NOT_CONFIRMER) = range(20)
SRC_CLI, SRC_HOTKEY, SRC_LLM = 1, 2, 4
EV_SYN, EV_KEY = 0x00, 0x01
KEY_F13, KEY_F14 = 183, 184
CONFIRM_REQ_FMT = "<IIHHHH32s"
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


def recv_frame(s, timeout=5):
    s.settimeout(timeout)
    h = b""
    while len(h) < 16:
        chunk = s.recv(16 - len(h))
        if not chunk:
            return None, None, b""
        h += chunk
    ver, op, src, seq, plen = struct.unpack(HDR, h)
    body = b""
    while len(body) < plen:
        chunk = s.recv(plen - len(body))
        if not chunk:
            break
        body += chunk
    return op, seq, body


def reply(s, timeout=5):
    op, seq, body = recv_frame(s, timeout)
    if body is None or len(body) < 2:
        return None, b""
    return struct.unpack_from("<H", body, 0)[0], body[2:]


def hello(s, name, seq=1, src=SRC_CLI):
    body = struct.pack("<HH", 1, 1) + name.encode() + b"\x00" * (32 - len(name))
    s.sendall(struct.pack(HDR, 1, OP_HELLO, src, seq, len(body)) + body)
    return reply(s)


def send_key(s, code, seq, op=OP_KEY_TAP, src=SRC_CLI):
    s.sendall(struct.pack(HDR, 1, op, src, seq, 2) + struct.pack("<H", code))


def subscribe(s, seq=2):
    s.sendall(struct.pack(HDR, 1, OP_CONFIRM_SUBSCRIBE, SRC_CLI, seq, 0))
    return reply(s)[0]


def decide(s, token, allow, seq=99):
    body = struct.pack("<IBBBB", token, 1 if allow else 0, 0, 0, 0)
    s.sendall(struct.pack(HDR, 1, OP_CONFIRM_DECIDE, SRC_CLI, seq, len(body))
              + body)
    return reply(s)[0]


def expect_prompt(cf, timeout=5):
    """Read one OP_CONFIRM_REQUEST push off the confirmer's connection."""
    op, seq, body = recv_frame(cf, timeout)
    if op != OP_CONFIRM_REQUEST:
        return None
    token, pid, opcode, keycode, cl, res, name = struct.unpack(
        CONFIRM_REQ_FMT, body)
    return dict(token=token, pid=pid, opcode=opcode, keycode=keycode, cl=cl,
                reserved=res, name=name.split(b"\x00")[0].decode(), seq=seq)


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
    return [e for e in evs if e[0] == EV_KEY]


def make_home(prefix):
    home = tempfile.mkdtemp(prefix=prefix)
    cfg = os.path.join(home, ".config", "uictl")
    os.makedirs(cfg)
    os.makedirs(os.path.join(home, ".local", "state"))
    with open(os.path.join(cfg, "policy"), "w") as f:
        f.write("183-194\n")          # F13-F24, unbound on any desktop
    os.chmod(os.path.join(cfg, "policy"), 0o600)
    with open(os.path.join(cfg, "clients"), "w") as f:
        f.write("agent      untrusted   confirm\n"
                "prompter   untrusted   confirmer\n"
                "plain      interactive\n"
                "uictl-confirm untrusted confirmer\n")
    os.chmod(os.path.join(cfg, "clients"), 0o600)
    return home


def start(exe, home):
    errlog = os.path.join(home, "uictld.err")
    d = subprocess.Popen([exe], env=dict(os.environ, HOME=home),
                         stdout=subprocess.DEVNULL, stderr=open(errlog, "w"))
    time.sleep(0.8)
    return d, errlog


def stop(d):
    if d and d.poll() is None:
        d.send_signal(signal.SIGTERM)
        try:
            d.wait(timeout=5)
        except subprocess.TimeoutExpired:
            d.kill()


if os.path.exists(SOCK):
    try:
        conn().close()
        print("SKIP: a uictld is already running; stop it and re-run")
        sys.exit(0)
    except OSError:
        pass

home = make_home("uictl-confirm-")
d = None
efd = None
try:
    d, errlog = start("./uictld", home)
    if d.poll() is not None:
        print("SKIP: daemon would not start:", open(errlog).read())
        sys.exit(0)
    node = event_node()
    if not node:
        fail("no event node for '%s'" % DEV_NAME)
        raise SystemExit
    try:
        efd = uictl_expect.open_node(node)
    except PermissionError:
        print("SKIP: cannot read %s (need the input group)" % node)
        sys.exit(0)
    audit_path = os.path.join(home, ".local", "state", "uictl", "audit.log")

    # --- CE: fails closed with no confirmer ---------------------------
    a = conn()
    if hello(a, "agent")[0] != OK:
        fail("CE: agent handshake failed")
    drain(efd, 0.2)
    send_key(a, KEY_F13, 10)
    r = reply(a)[0]
    evs = drain(efd, 0.4)
    if r != ERR_CONFIRM_UNAVAILABLE:
        fail("CE: with no confirmer the flagged client got result=%s, "
             "expected ERR_CONFIRM_UNAVAILABLE" % r)
    elif evs:
        fail("CE: THE KEY REACHED THE DEVICE with no confirmer running: %s"
             % evs)
    else:
        print("CE no confirmer means no approval, not automatic approval")

    # --- CF: only the confirmer role may subscribe --------------------
    bad = conn()
    hello(bad, "plain")
    r = subscribe(bad)
    if r != ERR_NOT_CONFIRMER:
        fail("CF: a client without the confirmer role subscribed (result=%s) "
             "-- it could then approve its own requests" % r)
    else:
        print("CF a client without the `confirmer` role cannot subscribe")
    bad.close()

    cf = conn()
    if hello(cf, "prompter")[0] != OK:
        fail("CF: prompter handshake failed")
    if subscribe(cf) != OK:
        fail("CF: the registered confirmer could not subscribe")
    cf2 = conn()
    hello(cf2, "prompter")
    if subscribe(cf2) != ERR_NOT_CONFIRMER:
        fail("CF: a second confirmer was allowed to subscribe, silently "
             "displacing the first")
    else:
        print("CF one confirmer at a time; the first subscriber keeps it")
    cf2.close()

    # --- CA: the request is parked and the prompt describes it --------
    drain(efd, 0.2)
    send_key(a, KEY_F13, 11)
    time.sleep(0.3)
    evs = drain(efd, 0.3)
    if evs:
        fail("CA: THE KEY REACHED THE DEVICE BEFORE ANY HUMAN ANSWERED: %s"
             % evs)
    p = expect_prompt(cf)
    if not p:
        fail("CA: no prompt arrived on the confirmer's connection")
        raise SystemExit
    if (p["name"] != "agent" or p["opcode"] != OP_KEY_TAP
            or p["keycode"] != KEY_F13 or p["cl"] != 0 or p["reserved"] != 0):
        fail("CA: prompt was %s" % p)
    elif p["pid"] != os.getpid():
        fail("CA: prompt named pid %d, this process is %d -- the pid must "
             "come from SO_PEERCRED" % (p["pid"], os.getpid()))
    else:
        print("CA parked, nothing at the device; prompt names agent/pid/"
              "class/keycode")

    # --- CG: a parked connection is not read from ---------------------
    send_key(a, KEY_F14, 12)          # pipelined behind the parked one
    a.settimeout(0.6)
    early = None
    try:
        early = reply(a, timeout=0.6)[0]
    except socket.timeout:
        pass
    if early is not None:
        fail("CG: a request pipelined behind a parked one was answered "
             "(result=%s) -- it jumped the queue past the prompt" % early)
    else:
        print("CG a parked connection is not read from; the queued request "
              "waits")

    # --- CH: a forged token does not resolve the live confirmation ----
    if decide(cf, p["token"] ^ 0xdead, True) != ERR_PAYLOAD_INVALID:
        fail("CH: a forged token was accepted")
    else:
        print("CH a stale/forged token is refused")

    # --- CB: yes completes the original request -----------------------
    drain(efd, 0.2)
    if decide(cf, p["token"], True) != OK:
        fail("CB: the decision was not acked")
    r, _ = reply(a, timeout=5)
    evs = drain(efd, 0.6)
    if r != OK:
        fail("CB: after approval the client got result=%s" % r)
    elif evs != [(EV_KEY, KEY_F13, 1), (EV_KEY, KEY_F13, 0)]:
        fail("CB: after approval the device saw %s, expected one tap of %d"
             % (evs, KEY_F13))
    else:
        print("CB approval completes the original request at the device")
    # ... and the queued second request is picked up once the park clears.
    # It is from the same flagged client, so it prompts in its turn rather
    # than being answered directly -- which is the queue draining correctly.
    p2 = expect_prompt(cf)
    if not p2 or p2["keycode"] != KEY_F14:
        fail("CG: the queued request did not resume after the park cleared "
             "(prompt=%s)" % p2)
    else:
        decide(cf, p2["token"], True)
        r2, _ = reply(a, timeout=5)
        if r2 != OK:
            fail("CG: the resumed request failed (result=%s)" % r2)
        else:
            print("CG the queued request resumes normally afterwards")
    drain(efd, 0.5)

    audit = open(audit_path).read()
    if "confirmed by user" not in audit:
        fail("CB: the approval was not audited")
    else:
        print("CB audited: %s" % [l.split("args=")[-1] for l in
                                  audit.splitlines()
                                  if "confirmed by user" in l][0])

    # --- CC: no --------------------------------------------------------
    drain(efd, 0.2)
    send_key(a, KEY_F13, 13)
    p = expect_prompt(cf)
    if not p:
        fail("CC: no prompt")
    else:
        decide(cf, p["token"], False)
        r, _ = reply(a, timeout=5)
        evs = drain(efd, 0.5)
        if r != ERR_CONFIRM_DENIED:
            fail("CC: after refusal the client got result=%s" % r)
        elif evs:
            fail("CC: A REFUSED REQUEST REACHED THE DEVICE: %s" % evs)
        else:
            print("CC refusal answers ERR_CONFIRM_DENIED, device untouched")

    # --- CD: the gate ignores source_tag ------------------------------
    tags = {}
    for tag, label in ((SRC_CLI, "SRC_CLI"), (SRC_HOTKEY, "SRC_HOTKEY"),
                       (SRC_LLM, "SRC_LLM")):
        send_key(a, KEY_F13, 20 + tag, src=tag)
        pp = expect_prompt(cf)
        tags[label] = pp is not None
        if pp:
            decide(cf, pp["token"], False)
            reply(a, timeout=5)
    if not all(tags.values()):
        fail("CD: source_tag changed whether a request was gated: %s -- the "
             "client would simply not set the bit (G2)" % tags)
    else:
        print("CD gating is identical for SRC_CLI/SRC_HOTKEY/SRC_LLM "
              "(source_tag is not a policy input)")

    # --- CJ: an unflagged client is not gated -------------------------
    pl = conn()
    hello(pl, "plain")
    drain(efd, 0.2)
    send_key(pl, KEY_F14, 30)
    t0 = time.monotonic()
    r = reply(pl, timeout=2)[0]
    dt = time.monotonic() - t0
    evs = drain(efd, 0.5)
    if r != OK or not evs:
        fail("CJ: an unflagged client was not served normally (result=%s, "
             "evs=%s)" % (r, evs))
    elif dt > 1.0:
        fail("CJ: an unflagged client waited %.1fs -- it was gated" % dt)
    else:
        print("CJ an unflagged client is not gated (%.0f ms, key reached the "
              "device)" % (dt * 1000))
    pl.close()

    # --- CM: a RELEASE is never gated (WIRE.md 6.3) --------------------
    # Found by writing 6.3, not by a failing test. The gate ran on
    # op_touches_device() alone, so a flagged client's KEY_UP was parked
    # for a human -- and every way the confirmation flow can end badly
    # (denied, timed out, no confirmer) left the key DOWN. The flow fails
    # closed by design, so the gate turned "the user said no" into a
    # stuck modifier that only the 30-second dead-man timer would clear.
    #
    # The rule: policy already had its say on the PRESS, so nothing can
    # be held that was not allowed, and re-asking on the way up can only
    # ever create a stuck key. The rate limiter exempted releases from
    # M4; the confirmation gate did not until now.
    drain(efd, 0.2)
    send_key(a, KEY_F13, 50, op=OP_KEY_DOWN)
    pm = expect_prompt(cf)
    if not pm:
        fail("CM: the DOWN was not prompted -- a press must still be gated")
    else:
        if decide(cf, pm["token"], True) != OK:
            fail("CM: could not approve the press")
        elif reply(a, timeout=5)[0] != OK:
            fail("CM: the approved press was refused")
        else:
            # The release must go straight through: no prompt, no wait.
            drain(efd, 0.3)
            t0 = time.monotonic()
            send_key(a, KEY_F13, 51, op=OP_KEY_UP)
            try:
                r = reply(a, timeout=3)[0]
            except (TimeoutError, socket.timeout):
                # The pre-fix behaviour, and the worst of the three: the
                # release is parked for a human who is not there, so the
                # client gets no answer at all and the key stays down
                # until the dead-man timer. Reported, not raised -- a
                # negative control has to produce a legible failure.
                r = None
            dt = time.monotonic() - t0
            evs = drain(efd, 0.4)
            if r is None:
                fail("CM: a flagged client's KEY_UP got NO reply in 3s -- it "
                     "was parked awaiting a human, and the key is still down")
            elif r != OK:
                fail("CM: a flagged client's KEY_UP got result=%s -- a "
                     "release must never be refused for a policy reason, "
                     "or the key stays down" % r)
            elif dt > 1.0:
                fail("CM: the KEY_UP waited %.1fs -- it was parked for a "
                     "human, which is the bug" % dt)
            elif (EV_KEY, KEY_F13, 0) not in evs:
                fail("CM: the key was not released at the device: %s" % evs)
            else:
                print("CM a flagged client's release is not gated (%.0f ms, "
                      "key came back up)" % (dt * 1000))

    # --- CI: the confirmer vanishing denies, immediately --------------
    drain(efd, 0.2)
    send_key(a, KEY_F13, 40)
    if not expect_prompt(cf):
        fail("CI: no prompt")
    cf.close()
    t0 = time.monotonic()
    r = reply(a, timeout=5)[0]
    dt = time.monotonic() - t0
    evs = drain(efd, 0.4)
    if r != ERR_CONFIRM_UNAVAILABLE:
        fail("CI: after the confirmer vanished the client got result=%s, "
             "expected ERR_CONFIRM_UNAVAILABLE" % r)
    elif evs:
        fail("CI: the request executed after the confirmer vanished: %s" % evs)
    elif dt > 2.0:
        fail("CI: took %.1fs -- it waited for the timeout instead of failing "
             "when the prompter left" % dt)
    else:
        print("CI confirmer disconnecting denies the parked request in "
              "%.0f ms" % (dt * 1000))
    a.close()

    # --- CL: the uictl-confirm binary, end to end ---------------------
    helper = subprocess.Popen(["./uictl-confirm", "uictl-confirm"],
                              env=dict(os.environ, HOME=home),
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              text=True, bufsize=1)
    line = helper.stdout.readline()
    if "subscribed" not in line:
        fail("CL: uictl-confirm did not subscribe: %s" % line)
    else:
        a2 = conn()
        hello(a2, "agent")
        drain(efd, 0.2)
        send_key(a2, KEY_F13, 50)
        # the helper prints the prompt and blocks on stdin
        seen = ""
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and "allow?" not in seen:
            seen += helper.stdout.readline()
        helper.stdin.write("y\n")
        helper.stdin.flush()
        r = reply(a2, timeout=5)[0]
        evs = drain(efd, 0.6)
        if "agent" not in seen or "keycode: 183" not in seen:
            fail("CL: the helper's prompt did not describe the request:\n%s"
                 % seen)
        elif r != OK or not evs:
            fail("CL: answering y did not complete the request (result=%s, "
                 "evs=%s)" % (r, evs))
        else:
            print("CL uictl-confirm drove a real approval end to end")
        a2.close()
    helper.kill()
finally:
    if efd is not None:
        os.close(efd)
    stop(d)
    shutil.rmtree(home, ignore_errors=True)

# --- CK: the timeout denies -------------------------------------------
tmp = tempfile.mkdtemp(prefix="uictl-confirm-to-")
home2 = make_home("uictl-confirm-to-home-")
d = None
try:
    shutil.copytree("src", os.path.join(tmp, "src"))
    src = os.path.join(tmp, "src", "uictld.c")
    text = open(src).read()
    if "#define CONFIRM_TIMEOUT_SEC 30" not in text:
        print("SKIP: CONFIRM_TIMEOUT_SEC is not where this test expects it")
        sys.exit(0)
    open(src, "w").write(text.replace("#define CONFIRM_TIMEOUT_SEC 30",
                                      "#define CONFIRM_TIMEOUT_SEC 2", 1))
    exe = os.path.join(tmp, "uictld-timeout")
    build = subprocess.run(
        ["cc", "-D_FORTIFY_SOURCE=2", "-fPIE", "-Wall", "-Wextra",
         "-Wconversion", "-g", "-std=c11", "-D_GNU_SOURCE", src,
         os.path.join(tmp, "src", "platform", "uinput.c"), "-o", exe, "-pie"],
        capture_output=True, text=True)
    if build.returncode != 0:
        print("SKIP: throwaway build failed:\n" + build.stderr)
        sys.exit(0)

    d, errlog = start(exe, home2)
    if d.poll() is not None:
        print("SKIP: throwaway daemon would not start:", open(errlog).read())
        sys.exit(0)
    efd = uictl_expect.open_node(event_node())
    cf = conn()
    hello(cf, "prompter")
    subscribe(cf)
    a = conn()
    hello(a, "agent")
    drain(efd, 0.2)
    send_key(a, KEY_F13, 60)
    if not expect_prompt(cf):
        fail("CK: no prompt")
    t0 = time.monotonic()
    r = reply(a, timeout=10)[0]      # 2 s ceiling + 1 s reaper tick
    dt = time.monotonic() - t0
    evs = drain(efd, 0.4)
    if r != ERR_CONFIRM_TIMEOUT:
        fail("CK: an unanswered prompt resolved as result=%s, expected "
             "ERR_CONFIRM_TIMEOUT" % r)
    elif evs:
        fail("CK: A TIMED-OUT REQUEST REACHED THE DEVICE: %s -- a timeout "
             "must deny, never approve" % evs)
    else:
        print("CK an unanswered prompt denies after %.1fs" % dt)
    # the connection survives and the channel is not wedged
    send_key(a, KEY_F13, 61)
    p = expect_prompt(cf)
    if not p:
        fail("CK: after a timeout the confirmation channel was wedged")
    else:
        decide(cf, p["token"], True)
        if reply(a, timeout=5)[0] != OK:
            fail("CK: the next request after a timeout did not complete")
        else:
            print("CK the channel is usable again afterwards")
    os.close(efd)
    a.close()
    cf.close()
finally:
    stop(d)
    shutil.rmtree(tmp, ignore_errors=True)
    shutil.rmtree(home2, ignore_errors=True)

print("\n== PASS ==" if ok else "\n== FAIL ==")
sys.exit(0 if ok else 1)
