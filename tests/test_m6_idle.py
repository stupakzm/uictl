#!/usr/bin/env python3
"""M6: idle exit -- the daemon leaves when nothing is connected.

Shipped verified by hand. That is a bad fit for this feature in
particular, because the decision inside it is invisible from the
outside: the daemon exits when the CONNECTION TABLE is empty
(conn_count_live, uictld.c), not when no key is held. Both predicates
pass every ordinary run. They differ only for a client that is
connected, holding nothing, and about to send something -- which is the
resting state of every long-lived client this broker exists to serve,
and the one where the wrong predicate pulls the daemon out from under
it.

So IC below is the suite. The rest is what has to be true around it.

The other thing at risk is the pairing with activation. Idle exit is
refused unless systemd holds the listening socket, and the refusal is
the feature: a daemon that exits when nothing will restart it takes the
socket file with it and every later client gets ECONNREFUSED with
nothing to fix. IG checks the refusal happens and is loud; IB checks
the socket file outlives the exit and the next activation serves on it,
which is what makes the exit cheap rather than terminal.

There is deliberately no case for "a pending confirmation blocks the
exit". It cannot be reached: a confirmation belongs to a connection, so
the table is not empty while one is open. The daemon checks it anyway,
and the reason it checks it is the reason there is no test -- a cheap
condition kept for the next change to either half, not a reachable
state today.

Runs with HOME in a temp dir so it owns the policy and client files.
Requires: no uictld running, /dev/uinput writable, read access to the
event nodes (input group).

IA  activated, an empty table for the timer: the daemon exits, within a
    reaper tick of the deadline, and says why.
IB  the socket file survives that exit and a second activation on the
    same listener serves. Without this, "idle exit" is "the daemon
    stops working after five seconds".
IC  NEGATIVE CONTROL. One connected client, handshaken, holding
    nothing, sending nothing: the daemon is still there after twice the
    timer. A build whose idle check asked "are any keys held?" instead
    of "are any connections live?" exits here, and only here.
ID  a held key does not get abandoned either. Weaker than IC by
    construction -- a "no keys held" build passes this one -- and worth
    stating because it is the case a reader expects to be the risk.
IE  the countdown is a duration measured from when the table emptied,
    not from start-up: after IC's client leaves, the exit comes one
    timer later, not immediately.
IF  the 5 s floor clamps a smaller setting, and clamps it in behaviour
    rather than only in the message: a daemon honouring 1 s would be
    gone before the third second.
IG  without socket activation the setting is refused, loudly, and the
    daemon keeps running. Ignoring it silently would present as "the
    daemon keeps vanishing" instead of "your unit is wrong".
IH  a value that is not a number is refused the same way, and an
    explicit 0 is off without a complaint -- a unit that always sets
    the variable must have a way to say "no" that is not a warning.
"""
import os, shutil, socket, struct, subprocess, sys, tempfile, time
import uictl_expect          # shared: safe key range, device nodes, grabs

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
SOCK = os.path.join(os.environ["XDG_RUNTIME_DIR"], "uictld.sock")
HDR = "<HHIII"
HDR_SIZE = struct.calcsize(HDR)
OP_PING, OP_HELLO, OP_KEY_DOWN = 1, 3, 6
OK = 0
KEY_F13 = 183

# The timer every case uses, and the floor it is equal to. Picking the
# floor itself keeps the suite honest about how long IC has to sit
# there: doubling a five second timer is the whole cost of the negative
# control, and a longer timer would buy nothing but a slower run.
IDLE = 5
TICK = 1        # REAPER_TICK_SEC: the exit lands within one of these

# The binary under test. Overridable so that a deliberately WRONG build
# can be run through this same file -- which is the only way to know the
# negative control bites:
#
#   cp -r src /tmp/mut && edit /tmp/mut/uictld.c so the idle check counts
#   held keys instead of live connections, build it, then
#   UICTL_TEST_DAEMON=/tmp/mut/uictld python3 tests/test_m6_idle.py
#
# IC must fail on that binary and pass on this one. A suite that cannot
# tell the two apart is not testing the decision, only the feature.
DAEMON = os.environ.get("UICTL_TEST_DAEMON", os.path.join(REPO, "uictld"))

ok = True


def fail(msg):
    global ok
    ok = False
    print("FAIL: " + msg)


def skip(msg):
    print("SKIP: " + msg)
    sys.exit(0)


def make_home():
    home = tempfile.mkdtemp(prefix="uictl-idle-")
    cfg = os.path.join(home, ".config", "uictl")
    os.makedirs(cfg, mode=0o700)
    os.makedirs(os.path.join(home, ".local", "state"), mode=0o700)
    # Only ID injects, and only KEY_F13. Never widen this -- the codes
    # just above F24 are Super and a level-5 shift once XKB is done with
    # them. See uictl_expect.SAFE_POLICY.
    with open(os.path.join(cfg, "policy"), "w") as f:
        f.write(uictl_expect.SAFE_POLICY)
    os.chmod(os.path.join(cfg, "policy"), 0o600)
    with open(os.path.join(cfg, "clients"), "w") as f:
        f.write("idle interactive\n")
    os.chmod(os.path.join(cfg, "clients"), 0o600)
    return home


def listener(path, mode=0o600):
    """Stand in for the .socket unit: create, bind, chmod, listen."""
    if os.path.exists(path):
        os.unlink(path)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(path)
    os.chmod(path, mode)
    s.listen(16)
    return s


def _spawn(argv_env, home, errname, preexec):
    errpath = os.path.join(home, errname)
    d = subprocess.Popen([DAEMON], cwd=REPO,
                         stdout=subprocess.DEVNULL,
                         stderr=open(errpath, "w"),
                         preexec_fn=preexec, **argv_env)
    d.errpath = errpath
    return d


def start_activated(srv, home, extra_env=None, errname="uictld.err"):
    """Start uictld with `srv` as fd 3, the way systemd would.

    A deliberate copy of test_m6_activation.py's fixture rather than an
    import of it. Every suite here stands alone -- `python3
    tests/test_m6_idle.py` has to work with no runner and no sibling
    suite importable -- and twenty forked lines cost less than a
    cross-suite dependency that breaks the first time someone runs one
    file, or reorders SUITES.

    LISTEN_PID is set from inside the child (preexec_fn runs after fork,
    before exec) because it must name the daemon's own pid. That is the
    entire point of the variable: an inherited environment must not
    convince some later process that its fd 3 is a listening socket.

    stderr goes to a FILE, not a pipe. Every case below reads the
    daemon's messages while it is still running, and a pipe nobody
    drains is a daemon that blocks once 64K of it fills -- which for a
    suite about a timer would look exactly like the timer being wrong.
    """
    env = dict(extra_env or {})

    def child():
        os.dup2(srv.fileno(), 3)
        os.set_inheritable(3, True)
        os.environ["HOME"] = home
        os.environ["LISTEN_FDS"] = "1"
        os.environ["LISTEN_PID"] = str(os.getpid())
        os.environ.update(env)

    return _spawn({"pass_fds": (srv.fileno(),)}, home, errname, child)


def start_plain(home, extra_env=None, errname="plain.err"):
    """The ordinary start: the daemon binds its own socket. The listener
    must be closed and the path unlinked before this, or bind() meets
    its own socket file."""
    env = dict(extra_env or {})

    def child():
        os.environ["HOME"] = home
        os.environ.pop("LISTEN_PID", None)
        os.environ.pop("LISTEN_FDS", None)
        os.environ.update(env)

    return _spawn({}, home, errname, child)


def errtext(d):
    try:
        return open(d.errpath).read()
    except OSError:
        return ""


def stop(d):
    if d.poll() is None:
        d.terminate()
        try:
            d.wait(timeout=5)
        except subprocess.TimeoutExpired:
            d.kill()
            d.wait(timeout=5)


def wait_exit(d, seconds):
    """Seconds the daemon took to exit, or None if it outlived the wait."""
    t0 = time.monotonic()
    while time.monotonic() - t0 < seconds:
        if d.poll() is not None:
            return time.monotonic() - t0
        time.sleep(0.1)
    return None


def conn():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect(SOCK)
    return s


_seq = [1]


def send(s, opcode, payload):
    _seq[0] += 1
    s.sendall(struct.pack(HDR, 1, opcode, 1, _seq[0], len(payload)) + payload)
    head = s.recv(HDR_SIZE)
    if len(head) != HDR_SIZE:
        return None
    plen = struct.unpack(HDR, head)[4]
    body = b""
    while len(body) < plen:
        chunk = s.recv(plen - len(body))
        if not chunk:
            break
        body += chunk
    return struct.unpack_from("<H", body, 0)[0] if body else None


def hello(s):
    return send(s, OP_HELLO, struct.pack("<HH", 1, 1) + b"idle".ljust(32, b"\x00"))


def ping(s):
    return send(s, OP_PING, b"")


def started(d, what):
    """One second for device registration, then a liveness check. Every
    case starts by proving the daemon came up at all, because 'it exited
    during the wait' and 'it never started' are the same observation
    otherwise."""
    time.sleep(1.0)
    if d.poll() is not None:
        fail("%s: the daemon did not start:\n%s" % (what, errtext(d)))
        return False
    return True


if not os.access("/dev/uinput", os.W_OK):
    skip("/dev/uinput is not writable (input group?)")
if os.path.exists(SOCK):
    try:
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        probe.connect(SOCK)
        probe.close()
        skip("a uictld is already listening; this suite starts its own")
    except OSError:
        pass

home = make_home()
srv = None
d = None
grabs = []
try:
    srv = listener(SOCK)

    # --- IA: it exits, and not before the timer -----------------------
    d = start_activated(srv, home, {"UICTL_IDLE_EXIT_SEC": str(IDLE)},
                        "ia.err")
    if started(d, "IA"):
        c = conn()
        if ping(c) != OK:
            fail("IA: the activated daemon did not answer a PING")
        c.close()
        # The clock starts at the reaper tick that saw the table empty,
        # which is up to one tick before this close returned -- hence the
        # tick of slack on the low side. On the high side the exit can
        # only be late by the tick that notices it.
        t = wait_exit(d, IDLE * 3)
        if t is None:
            fail("IA: still running %ds after the last client left, with "
                 "UICTL_IDLE_EXIT_SEC=%d" % (IDLE * 3, IDLE))
            stop(d)
        elif t < IDLE - TICK - 0.5:
            fail("IA: exited after %.1fs, before the %ds timer" % (t, IDLE))
        elif "idle for" not in errtext(d):
            fail("IA: exited on time but said nothing about why:\n%s"
                 % errtext(d))
        else:
            print("IA an empty connection table for %ds ends the daemon "
                  "(%.1fs)" % (IDLE, t))
    d = None

    # --- IB: the exit is cheap, not terminal --------------------------
    if not os.path.exists(SOCK):
        fail("IB: the idle exit took the socket file with it. The socket "
             "unit is now listening on an unreachable inode and no "
             "restart of the service fixes it.")
    else:
        d = start_activated(srv, home, errname="ib.err")
        if started(d, "IB"):
            try:
                c = conn()
                r = ping(c)
                c.close()
                if r != OK:
                    fail("IB: the next activation did not serve (result=%s)"
                         % r)
                else:
                    print("IB the socket file survives, and the next "
                          "activation serves on it")
            except OSError as e:
                fail("IB: nothing could reach the next activation: %s" % e)
        stop(d)
        d = None

    # --- IC: the negative control -------------------------------------
    # One client, connected and handshaken, doing nothing at all. This is
    # the shape a build that tested "no keys held" gets wrong.
    d = start_activated(srv, home, {"UICTL_IDLE_EXIT_SEC": str(IDLE)},
                        "ic.err")
    c = None
    if started(d, "IC"):
        c = conn()
        if hello(c) != OK:
            fail("IC: HELLO refused; is the client registry being read?")
        t = wait_exit(d, IDLE * 2)
        if t is not None:
            fail("IC: exited after %.1fs with a client connected. The idle "
                 "check is testing something other than the connection "
                 "table -- held keys, most likely -- and every idle "
                 "long-lived client is now on a %ds fuse.\n%s"
                 % (t, IDLE, errtext(d)))
        else:
            print("IC a connected client that holds nothing keeps the "
                  "daemon alive past %ds" % (IDLE * 2))

        # --- IE: the countdown runs from the disconnect ---------------
        if c is not None:
            c.close()
            c = None
            t = wait_exit(d, IDLE * 3)
            if t is None:
                fail("IE: the client left and the daemon stayed. The clock "
                     "is not being restarted when the table empties.")
            elif t < IDLE - TICK - 0.5:
                fail("IE: exited %.1fs after the client left; the timer is "
                     "%ds and had been reset by the connection" % (t, IDLE))
            else:
                print("IE and it exits %.1fs after that client leaves, not "
                      "at %ds from start-up" % (t, IDLE))
    if c is not None:
        c.close()
    stop(d)
    d = None

    # --- ID: nor is a held key abandoned ------------------------------
    d = start_activated(srv, home, {"UICTL_IDLE_EXIT_SEC": str(IDLE)},
                        "id.err")
    c = None
    if started(d, "ID"):
        # Grab both nodes BEFORE the first injection: KEY_DOWN reaches a
        # real device and the compositor delivers it to whatever has
        # focus. F13 is unbound on a normal desktop, which is a reason to
        # pick it and not a reason to skip the grab.
        grabs = uictl_expect.grab_all()
        c = conn()
        if hello(c) != OK:
            fail("ID: HELLO refused")
        elif send(c, OP_KEY_DOWN, struct.pack("<H", KEY_F13)) != OK:
            fail("ID: KEY_DOWN refused; is the policy file being read?")
        else:
            # HOLD_MAX_SEC is 30, so the dead-man timer does not fire
            # inside this window and the key really is held throughout.
            t = wait_exit(d, IDLE * 2)
            if t is not None:
                fail("ID: exited after %.1fs with a key held down. The key "
                     "stays pressed on the user's desktop until something "
                     "else clears it." % t)
            else:
                print("ID a held key keeps it alive too (weaker than IC by "
                      "construction)")
        c.close()
        c = None
    if c is not None:
        c.close()
    stop(d)                      # releases the held key on the way out
    d = None
    for fd in grabs:
        os.close(fd)
    grabs = []

    # --- IF: the floor, in behaviour ----------------------------------
    d = start_activated(srv, home, {"UICTL_IDLE_EXIT_SEC": "1"}, "if.err")
    # No client at all: the clock starts when the accept loop does, so a
    # daemon honouring 1 s is gone within about two.
    t = wait_exit(d, 3.0)
    if t is not None:
        fail("IF: exited after %.1fs on UICTL_IDLE_EXIT_SEC=1. The %ds "
             "floor is not being applied, and activation would restart "
             "this daemon faster than a client can connect to it."
             % (t, IDLE))
    else:
        t = wait_exit(d, IDLE * 3)
        if t is None:
            fail("IF: clamped so hard it never exits; expected the %ds "
                 "floor:\n%s" % (IDLE, errtext(d)))
        elif "floor" not in errtext(d):
            fail("IF: clamped to the floor without saying so:\n%s"
                 % errtext(d))
        else:
            print("IF a 1s setting is clamped to the %ds floor, in "
                  "behaviour and in the message" % IDLE)
    stop(d)
    d = None

    # --- IH: values that are not timers -------------------------------
    d = start_activated(srv, home, {"UICTL_IDLE_EXIT_SEC": "soon"}, "ih1.err")
    if started(d, "IH"):
        t = wait_exit(d, IDLE + TICK + 2)
        if t is not None:
            fail("IH: UICTL_IDLE_EXIT_SEC=soon was parsed as a timer "
                 "(exited after %.1fs)" % t)
        elif "not a number" not in errtext(d):
            fail("IH: a garbage setting was ignored silently:\n%s"
                 % errtext(d))
        else:
            print("IH a non-numeric setting is ignored, and said so")
    stop(d)
    d = None

    d = start_activated(srv, home, {"UICTL_IDLE_EXIT_SEC": "0"}, "ih2.err")
    if started(d, "IH"):
        t = wait_exit(d, IDLE + TICK + 2)
        err = errtext(d)
        # Named branches, not the word "idle": the daemon echoes the
        # client registry on start-up and this suite's client is called
        # `idle`, so a substring check passes its own configuration off
        # as a complaint. It did, on the first run of this file.
        complaints = [w for w in ("not a number", "floor",
                                  "not socket-activated", "will exit after")
                      if w in err]
        if t is not None:
            fail("IH: an explicit 0 exited after %.1fs; 0 means off" % t)
        elif complaints:
            fail("IH: an explicit 0 produced a complaint (%s). A unit that "
                 "always sets the variable has no other way to say no:\n%s"
                 % (", ".join(complaints), err))
        else:
            print("IH   and an explicit 0 is off, quietly")
    stop(d)
    d = None

    srv.close()
    srv = None
    if os.path.exists(SOCK):
        os.unlink(SOCK)

    # --- IG: refused without activation -------------------------------
    d = start_plain(home, {"UICTL_IDLE_EXIT_SEC": str(IDLE)}, "ig.err")
    if started(d, "IG"):
        t = wait_exit(d, IDLE * 2)
        err = errtext(d)
        if t is not None:
            fail("IG: a self-bound daemon honoured UICTL_IDLE_EXIT_SEC and "
                 "exited after %.1fs. Nothing will start it again, and the "
                 "socket file left with it." % t)
        elif "not socket-activated" not in err:
            fail("IG: the setting was ignored, but silently. 'the daemon "
                 "keeps vanishing' and 'your unit is wrong' are a "
                 "debugging afternoon apart:\n%s" % err)
        else:
            print("IG without activation the setting is refused, loudly, "
                  "and the daemon stays up")
    stop(d)
    d = None

finally:
    if d is not None:
        stop(d)
    for fd in grabs:
        os.close(fd)
    if srv is not None:
        srv.close()
    if os.path.exists(SOCK):
        os.unlink(SOCK)
    shutil.rmtree(home, ignore_errors=True)

print("\n== PASS ==" if ok else "\n== FAIL ==")
sys.exit(0 if ok else 1)
