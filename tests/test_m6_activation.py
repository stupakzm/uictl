#!/usr/bin/env python3
"""M6: socket activation, without systemd in the loop.

The handoff is three environment variables and a file descriptor, so it
can be staged exactly by any process willing to set them -- which is the
whole reason it is worth testing here rather than only under
`systemctl --user`. A suite that needed a real systemd unit would be a
suite nobody runs.

What is actually at risk in this feature, and therefore what each check
is for:

  the socket file's MODE. systemd creates the node, and its SocketMode
  default is 0666. A unit that forgets SocketMode=0600 produces a
  world-writable input broker -- the exact outcome this whole project
  exists to prevent -- and everything would still appear to work. The
  daemon must refuse.

  the socket file's OWNERSHIP. Nothing about the daemon binding its own
  socket could hand it a path owned by someone else. Activation can.

  NOT unlinking it. Under activation the path belongs to the socket
  unit and outlives the service. A daemon that removes it on shutdown
  leaves the unit listening on an inode nothing can reach, and no
  restart of the service fixes it.

Runs with HOME in a temp dir so it owns the lock and audit files.
Requires: no uictld running, /dev/uinput writable.

AA  with LISTEN_PID/LISTEN_FDS set and a listening socket on fd 3, the
    daemon serves on that fd -- it does not create one of its own.
AB  it says so on stderr, per WIRE.md 8.8.
AC  on shutdown the socket file is still there. This is the one that
    would break a user's session until they restarted the socket unit
    by hand.
AD  a socket file with group/world bits is refused, and the message
    names SocketMode.
AE  LISTEN_PID belonging to another process is ignored: the daemon
    binds its own socket, which is what an inherited environment must
    do rather than adopting a stranger's fd.
AF  fd 3 that is not a listening socket is refused rather than accepted
    on.
AG  Type=notify: READY=1 arrives on $NOTIFY_SOCKET, and it arrives
    AFTER the daemon can actually serve -- a readiness notification
    that outran the accept loop would make `systemctl --user start`
    return before the thing it started worked.
AH  STOPPING=1 on the way out, so a shutdown that pauses to release
    held keys reads as a clean stop rather than a stall.
AI  the shipped unit files parse, and uictld.socket sets SocketMode.
    Skipped where systemd-analyze is unavailable.
"""
import os, shutil, socket, stat, struct, subprocess, sys, tempfile, time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
RUNTIME = os.environ["XDG_RUNTIME_DIR"]
SOCK = os.path.join(RUNTIME, "uictld.sock")
HDR = "<HHIII"
HDR_SIZE = struct.calcsize(HDR)
OPCODE_PING = 1

ok = True


def fail(msg):
    global ok
    ok = False
    print("FAIL: " + msg)


def skip(msg):
    print("SKIP: " + msg)
    sys.exit(0)


def make_home():
    home = tempfile.mkdtemp(prefix="uictl-m6-")
    os.makedirs(os.path.join(home, ".config", "uictl"), mode=0o700)
    return home


def listener(path, mode=0o600):
    """Stand in for the .socket unit: create, bind, listen, chmod."""
    if os.path.exists(path):
        os.unlink(path)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(path)
    os.chmod(path, mode)
    s.listen(16)
    return s


def start_plain(home, extra_env=None):
    """Start uictld the ordinary way: it binds its own socket."""
    env = dict(os.environ, HOME=home)
    env.pop("LISTEN_PID", None)
    env.pop("LISTEN_FDS", None)
    if extra_env:
        env.update(extra_env)
    return subprocess.Popen([os.path.join(REPO, "uictld")], cwd=REPO,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, env=env)


def start_activated(sock, home, claim_pid=True):
    """Start uictld with `sock` as fd 3, the way systemd would.

    LISTEN_PID is set from inside the child (preexec_fn runs after fork,
    before exec) because it must name the daemon's own pid -- which is
    the point of the variable: an inherited environment must not
    convince some later process that fd 3 is its listening socket.
    """
    def child():
        os.dup2(sock.fileno(), 3)
        os.set_inheritable(3, True)
        os.environ["HOME"] = home
        os.environ["LISTEN_FDS"] = "1"
        os.environ["LISTEN_PID"] = str(os.getpid()) if claim_pid else "1"
    return subprocess.Popen([os.path.join(REPO, "uictld")], cwd=REPO,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, preexec_fn=child,
                            pass_fds=(sock.fileno(),))


def ping(path):
    c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    c.settimeout(5)
    c.connect(path)
    c.sendall(struct.pack(HDR, 1, OPCODE_PING, 1, 7, 0))
    head = c.recv(HDR_SIZE)
    _, _, _, seq, plen = struct.unpack(HDR, head)
    body = c.recv(plen)
    c.close()
    return seq, struct.unpack("<H", body[:2])[0]


def stop(p):
    if p.poll() is None:
        p.terminate()
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()
    return p.stdout.read(), p.stderr.read()


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
try:
    # --- AA/AB/AC: the happy path -------------------------------------
    srv = listener(SOCK)
    d = start_activated(srv, home)
    time.sleep(1.0)
    if d.poll() is not None:
        fail("AA: the daemon exited: %s" % d.stderr.read())
    else:
        try:
            seq, result = ping(SOCK)
            if seq != 7 or result != 0:
                fail("AA: ping over the inherited socket: seq=%d result=%d"
                     % (seq, result))
            else:
                print("AA the daemon serves on the fd it was handed")
        except OSError as e:
            fail("AA: could not reach the activated daemon: %s" % e)

    out, err = stop(d)
    d = None
    if "socket-activated" not in err:
        fail("AB: no socket-activation line on stderr (8.8 requires it):\n%s"
             % err)
    else:
        print("AB it reports being socket-activated:",
              [l for l in err.splitlines() if "socket-activated" in l][0][:88])

    if not os.path.exists(SOCK):
        fail("AC: the daemon unlinked a socket file it did not create. "
             "The socket unit is now listening on an unreachable inode "
             "and no service restart fixes it.")
    else:
        print("AC the socket file survives the daemon that served on it")

    # The listener is still ours, still valid: prove it by serving again
    # on the same fd, which is exactly what systemd does on the next
    # activation.
    d = start_activated(srv, home)
    time.sleep(1.0)
    if d.poll() is not None:
        fail("AC: a second activation on the same listener failed: %s"
             % d.stderr.read())
    else:
        try:
            _, result = ping(SOCK)
            print("AC   and a second activation on it works (result=%d)"
                  % result)
        except OSError as e:
            fail("AC: second activation unreachable: %s" % e)
    stop(d)
    d = None
    srv.close()
    srv = None

    # --- AD: a loose mode is refused ----------------------------------
    srv = listener(SOCK, mode=0o666)
    d = start_activated(srv, home)
    d.wait(timeout=5)
    err = d.stderr.read()
    if d.returncode == 0:
        fail("AD: the daemon served on a world-writable socket")
    elif "SocketMode" not in err:
        fail("AD: refused, but did not name the fix (SocketMode=0600):\n%s"
             % err)
    else:
        print("AD a 0666 socket is refused, and the message names "
              "SocketMode=0600")
    d = None
    srv.close()
    srv = None
    if os.path.exists(SOCK):
        os.unlink(SOCK)

    # --- AE: LISTEN_PID that is not ours ------------------------------
    # No listener at all: if the daemon honoured the stale variables it
    # would try to serve on fd 3, which here is a plain pipe. Binding its
    # own socket is the correct outcome.
    r, w = os.pipe()
    try:
        class FakeFd:
            def fileno(self_inner):
                return r
        d = start_activated(FakeFd(), home, claim_pid=False)
        time.sleep(1.0)
        if d.poll() is not None:
            fail("AE: the daemon exited instead of binding its own "
                 "socket: %s" % d.stderr.read())
        else:
            try:
                _, result = ping(SOCK)
                print("AE a LISTEN_PID naming another process is ignored; "
                      "the daemon bound its own socket (result=%d)" % result)
            except OSError as e:
                fail("AE: no socket of its own: %s" % e)
        stop(d)
        d = None
        if os.path.exists(SOCK):
            # it owns this one, so it must have removed it
            fail("AE: the daemon left behind a socket file it created")
        else:
            print("AE   and removed it on the way out, because it owned it")
    finally:
        os.close(r)
        os.close(w)

    # --- AF: fd 3 is not a socket -------------------------------------
    r, w = os.pipe()
    try:
        class FakeFd2:
            def fileno(self_inner):
                return r
        d = start_activated(FakeFd2(), home)
        d.wait(timeout=5)
        err = d.stderr.read()
        if d.returncode == 0:
            fail("AF: the daemon accepted on a pipe")
        elif "listening socket" not in err:
            fail("AF: refused, but not for the right reason:\n%s" % err)
        else:
            print("AF fd 3 that is not a listening socket is refused")
        d = None
    finally:
        os.close(r)
        os.close(w)

    # --- AG/AH: the readiness protocol --------------------------------
    # A datagram socket standing in for systemd's. The daemon has no way
    # to tell the difference, which is the point: the protocol is one
    # sendto() and testing it needs no supervisor.
    notify_path = os.path.join(home, "notify.sock")
    nsock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    nsock.bind(notify_path)
    nsock.settimeout(5)
    try:
        d = start_plain(home, {"NOTIFY_SOCKET": notify_path})
        try:
            msg = nsock.recv(256).decode()
        except socket.timeout:
            msg = ""
        if "READY=1" not in msg:
            fail("AG: no READY=1 on NOTIFY_SOCKET, got %r" % msg)
        else:
            # Ready must mean serviceable. If READY=1 were sent before
            # the accept loop, this connect would be the race that
            # Type=notify exists to remove.
            try:
                _, result = ping(SOCK)
                print("AG READY=1 arrives, and the daemon is already "
                      "serving when it does (result=%d)" % result)
            except OSError as e:
                fail("AG: READY=1 arrived before the daemon could serve: %s"
                     % e)

        stop(d)
        d = None
        try:
            msg2 = nsock.recv(256).decode()
        except socket.timeout:
            msg2 = ""
        if "STOPPING=1" not in msg2:
            fail("AH: no STOPPING=1 on shutdown, got %r" % msg2)
        else:
            print("AH STOPPING=1 on the way out")
    finally:
        nsock.close()
        if os.path.exists(notify_path):
            os.unlink(notify_path)

    # --- AI: the units we ship actually parse -------------------------
    if not shutil.which("systemd-analyze"):
        print("AI skipped: systemd-analyze is not installed")
    else:
        units = [os.path.join(REPO, "systemd", "uictld.socket"),
                 os.path.join(REPO, "systemd", "uictld.service")]
        v = subprocess.run(["systemd-analyze", "--user", "verify"] + units,
                           capture_output=True, text=True)
        sock_unit = open(units[0]).read()
        if v.returncode != 0:
            fail("AI: the shipped units do not verify:\n%s%s"
                 % (v.stdout, v.stderr))
        elif "SocketMode=0600" not in sock_unit:
            fail("AI: uictld.socket does not set SocketMode=0600. "
                 "systemd's default is 0666 -- a world-writable input "
                 "broker.")
        else:
            print("AI the shipped units verify, and the socket unit sets "
                  "SocketMode=0600")

finally:
    if d is not None:
        stop(d)
    if srv is not None:
        srv.close()
    if os.path.exists(SOCK):
        os.unlink(SOCK)
    shutil.rmtree(home, ignore_errors=True)

print("\n== PASS ==" if ok else "\n== FAIL ==")
sys.exit(0 if ok else 1)
