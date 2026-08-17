#!/usr/bin/env python3
"""WIRE.md 8.7: the connection-attempt backstop.

MAX_CONNS_PER_PID bounds how many connections a pid holds AT ONCE. It
says nothing about how fast a pid may open and close them, and under
socket activation that is the gap that matters: connect() succeeds
whether or not a daemon is running, so a client whose reconnect loop has
no backoff spins as fast as the scheduler allows, and every individual
attempt is within every other limit the daemon has.

8.6's advertised advice cannot close that gap -- it is read by the
client, in the client's process, at the moment the daemon is least able
to influence anything. This is the enforcing half, and the only rule in
8 that survives a client that ignores everything else. So it is the one
that has to be tested against a client that ignores everything else.

Runs its own daemon with HOME in a temp dir. Requires no uictld running.
Injects nothing -- it never gets as far as an opcode -- but grabs the
nodes anyway, because run_all.check_grabs is a static scan and an
exemption is a hole in it.

CA  a pid that opens connections in a tight loop is refused with
    ERR_BUSY once it passes the window budget, and the refusal is a
    frame, not a silent close: a client that gets EOF cannot tell a
    storm refusal from a crashed daemon, and would retry either way.
CB  ERR_BUSY, never ERR_DENIED_BY_POLICY. The storm is transient by
    definition and the client should come back later; a terminal code
    would tell a legitimate-but-buggy client to give up forever.
CC  the refusal is audited, naming the peer pid.
CD  it is per pid: while one pid is locked out, a different pid connects
    normally. A backstop that bounded the daemon globally would let one
    broken client deny service to every other.
CE  the window slides -- the same pid is admitted again once its window
    expires. This is a backstop, not a ban, and nothing ever clears a
    ban.
"""
import os, re, select, shutil, socket, struct, subprocess, sys, tempfile, time
import multiprocessing as mp
import uictl_expect

SOCK = os.path.join(os.environ["XDG_RUNTIME_DIR"], "uictld.sock")
HDR = "<HHIII"
OK, ERR_DENIED_BY_POLICY, ERR_BUSY = 0, 4, 7
# Must match uictld.c.
WINDOW_SEC = 10
PER_WINDOW = 60
ok = True


def fail(msg):
    global ok
    print("FAIL:", msg)
    ok = False


def attempt():
    """One connect. Returns the result code if the daemon refused us at
    admission, OK if it stayed open, None if the socket is gone."""
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect(SOCK)
    except OSError:
        return None
    try:
        # Poll, do not peek. A non-blocking recv() straight after
        # connect() races the daemon: connect() returns as soon as the
        # kernel completes the handshake, which is BEFORE the daemon has
        # accepted, decided, and written the refusal. A bare recv()
        # therefore reports "admitted" for every refusal, which is
        # exactly what this suite was written to catch -- and it caught
        # it here first, in its own client.
        # 50 ms, and the size of it matters in both directions. Too
        # short and an admitted connection is indistinguishable from a
        # refused one the daemon has not answered yet. Too long and the
        # storm cannot outrun its own window: at 250 ms, 85 attempts take
        # 21 s against a 10 s window, the window resets mid-storm, the
        # budget is never spent and the suite reports no backstop at all.
        # 50 ms is ~1000x the daemon's actual response time and keeps the
        # whole storm inside 5 s.
        if not select.select([s], [], [], 0.05)[0]:
            return OK           # nothing was pushed at us: admitted
        r = s.recv(18)
        if len(r) < 18:
            return None         # closed with no frame
        return struct.unpack_from("<H", r, 16)[0]
    finally:
        s.close()


def storm(n):
    """n attempts as fast as possible. Returns (admitted, refused_codes)."""
    admitted, refused = 0, []
    for _ in range(n):
        r = attempt()
        if r == OK:
            admitted += 1
        elif r is not None:
            refused.append(r)
    return admitted, refused


def child_storm(q):
    """Storm from a separate pid, then prove the window slides for it."""
    admitted, refused = storm(PER_WINDOW + 25)
    q.put(("storm", admitted, refused[:3], os.getpid()))
    # CE: same pid, after the window. The lockout must lift on its own.
    time.sleep(WINDOW_SEC + 1.5)
    q.put(("after", attempt(), [], os.getpid()))


home = tempfile.mkdtemp(prefix="uictl-storm-")
os.makedirs(os.path.join(home, ".config", "uictl"))
os.makedirs(os.path.join(home, ".local", "state"))
audit_path = os.path.join(home, ".local", "state", "uictl", "audit.log")

if os.path.exists(SOCK):
    try:
        socket.socket(socket.AF_UNIX, socket.SOCK_STREAM).connect(SOCK)
        print("SKIP: a uictld is already running; stop it and re-run")
        sys.exit(0)
    except OSError:
        pass

d = None
grabs = []
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

    # The storm runs in a child so this process keeps a clean budget for
    # CD -- which is the whole point of CD, and would be untestable from
    # inside the storming pid.
    q = mp.Queue()
    p = mp.Process(target=child_storm, args=(q,))
    p.start()

    tag, admitted, refused, child_pid = q.get(timeout=60)
    assert tag == "storm"

    # --- CA -----------------------------------------------------------
    if not refused:
        fail("CA: %d attempts in a tight loop and none was refused -- the "
             "window budget is %d" % (admitted, PER_WINDOW))
    elif admitted > PER_WINDOW:
        fail("CA: %d attempts admitted, budget is %d" % (admitted, PER_WINDOW))
    else:
        print("CA storm: %d admitted then refused (budget %d)"
              % (admitted, PER_WINDOW))

    # --- CB -----------------------------------------------------------
    if refused and set(refused) != {ERR_BUSY}:
        if ERR_DENIED_BY_POLICY in refused:
            fail("CB: storm refused with ERR_DENIED_BY_POLICY (terminal) -- "
                 "a storm is transient, the client should come back later")
        else:
            fail("CB: storm refused with %s, expected ERR_BUSY(%d)"
                 % (set(refused), ERR_BUSY))
    elif refused:
        print("CB refusal is ERR_BUSY (retryable), not terminal")

    # --- CD: a different pid is unaffected -----------------------------
    # This process has made no connections yet, so its window is empty
    # even though the child just exhausted its own.
    mine = attempt()
    if mine != OK:
        fail("CD: an innocent pid got %s while another pid was storming -- "
             "one broken client must not deny service to the rest" % mine)
    else:
        print("CD a different pid is admitted while the storming one is not")

    # --- CC: audited ---------------------------------------------------
    audit = open(audit_path).read() if os.path.exists(audit_path) else ""
    storm_lines = [l for l in audit.splitlines()
                   if "connection-attempt storm" in l]
    if not storm_lines:
        fail("CC: the storm refusals were not audited")
    elif not any("pid=%d" % child_pid in l for l in storm_lines):
        fail("CC: storm audit lines do not name the peer pid %d" % child_pid)
    elif not all("result=%d" % ERR_BUSY in l for l in storm_lines):
        fail("CC: a storm audit line does not record result=ERR_BUSY")
    else:
        print("CC audited: %d storm lines, peer pid named, result=ERR_BUSY"
              % len(storm_lines))

    # --- CE: the window slides ------------------------------------------
    tag, after, _, _ = q.get(timeout=60)
    assert tag == "after"
    if after != OK:
        fail("CE: the storming pid was still refused (%s) after its window "
             "expired -- this is a backstop, not a ban, and nothing in the "
             "daemon ever lifts a ban" % after)
    else:
        print("CE the same pid is admitted again once its window expires")
    p.join(timeout=10)

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
