#!/usr/bin/env python3
"""M4 step 10: per-pid token bucket, sized by the daemon-derived class.

Runs its own daemon with HOME in a temp dir so it owns both config files
(the client registry that assigns classes, and the key policy). Requires
no uictld running.

AF  the default class gets the floor rate: a burst of 10 from an
    unregistered client yields 5 OK then ERR_RATE_LIMITED.
AG  the bucket refills over time, at roughly the class rate.
AH  a registered `interactive` client gets the high rate on the same
    workload -- the class, not the client's own say-so, sets the limit.
AI  **the budget is per pid, not per connection.** Two connections from
    one process share one bucket; otherwise the limit is multiplied by
    MAX_CONNS_PER_PID and is not a limit.
AJ  **reconnecting does not reset the budget.** Otherwise "close and
    reopen the socket" is a trivial bypass.
AK  PING and HELLO are free -- a throttled client must still be able to
    ask what is wrong.
AL  a KEY_SEQUENCE costs one unit per PRESS, so a 3-key combo cannot
    smuggle three keystrokes through a one-unit charge.
AM  source_tag cannot buy a better rate (G2, restated where it matters).
AN  **the daemon-wide backstop.** A per-pid bucket alone is bypassable by
    forking: a new process is a new pid is a fresh budget, which the CLI
    does by accident on every invocation. Several processes, each inside
    its own class limit, must still be capped in aggregate.
"""
import os, re, shutil, signal, socket, struct, subprocess, sys, tempfile, time
import multiprocessing as mp

SOCK = os.path.join(os.environ["XDG_RUNTIME_DIR"], "uictld.sock")
HDR = "<HHIII"
OP_PING, OP_MOVE_ABS, OP_HELLO, OP_KEY_TAP, OP_KEY_SEQUENCE = 1, 2, 3, 4, 5
OK, ERR_RATE_LIMITED = 0, 11
SRC_CLI, SRC_LLM = 1 << 0, 1 << 2
F13, F14, F15 = 183, 184, 185
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


def hello(s, name=b"probe", seq=1, src=SRC_CLI):
    body = struct.pack("<HH", 1, 1) + name + b"\x00" * (32 - len(name))
    s.sendall(struct.pack(HDR, 1, OP_HELLO, 1, seq, len(body)) + body)
    return reply(s)


def move(s, seq, src=SRC_CLI):
    s.sendall(struct.pack(HDR, 1, OP_MOVE_ABS, src, seq, 8) +
              struct.pack("<ii", 100, 100))
    return reply(s)


def ping(s, seq):
    s.sendall(struct.pack(HDR, 1, OP_PING, 1, seq, 0))
    return reply(s)


def combo(s, seq, codes):
    items = [(c, 1) for c in codes] + [(c, 0) for c in reversed(codes)]
    pay = struct.pack("<HH", len(items), 0) + b"".join(
        struct.pack("<HBB", c, v, 0) for c, v in items)
    s.sendall(struct.pack(HDR, 1, OP_KEY_SEQUENCE, 1, seq, len(pay)) + pay)
    return reply(s)


def burst(s, n, start=2, src=SRC_CLI):
    return [move(s, start + i, src) for i in range(n)]


def start_daemon(home, registry=None):
    cfg = os.path.join(home, ".config", "uictl")
    os.makedirs(cfg, exist_ok=True)
    os.makedirs(os.path.join(home, ".local", "state"), exist_ok=True)
    with open(os.path.join(cfg, "policy"), "w") as f:
        f.write("183-185\n")            # F13-F15, unbound everywhere
    os.chmod(os.path.join(cfg, "policy"), 0o600)
    reg = os.path.join(cfg, "clients")
    if registry:
        with open(reg, "w") as f:
            f.write(registry)
        os.chmod(reg, 0o600)
    elif os.path.exists(reg):
        os.unlink(reg)
    d = subprocess.Popen(["./uictld"], env=dict(os.environ, HOME=home),
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         text=True)
    time.sleep(0.8)
    return d


def stop(d):
    d.send_signal(signal.SIGTERM)
    try:
        d.wait(timeout=5)
    except subprocess.TimeoutExpired:
        d.kill()
    return d.stderr.read()


if os.path.exists(SOCK):
    try:
        conn().close()
        print("SKIP: a uictld is already running; stop it and re-run")
        sys.exit(0)
    except OSError:
        pass

home = tempfile.mkdtemp(prefix="uictl-rate-")
d = None
try:
    d = start_daemon(home, registry="fastclient   interactive\n"
                                    "stranger     untrusted\n")
    if d.poll() is not None:
        print("SKIP: daemon would not start:", d.stderr.read())
        sys.exit(0)

    # --- AF: the floor ------------------------------------------------
    a = conn()
    hello(a, b"stranger")
    res = burst(a, 10)
    allowed = res.count(OK)
    limited = res.count(ERR_RATE_LIMITED)
    if allowed != 5 or limited != 5:
        fail("AF: unregistered client got %d OK / %d limited, expected 5/5"
             % (allowed, limited))
    else:
        print("AF untrusted class: 5 allowed then ERR_RATE_LIMITED")

    # --- AK: probes stay free while throttled -------------------------
    if ping(a, 100) != OK:
        fail("AK: PING was refused while the bucket was empty -- a throttled "
             "client must still be able to check the daemon is alive")
    b2 = conn()
    if hello(b2, b"stranger") != OK:
        fail("AK: HELLO was refused while the bucket was empty")
    else:
        print("AK PING and HELLO stay free under throttling")

    # --- AI: one bucket per pid, shared across connections -------------
    shared = burst(b2, 3, start=200)
    if OK in shared:
        fail("AI: a second connection from the same pid got fresh budget "
             "(%s) -- the limit is per pid, or it is not a limit" % shared)
    else:
        print("AI a second connection from the same pid shares the bucket")
    a.close()
    b2.close()

    # --- AJ: reconnecting does not reset ------------------------------
    c = conn()
    hello(c, b"stranger")
    again = burst(c, 3, start=300)
    if OK in again:
        fail("AJ: reconnecting refilled the bucket (%s) -- close/reopen "
             "would be a free bypass" % again)
    else:
        print("AJ reconnecting does not reset the budget")

    # --- AG: it refills -----------------------------------------------
    time.sleep(1.1)
    refilled = burst(c, 6, start=400)
    if refilled.count(OK) < 4 or refilled.count(OK) > 6:
        fail("AG: after 1.1 s the bucket yielded %d requests, expected ~5"
             % refilled.count(OK))
    else:
        print("AG bucket refilled to ~%d after 1.1 s" % refilled.count(OK))

    # --- AM: source_tag buys nothing ----------------------------------
    time.sleep(1.1)
    lying = burst(c, 8, start=500, src=SRC_LLM)
    if lying.count(OK) > 6:
        fail("AM: source_tag changed the rate (%d allowed)" % lying.count(OK))
    else:
        print("AM source_tag does not change the rate (G2)")
    c.close()

    # --- AL: a sequence costs one per press ---------------------------
    time.sleep(1.5)
    e = conn()
    hello(e, b"stranger")
    first = combo(e, 2, [F13, F14, F15])     # 3 presses -> 3 units
    second = combo(e, 3, [F13, F14, F15])    # only 2 units left
    if first != OK:
        fail("AL: the first 3-key combo was refused (%s)" % first)
    elif second != ERR_RATE_LIMITED:
        fail("AL: a second 3-key combo got %s -- a sequence must cost one "
             "unit per press, or it is a way around the limit" % second)
    else:
        print("AL a 3-key combo costs 3 units, not 1")
    e.close()

    # --- AN: many pids, each within its class, capped in aggregate ----
    def hammer(n, out):
        """One child = one pid = its own per-pid bucket."""
        s = conn()
        hello(s, b"fastclient")
        got = [move(s, 2 + i) for i in range(n)]
        out.put(got.count(ERR_RATE_LIMITED))
        s.close()

    time.sleep(1.5)
    q = mp.Queue()
    kids = [mp.Process(target=hammer, args=(60, q)) for _ in range(5)]
    for k in kids:
        k.start()
    for k in kids:
        k.join(20)
    trips = sum(q.get() for _ in kids)
    if trips == 0:
        fail("AN: 5 processes x 60 requests (300, well over the 200/s "
             "ceiling) were all allowed -- forking bypasses the limit "
             "entirely")
    else:
        print("AN 5 separate pids hit the daemon-wide ceiling %d times "
              "(per-pid buckets alone would not have)" % trips)

    err = stop(d)
    d = None
    audit = open(os.path.join(home, ".local", "state", "uictl",
                              "audit.log")).read()
    if not [l for l in audit.splitlines() if "daemon-wide" in l]:
        fail("AN: the daemon-wide trips were not audited as such -- a client "
             "cannot tell 'my class is full' from 'the daemon is saturated'")
    trips = [l for l in audit.splitlines() if "rate limited" in l]
    if not trips:
        fail("no rate-limit trip was audited")
    elif "class=untrusted" not in trips[0] or "5/s" not in trips[0]:
        fail("the audit line does not record the class and rate: %s" % trips[0])
    else:
        print("-- audited:", trips[0].split("args=")[1].strip())

    # --- AH: a registered class gets the higher rate ------------------
    d = start_daemon(home, registry="fastclient   interactive\n")
    if d.poll() is not None:
        fail("AH: daemon would not restart")
    else:
        f = conn()
        if hello(f, b"fastclient") != OK:
            fail("AH: handshake failed")
        fast = burst(f, 30)
        if fast.count(OK) < 25:
            fail("AH: an 'interactive' client got only %d of 30 through -- "
                 "the class did not raise the limit" % fast.count(OK))
        else:
            print("AH interactive class: %d/30 allowed on the same workload"
                  % fast.count(OK))
        f.close()
        stop(d)
        d = None
finally:
    if d is not None:
        stop(d)
    shutil.rmtree(home, ignore_errors=True)

print("\n== PASS ==" if ok else "\n== FAIL ==")
sys.exit(0 if ok else 1)
