#!/usr/bin/env python3
"""M3.7 tasks 1-3: admission control + fairness (gaps G6, G7, G8).

A  fairness (G6): one client pipelines a large burst while another sends
   single pings. Every ping must come back inside FAIR_BUDGET_MS. Without
   the per-wakeup frame budget the burst is drained to EAGAIN in one
   epoll turn and the second client waits for all of it.
B  per-pid cap (G7): MAX_CONNS_PER_PID connections from one pid succeed,
   the next is refused with ERR_BUSY -- and a *different* pid is still
   admitted while the first is at its cap.
C  error semantics (G8): the refusal above is ERR_BUSY (retryable), not
   ERR_DENIED_BY_POLICY (terminal), and it is audited.
D  regression: the one-shot CLI path is untouched by the budget.
"""
import os, socket, struct, subprocess, sys, time
import multiprocessing as mp

SOCK = os.path.join(os.environ["XDG_RUNTIME_DIR"], "uictld.sock")
AUDIT = os.path.expanduser("~/.local/state/uictl/audit.log")
HDR = "<HHIII"

OK, ERR_DENIED_BY_POLICY, ERR_BUSY = 0, 4, 7
MAX_CONNS_PER_PID = 4          # must match uictld.c
BURST = 2000                   # frames the hog pipelines in one write()
FAIR_BUDGET_MS = 50            # muvor's stated end-to-end budget
# The trip wire is deliberately far tighter than the 50 ms product
# budget. The backlog one connection can present is capped by the
# receive queue (~9.5k frames here), and an un-budgeted daemon chews
# through that in ~18 ms on this machine -- under 50 ms, so a 50 ms
# assertion would pass against the very bug this test exists to catch.
# With the budget the same run costs a fraction of a millisecond.
STARVE_LIMIT_MS = 5
ok = True


def fail(msg):
    global ok
    print("FAIL:", msg)
    ok = False


def ping(seq):
    return struct.pack(HDR, 1, 1, 1, seq, 0)


def hello(seq=0, name=b"hog"):
    """Since M3.6 task 7 an un-handshaked MOVE_ABS is refused before it
    reaches the device, which would make the frames below cost an audit
    write and nothing else -- a much lighter unit of work than the one
    this test is supposed to be measuring."""
    body = struct.pack("<HH", 1, 1) + name + b"\x00" * (32 - len(name))
    return struct.pack(HDR, 1, 3, 1, seq, len(body)) + body


def move(seq, x, y):
    """MOVE_ABS costs a uinput write *and* an audit write -- a heavier
    unit of work than PING, which is what makes the starvation visible."""
    return struct.pack(HDR, 1, 2, 1, seq, 8) + struct.pack("<ii", x, y)


def conn():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(SOCK)
    return s


audit0 = open(AUDIT).read()

# --- A: fairness under a sustained pipeline ---------------------------
# A single burst is not enough to show anything: the daemon drains 2000
# frames in well under a millisecond, so it is idle again before the
# other client even asks. The hog must keep a backlog *present* -- it
# runs as its own process, writing BURST-frame blobs in a loop (one
# write() syscall for it, BURST frames of work for the daemon) and
# draining its replies so this stays a G6 read-side test and does not
# turn into the M3.5 EPOLLOUT stall, which would yield the loop anyway
# and mask exactly what we are measuring.
def hog_proc(ready, go, queued):
    """Present the deepest single-connection backlog the kernel allows,
    with the reply path deliberately *kept clear*.

    Draining the replies is what makes this a test of G6 rather than of
    M3.5 task 7. A hog that stops reading looks like the harsher client,
    but it isn't: unix-socket buffer accounting charges each 18-byte
    reply its whole skb overhead, so a non-reading peer pushes the daemon
    onto EPOLLOUT after only a few hundred replies -- and EPOLLOUT drops
    EPOLLIN, which yields the loop and hides the starvation entirely.
    Reading promptly keeps the write side unblocked, leaving exactly the
    G6 case: thousands of complete frames parked in the daemon's receive
    queue with nothing to stop it dispatching every one of them before it
    looks at anybody else."""
    blob = b"".join(move(i, i % 32768, i % 32768) for i in range(BURST))
    s = conn()
    s.sendall(hello())
    # Drain the whole handshake reply, not a fixed 18 bytes: the HELLO
    # response carries the 24-byte capability payload, and leaving those
    # bytes in the buffer would throw off the reply accounting below.
    h = s.recv(16)
    plen = struct.unpack(HDR, h)[4]
    body = b""
    while len(body) < plen:
        body += s.recv(plen - len(body))
    s.setblocking(False)
    ready.set()
    go.wait(10)
    sent = 0
    while True:                        # one shot: fill the receive queue
        try:
            n = s.send(blob)
        except (BlockingIOError, OSError):
            break
        if n == 0:
            break
        sent += n
    queued.value = sent // 24

    got = 0
    s.setblocking(True)
    s.settimeout(15)
    try:
        while got < (sent // 24) * 18:
            c = s.recv(1 << 20)
            if not c:
                break
            got += len(c)
    except OSError:
        pass
    if got != (sent // 24) * 18:
        queued.value = -1              # replies lost: budget dropped frames
    s.close()


ready, go = mp.Event(), mp.Event()
queued = mp.Value("i", 0)
hproc = mp.Process(target=hog_proc, args=(ready, go, queued))
hproc.start()
ready.wait(10)

victim = conn()
victim.settimeout(10)
worst, samples = 0.0, []
go.set()                               # burst starts now; ping through it
for seq in range(1, 201):
    t0 = time.monotonic()
    victim.sendall(ping(seq))
    r = victim.recv(18)
    dt = (time.monotonic() - t0) * 1000.0
    samples.append(dt)
    worst = max(worst, dt)
    if len(r) != 18:
        fail("A: short reply (len=%d)" % len(r))
        break
    if struct.unpack(HDR, r[:16])[3] != seq:
        fail("A: seq mismatch")
        break
    time.sleep(0.002)

hproc.join(10)
if hproc.is_alive():
    hproc.terminate()
victim.close()

samples.sort()
print("A %d frames queued by one peer; victim round-trip: median %.1f ms, "
      "p95 %.1f ms, worst %.1f ms" %
      (queued.value, samples[len(samples) // 2],
       samples[int(len(samples) * 0.95)], worst))
if queued.value < 0:
    fail("A: hog did not get every reply -- the budget dropped frames")
elif queued.value < 2000:
    fail("A: only %d frames queued -- backlog too shallow to prove anything"
         % queued.value)
if worst > STARVE_LIMIT_MS:
    fail("A: worst %.1f ms > %d ms -- one connection owned the loop" %
         (worst, STARVE_LIMIT_MS))

# --- B/C: per-pid cap, and what the refusal says ----------------------
held = []
for i in range(MAX_CONNS_PER_PID):
    try:
        held.append(conn())
    except OSError as e:
        fail("B: connection %d/%d refused: %s" % (i + 1, MAX_CONNS_PER_PID, e))

over = conn()                      # one past the cap
over.settimeout(3)
try:
    r = over.recv(18)
except socket.timeout:
    r = b""
if len(r) != 18:
    fail("B: over-cap connection got no refusal frame (len=%d)" % len(r))
else:
    res = struct.unpack_from("<H", r, 16)[0]
    if res == ERR_BUSY:
        print("B connection %d from one pid refused with ERR_BUSY" %
              (MAX_CONNS_PER_PID + 1))
    elif res == ERR_DENIED_BY_POLICY:
        fail("C: refusal is ERR_DENIED_BY_POLICY (terminal); "
             "a transient full table must be ERR_BUSY")
    else:
        fail("B: unexpected result=%d" % res)
over.close()

# a different pid must still get in while this one is capped
r = subprocess.run(["./uictl", "ping"], capture_output=True, text=True)
if r.returncode != 0 or "PONG" not in r.stdout:
    fail("B: cap is not per-pid -- another process was refused: %s %s" %
         (r.stdout.strip(), r.stderr.strip()))
else:
    print("B another pid still admitted while the first is at its cap")

for s in held:
    s.close()
time.sleep(0.3)                    # let the daemon reap the closed slots

# freeing them must free the cap
try:
    s = conn()
    s.settimeout(1)
    s.sendall(ping(7))
    if len(s.recv(18)) == 18:
        print("B cap released once the connections closed")
    else:
        fail("B: cap not released after close")
    s.close()
except OSError as e:
    fail("B: cap not released after close: %s" % e)

# --- D: one-shot CLI regression ---------------------------------------
r = subprocess.run(["./uictl", "move-abs", "300", "400"],
                   capture_output=True, text=True)
if r.returncode != 0 or "OK" not in r.stdout:
    fail("D: CLI move-abs broken: %s %s" % (r.stdout.strip(), r.stderr.strip()))
else:
    print("D CLI one-shot path unchanged:", r.stdout.strip())

new = open(AUDIT).read()[len(audit0):]
capped = new.count("per-pid conn cap")
print("audit: 'per-pid conn cap' x%d" % capped)
if capped < 1:
    fail("C: the per-pid refusal was not audited")

print("\n== PASS ==" if ok else "\n== FAIL ==")
sys.exit(0 if ok else 1)
