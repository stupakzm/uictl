#!/usr/bin/env python3
"""M3.5 task 7 verification: non-blocking writes / EPOLLOUT backpressure.

D  pipeline 1000 PINGs with a tiny SO_RCVBUF and don't read -> the daemon
   must stall mid-reply, park on EPOLLOUT, and deliver all 1000 replies
   once we start draining. (Old conn_flush killed the connection here.)
E  same, but never drain -> reaped as "response stalled" after ~5 s.
F  regression: a fatal frame (bad version) still gets its error reply.
G  regression: task 6 partial-frame reap + plain ping still work.
"""
import os, socket, struct, subprocess, sys, time

SOCK = os.path.join(os.environ["XDG_RUNTIME_DIR"], "uictld.sock")
AUDIT = os.path.expanduser("~/.local/state/uictl/audit.log")
PING = struct.pack("<HHIII", 1, 1, 1, 0, 0)   # version 1, OP_PING, no payload
N = 1000
ok = True


def conn(rcvbuf=None):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    if rcvbuf:                       # must be set before connect to stick
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
    s.connect(SOCK)
    return s


def fail(msg):
    global ok
    print("FAIL:", msg)
    ok = False


audit0 = open(AUDIT).read()

# --- D: backpressure, then drain -------------------------------------
d = conn(rcvbuf=2048)
d.sendall(PING * N)
time.sleep(1.5)                      # daemon fills our rcvbuf and stalls

got = b""
d.settimeout(10)
try:
    while len(got) < N * 18:
        chunk = d.recv(65536)
        if not chunk:
            break
        got += chunk
except socket.timeout:
    pass

if len(got) != N * 18:
    fail("D: got %d/%d reply bytes -- backpressure lost replies" % (len(got), N * 18))
else:
    results = {struct.unpack_from("<H", got, i * 18 + 16)[0] for i in range(N)}
    if results != {0}:
        fail("D: non-OK results in replies: %s" % results)
    else:
        print("D pipelined %d PINGs through an EPOLLOUT stall, all OK" % N)

# connection must still be usable after the stall cleared
d.sendall(PING)
d.settimeout(3)
try:
    if len(d.recv(18)) == 18:
        print("D connection still live after drain")
    else:
        fail("D: short reply after drain")
except socket.timeout:
    fail("D: connection dead after drain -- EPOLLIN never re-armed")
d.close()

# --- E: never drain -> reaped ----------------------------------------
e = conn(rcvbuf=2048)
e.sendall(PING * N)
t0 = time.monotonic()
e.settimeout(9)
try:
    while True:                      # consume nothing... except we must
        break                        # not read at all; just wait for EOF
except Exception:
    pass
time.sleep(7)
e.setblocking(False)
try:
    e.recv(1)                        # some data arrived before the stall
    reaped = True                    # a closed peer eventually gives b""
except BlockingIOError:
    reaped = False

# --- F: fatal frame still gets its reply -----------------------------
f = conn()
f.sendall(struct.pack("<HHIII", 99, 1, 1, 3, 0))   # bad version
f.settimeout(3)
try:
    r = f.recv(18)
    if len(r) == 18 and struct.unpack_from("<H", r, 16)[0] == 1:  # ERR_VERSION
        print("F fatal frame received ERR_VERSION before close")
    else:
        fail("F: unexpected fatal reply %r" % r)
except socket.timeout:
    fail("F: no error reply for fatal frame")
f.close()

# --- G: task 6 regression + liveness ---------------------------------
g = conn()
g.sendall(b"\x01\x00\x00")
g.settimeout(9)
t0 = time.monotonic()
try:
    while g.recv(64) != b"":
        pass
    print("G partial-frame conn reaped after %.1fs" % (time.monotonic() - t0))
except socket.timeout:
    fail("G: task 6 reaper regressed -- partial frame never reaped")

r = subprocess.run(["./uictl", "ping"], capture_output=True, text=True)
if r.returncode != 0 or "PONG" not in r.stdout:
    fail("G: CLI ping broken: %s %s" % (r.stdout, r.stderr))
else:
    print("G CLI ping still works:", r.stdout.strip())

new = open(AUDIT).read()[len(audit0):]
stalled = new.count("response stalled")
partial = new.count("partial frame timeout")
print("audit: 'response stalled' x%d, 'partial frame timeout' x%d" % (stalled, partial))
if stalled < 1:
    fail("E: non-reading peer was never reaped as 'response stalled'")
if partial < 1:
    fail("G: no partial-frame audit line")
e.close()

print("\n== PASS ==" if ok else "\n== FAIL ==")
sys.exit(0 if ok else 1)
