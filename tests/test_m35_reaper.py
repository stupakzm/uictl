#!/usr/bin/env python3
"""M3.5 task 6 verification: partial-frame reaper.

Case A: half a header, then silence -> closed in 5-6 s.
Case B: full header (MOVE_ABS, payload_len=8), no payload -> closed too.
Case C: idle connection, no frame started -> still alive after 8 s.
Concurrently: ./uictl ping must keep working throughout.
"""
import os, socket, struct, subprocess, sys, time

SOCK = os.path.join(os.environ["XDG_RUNTIME_DIR"], "uictld.sock")
AUDIT = os.path.expanduser("~/.local/state/uictl/audit.log")


def conn():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(SOCK)
    return s


def closed_after(s, limit):
    """Seconds until the peer closes, or None."""
    t0 = time.monotonic()
    s.settimeout(limit)
    try:
        while True:
            if s.recv(64) == b"":
                return time.monotonic() - t0
    except socket.timeout:
        return None


audit0 = open(AUDIT).read().count("partial frame timeout")

a = conn()
a.sendall(b"\x01\x00\x00")                                   # 3 bytes of header

b = conn()
b.sendall(struct.pack("<HHIII", 1, 2, 1, 7, 8))              # header, no payload

c = conn()                                                    # never says anything

t0 = time.monotonic()
ok = True

# liveness: a one-shot CLI ping must succeed while the reaper is armed
for _ in range(3):
    r = subprocess.run(["./uictl", "ping"], capture_output=True, text=True)
    if r.returncode != 0:
        print("FAIL: ping broke during reap window:", r.stderr.strip())
        ok = False
    time.sleep(1)

ta = closed_after(a, 8)
tb = closed_after(b, 3)

print("A (partial header)  closed after %.1fs" % ta if ta else "A: NOT CLOSED")
print("B (header, no body) closed after %.1fs" % (tb + (time.monotonic() - t0 - tb))
      if tb is not None else "B: NOT CLOSED")

for name, t in (("A", ta), ("B", tb)):
    if t is None:
        print("FAIL: %s was never reaped" % name)
        ok = False

# C must survive: it never started a frame
if closed_after(c, 3) is not None:
    print("FAIL: idle connection C was reaped -- long-lived clients broken")
    ok = False
else:
    print("C (idle, no frame)  still open  <- correct")

r = subprocess.run(["./uictl", "ping"], capture_output=True, text=True)
if r.returncode != 0:
    print("FAIL: ping broke after reaping:", r.stderr.strip())
    ok = False
else:
    print("ping after reap:", r.stdout.strip())

audit1 = open(AUDIT).read().count("partial frame timeout")
print("audit 'partial frame timeout' lines: +%d (expect +2)" % (audit1 - audit0))
if audit1 - audit0 != 2:
    ok = False

c.close()
print("\n== PASS ==" if ok else "\n== FAIL ==")
sys.exit(0 if ok else 1)
