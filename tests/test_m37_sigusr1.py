#!/usr/bin/env python3
"""M3.7 task 4: SIGUSR1 dumps the connection table (gap G10).

Unlike the other suites this one *starts its own daemon*, because the
dump goes to stderr and there is no other way to read it. It therefore
requires that no uictld is already running -- the flock singleton would
refuse the second one anyway.

H  SIGUSR1 does not kill the daemon (its default disposition is
   terminate, so this only works if it is blocked *and* on the signalfd
   mask) and the daemon still serves afterwards.
I  the dump reports one line per live connection, with the phase each is
   actually in: idle, mid-header, and mid-payload.
J  frames served is counted per connection.
K  the dump leaks no payload content -- metadata only.
"""
import os, re, signal, socket, struct, subprocess, sys, time

SOCK = os.path.join(os.environ["XDG_RUNTIME_DIR"], "uictld.sock")
HDR = "<HHIII"
ok = True


def fail(msg):
    global ok
    print("FAIL:", msg)
    ok = False


def ping(seq):
    return struct.pack(HDR, 1, 1, 1, seq, 0)


def conn():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(SOCK)
    return s


if os.path.exists(SOCK):
    try:
        conn().close()
        print("SKIP: a uictld is already running; stop it and re-run")
        sys.exit(0)
    except OSError:
        pass                            # stale socket, the daemon will clear it

d = subprocess.Popen(["./uictld"], stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE, text=True)
time.sleep(0.7)
if d.poll() is not None:
    print("SKIP: daemon would not start:", d.stderr.read())
    sys.exit(0)

# three connections, each parked in a different observable state
idle = conn()                           # connected, no frame in progress
busy = conn()                           # served some frames, then idle
mid_hdr = conn()                        # 3 bytes of a 16-byte header
mid_pay = conn()                        # header complete, payload missing

for seq in range(1, 6):
    busy.sendall(ping(seq))
    busy.recv(18)
mid_hdr.sendall(b"\x01\x00\x00")
mid_pay.sendall(struct.pack(HDR, 1, 2, 1, 9, 8) + b"\x00\x00")  # 2 of 8 bytes
time.sleep(0.3)

d.send_signal(signal.SIGUSR1)
time.sleep(0.5)

# H: still alive and still serving
if d.poll() is not None:
    fail("H: SIGUSR1 killed the daemon (rc=%s) -- not blocked before "
         "signalfd, so the default disposition ran" % d.returncode)
    print("\n== FAIL ==")
    sys.exit(1)

r = subprocess.run(["./uictl", "ping"], capture_output=True, text=True)
if r.returncode != 0 or "PONG" not in r.stdout:
    fail("H: daemon stopped serving after SIGUSR1")
else:
    print("H daemon survived SIGUSR1 and still serves")

# stop the daemon so its stderr closes and we can read the dump
d.send_signal(signal.SIGTERM)
try:
    d.wait(timeout=5)
except subprocess.TimeoutExpired:
    d.kill()
    fail("H: daemon did not exit on SIGTERM after SIGUSR1")
err = d.stderr.read()
for s in (idle, busy, mid_hdr, mid_pay):
    s.close()

print("--- daemon stderr ---")
print(err.strip())
print("---------------------")

lines = [l for l in err.splitlines() if l.startswith("  slot=")]
header = [l for l in err.splitlines() if "slots used" in l]

# I: one line per live connection, phases distinguished
if not header:
    fail("I: no 'slots used' header in the dump")
elif "4/32" not in header[0]:
    fail("I: header says %r, expected 4 of 32 slots used" % header[0].strip())
else:
    print("I", header[0].strip())

if len(lines) != 4:
    fail("I: %d connection lines, expected 4" % len(lines))
else:
    phases = sorted(re.search(r"phase=(\w+)", l).group(1) for l in lines)
    if phases != ["hdr", "idle", "idle", "payload"]:
        fail("I: phases %s -- expected two idle, one hdr, one payload" % phases)
    else:
        print("I dump distinguished idle / mid-header / mid-payload")

# J: per-connection frame counter
counts = sorted(int(re.search(r"frames=(\d+)", l).group(1)) for l in lines)
if counts != [0, 0, 0, 5]:
    fail("J: frames served %s -- expected one connection at 5, rest at 0"
         % counts)
else:
    print("J frames-served counted per connection:", counts)

# K: metadata only
for bad in ("payload=", "buf=", "x=", "0x00"):
    if bad in err:
        fail("K: dump appears to contain frame content (%r)" % bad)
if ok:
    print("K dump is metadata only")

print("\n== PASS ==" if ok else "\n== FAIL ==")
sys.exit(0 if ok else 1)
