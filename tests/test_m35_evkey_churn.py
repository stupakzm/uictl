#!/usr/bin/env python3
"""Event-key aliasing regression: hammer close/accept churn so the kernel
recycles fd numbers aggressively while other connections stay live and
busy. Under the old data.fd keying, a stale event resolved to whatever
new connection inherited the number.

Long-lived connections must not be disturbed: every reply they get must
match the seq they sent, and none may be closed under them.

Churn workers run as separate *processes*, not threads: since M3.7 task 2
the daemon caps concurrent connections per peer pid (MAX_CONNS_PER_PID),
and 3 steady + 4 churning connections from one pid would be refused with
ERR_BUSY. Each churn process holds one connection at a time; the main
process holds the 3 steady ones.
"""
import os, socket, struct, sys, threading, time
import multiprocessing as mp

SOCK = os.path.join(os.environ["XDG_RUNTIME_DIR"], "uictld.sock")
HDR = "<HHIII"
ok = True
lock = threading.Lock()


def fail(msg):
    global ok
    with lock:
        print("FAIL:", msg)
        ok = False


def ping(seq):
    return struct.pack(HDR, 1, 1, 1, seq, 0)


def churn(stop, tag):
    """Open/close as fast as possible; mix clean closes, abrupt RSTs and
    partial frames so connections die through every code path."""
    n = 0
    while not stop.is_set():
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.connect(SOCK)
            mode = n % 3
            if mode == 0:
                s.sendall(ping(n))
                s.recv(18)
                s.close()                       # clean EOF
            elif mode == 1:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                             struct.pack("ii", 1, 0))
                s.sendall(ping(n))
                s.close()                       # RST -> EPOLLHUP/ERR
            else:
                s.sendall(b"\x01\x00")          # partial frame, then vanish
                s.close()
            n += 1
        except OSError:
            pass
    return n


def steady(stop, idx):
    """A long-lived client doing request/response the whole time."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(SOCK)
    s.settimeout(5)
    seq = 0
    try:
        while not stop.is_set():
            seq += 1
            s.sendall(ping(seq))
            r = s.recv(18)
            if len(r) != 18:
                fail("steady%d: short/EOF reply at seq=%d (len=%d)" % (idx, seq, len(r)))
                return
            v, op, src, gseq, plen = struct.unpack(HDR, r[:16])
            res = struct.unpack_from("<H", r, 16)[0]
            if gseq != seq:
                fail("steady%d: seq mismatch sent=%d got=%d -- ALIASED" % (idx, seq, gseq))
                return
            if res != 0:
                fail("steady%d: result=%d at seq=%d" % (idx, res, seq))
                return
    except socket.timeout:
        fail("steady%d: timed out at seq=%d -- connection lost" % (idx, seq))
    except OSError as e:
        fail("steady%d: %s at seq=%d" % (idx, e, seq))
    finally:
        with lock:
            print("steady%d completed %d round-trips" % (idx, seq))
        s.close()


stop = threading.Event()          # for the in-process steady threads
pstop = mp.Event()                # for the out-of-process churn workers
threads = [threading.Thread(target=steady, args=(stop, i)) for i in range(3)]
procs = [mp.Process(target=churn, args=(pstop, i)) for i in range(4)]
for t in threads:
    t.start()
for p in procs:
    p.start()
time.sleep(8)
stop.set()
pstop.set()
for t in threads:
    t.join(10)
for p in procs:
    p.join(10)
    if p.is_alive():
        p.terminate()

# daemon must still be healthy
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(3)
try:
    s.connect(SOCK)
    s.sendall(ping(4242))
    r = s.recv(18)
    if struct.unpack(HDR, r[:16])[3] != 4242:
        fail("post-churn: seq echo wrong")
    else:
        print("daemon healthy after churn")
except OSError as e:
    fail("post-churn: daemon unreachable: %s" % e)
s.close()

print("\n== PASS ==" if ok else "\n== FAIL ==")
sys.exit(0 if ok else 1)
