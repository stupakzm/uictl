#!/usr/bin/env python3
"""M3.6 task 4: version range intersection, against a WIDE-range daemon.

The shipped daemon declares UICTL_PROTO_MIN == UICTL_PROTO_MAX == 1, so
selection and pinning are unobservable against it -- every legal frame
says version 1 either way. This suite therefore builds a throwaway daemon
with the range widened to 1-3 and drives that, the same way the M3.7
fairness suite was validated against a deliberately-broken build.

Requires: no uictld running (it starts its own), and a working `cc`.

V  selection is the *highest mutually supported* version, not the
   daemon's max and not the client's max: client 1-2 vs daemon 1-3 -> 2.
W  before HELLO, any version the daemon speaks is admissible -- a client
   must be able to get a frame in to negotiate at all.
X  after HELLO the version is PINNED: a frame stamped with another
   version the daemon otherwise speaks is fatal ERR_VERSION and the
   connection is closed. Version hopping mid-stream would let one opcode
   carry two payload layouts.
Y  a version the daemon does not speak at all is fatal before HELLO too.
"""
import os, re, shutil, socket, struct, subprocess, sys, tempfile, time

SOCK = os.path.join(os.environ["XDG_RUNTIME_DIR"], "uictld.sock")
HDR = "<HHIII"
OP_PING, OP_HELLO = 1, 3
OK, ERR_VERSION = 0, 1
NAME_MAX = 32
WIDE_MAX = 3
ok = True


def fail(msg):
    global ok
    print("FAIL:", msg)
    ok = False


def hello_payload(name: bytes, lo, hi):
    return struct.pack("<HH", lo, hi) + name + b"\x00" * (NAME_MAX - len(name))


def frame(op, payload=b"", seq=1, ver=1):
    return struct.pack(HDR, ver, op, 1, seq, len(payload)) + payload


def conn():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(SOCK)
    s.settimeout(5)
    return s


def reply(s):
    h = s.recv(16)
    if len(h) != 16:
        return None, b""
    plen = struct.unpack(HDR, h)[4]
    body = b""
    while len(body) < plen:
        chunk = s.recv(plen - len(body))
        if not chunk:
            break
        body += chunk
    if len(body) < 2:
        return None, b""
    return struct.unpack_from("<H", body, 0)[0], body[2:]


if os.path.exists(SOCK):
    try:
        conn().close()
        print("SKIP: a uictld is already running; stop it and re-run")
        sys.exit(0)
    except OSError:
        pass

tmp = tempfile.mkdtemp(prefix="uictl-wide-")
try:
    shutil.copytree("src", os.path.join(tmp, "src"))
    hdr = os.path.join(tmp, "src", "proto.h")
    text = open(hdr).read()
    widened = re.sub(r"#define UICTL_PROTO_MAX 1u",
                     "#define UICTL_PROTO_MAX %du" % WIDE_MAX, text)
    if widened == text:
        print("SKIP: could not widen UICTL_PROTO_MAX -- proto.h changed shape")
        sys.exit(0)
    open(hdr, "w").write(widened)

    exe = os.path.join(tmp, "uictld-wide")
    build = subprocess.run(
        ["cc", "-D_FORTIFY_SOURCE=2", "-fPIE", "-Wall", "-Wextra",
         "-Wconversion", "-g", "-std=c11", "-D_GNU_SOURCE",
         os.path.join(tmp, "src", "uictld.c"),
         os.path.join(tmp, "src", "platform", "uinput.c"), "-o", exe, "-pie"],
        capture_output=True, text=True)
    if build.returncode != 0:
        print("SKIP: could not build the wide-range daemon:\n" + build.stderr)
        sys.exit(0)

    d = subprocess.Popen([exe], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         text=True)
    time.sleep(0.7)
    if d.poll() is not None:
        print("SKIP: wide daemon would not start:", d.stderr.read())
        sys.exit(0)

    try:
        # --- W: any supported version is admissible before HELLO ------
        for ver in range(1, WIDE_MAX + 1):
            c = conn()
            c.sendall(frame(OP_PING, seq=ver, ver=ver))
            if reply(c)[0] != OK:
                fail("W: PING at version %d refused before HELLO" % ver)
            c.close()
        if ok:
            print("W versions 1..%d all admissible before HELLO" % WIDE_MAX)

        # --- Y: an unsupported version is fatal -----------------------
        c = conn()
        c.sendall(frame(OP_PING, seq=1, ver=WIDE_MAX + 1))
        res, _ = reply(c)
        if res != ERR_VERSION:
            fail("Y: version %d got result=%s, expected ERR_VERSION"
                 % (WIDE_MAX + 1, res))
        elif c.recv(1) != b"":
            fail("Y: connection stayed open after a fatal version error")
        else:
            print("Y unsupported version -> ERR_VERSION, stream closed")
        c.close()

        # --- V: highest mutually supported wins -----------------------
        for lo, hi, want in [(1, 2, 2),          # client caps below daemon
                             (1, WIDE_MAX, WIDE_MAX),
                             (2, 9, WIDE_MAX),   # daemon caps below client
                             (WIDE_MAX, WIDE_MAX, WIDE_MAX)]:
            c = conn()
            c.sendall(frame(OP_HELLO, hello_payload(b"probe", lo, hi), ver=lo))
            res, data = reply(c)
            if res != OK:
                fail("V: client range %d-%d refused (result=%s)" % (lo, hi, res))
            else:
                sel = struct.unpack_from("<H", data, 0)[0]
                if sel != want:
                    fail("V: client %d-%d vs daemon 1-%d selected %d, "
                         "expected %d" % (lo, hi, WIDE_MAX, sel, want))
            c.close()
        if ok:
            print("V selection is the highest mutually supported version")

        # --- X: the selection is pinned -------------------------------
        c = conn()
        c.sendall(frame(OP_HELLO, hello_payload(b"pinned", 1, 2), ver=1))
        res, data = reply(c)
        sel = struct.unpack_from("<H", data, 0)[0] if data else None
        if res != OK or sel != 2:
            fail("X: setup handshake failed (result=%s selected=%s)" % (res, sel))
        else:
            c.sendall(frame(OP_PING, seq=2, ver=2))       # the pinned version
            if reply(c)[0] != OK:
                fail("X: PING at the selected version %d refused" % sel)
            # version 1 and 3 are both spoken by this daemon, but neither
            # is what this connection negotiated
            for stray in (1, WIDE_MAX):
                c2 = conn()
                c2.sendall(frame(OP_HELLO, hello_payload(b"pinned", 1, 2),
                                 ver=1))
                reply(c2)
                c2.sendall(frame(OP_PING, seq=3, ver=stray))
                res, _ = reply(c2)
                if res != ERR_VERSION:
                    fail("X: version %d accepted after selecting 2 "
                         "(result=%s) -- pinning is not enforced"
                         % (stray, res))
                elif c2.recv(1) != b"":
                    fail("X: stream stayed open after a pin violation")
                c2.close()
            if ok:
                print("X post-handshake version is pinned to the selection")
        c.close()
    finally:
        d.terminate()
        try:
            d.wait(timeout=5)
        except subprocess.TimeoutExpired:
            d.kill()
finally:
    shutil.rmtree(tmp, ignore_errors=True)

print("\n== PASS ==" if ok else "\n== FAIL ==")
sys.exit(0 if ok else 1)
