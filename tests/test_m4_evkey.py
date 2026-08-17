#!/usr/bin/env python3
"""M4 step 1: the virtual device gains keyboard capability.

Step 1 is device-only. Nothing can inject a key yet -- that is steps 2-7,
and the deny-list lands before the injection path is connected. What this
suite pins down is the boundary itself:

GG  the kernel really created the device with EV_KEY, and with *every*
    keycode registered (bit 0 / KEY_RESERVED excluded), read back from
    /proc/bus/input/devices rather than trusted from our own ioctls.
HH  KEY_POWER is among them. That is deliberate: capability is not
    permission. The device is physically able to emit it; the RPC layer
    is what will refuse.
II  the daemon advertises CAP_KEYBOARD -- reported from what the device
    actually has, not from a constant.
JJ  the advertised opcode set matches what is actually implemented --
    since step 7 that includes key-tap, and the next free opcode is
    still refused, which is what catches an RPC added without
    advertising it.
"""
import os, re, socket, struct, sys
import uictl_expect          # the advertised opcode set, shared

SOCK = os.path.join(os.environ["XDG_RUNTIME_DIR"], "uictld.sock")
DEVICES = "/proc/bus/input/devices"
# GG/HH are about the KEYCODE space, which M5.5 moved to the keyboard
# device. The pointer keeps ABS/REL and exactly five buttons; asking it
# about KEY_POWER would now be asking the wrong device.
DEV_NAME = "uictl virtual keyboard"
HDR = "<HHIII"
OP_PING, OP_MOVE_ABS, OP_HELLO, OP_KEY_TAP, OP_KEY_SEQUENCE = 1, 2, 3, 4, 5
OK, ERR_OPCODE_UNKNOWN = 0, 2
CAP_POINTER_ABS, CAP_KEYBOARD = 1 << 0, 1 << 1
EV_SYN, EV_KEY, EV_ABS = 0x00, 0x01, 0x03
KEY_A, KEY_POWER, KEY_MAX = 30, 116, 767
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
        return None, b""
    plen = struct.unpack(HDR, h)[4]
    body = b""
    while len(body) < plen:
        chunk = s.recv(plen - len(body))
        if not chunk:
            break
        body += chunk
    return (struct.unpack_from("<H", body, 0)[0], body[2:]) if body else (None, b"")


def hello(s, name=b"evkey-test", seq=1):
    body = struct.pack("<HH", 1, 1) + name + b"\x00" * (32 - len(name))
    s.sendall(struct.pack(HDR, 1, OP_HELLO, 1, seq, len(body)) + body)
    return reply(s)


def bitmap_has(words, bit):
    """/proc/bus/input/devices prints 64-bit hex words, most significant
    FIRST, so the last word holds bits 0..63."""
    idx = bit // 64
    if idx >= len(words):
        return False
    return bool(int(words[-1 - idx], 16) & (1 << (bit % 64)))


# --- GG / HH: what the kernel actually built --------------------------
block = None
for chunk in open(DEVICES).read().split("\n\n"):
    if 'Name="%s"' % DEV_NAME in chunk:
        block = chunk
if not block:
    print("SKIP: no '%s' device in %s -- is the daemon running?"
          % (DEV_NAME, DEVICES))
    sys.exit(0)

# Since M5.5 the abilities live on two devices, so each bit is checked
# against the device that is supposed to have it. Asserting SYN+KEY+ABS
# on one node passed for three milestones and would now pass only if the
# split had not happened -- which is why this had to change rather than
# be loosened.
ev = int(re.search(r"B: EV=(\S+)", block).group(1), 16)
pblock = None
for chunk in open(DEVICES).read().split("\n\n"):
    if 'Name="uictl virtual pointer"' in chunk:
        pblock = chunk
pev = int(re.search(r"B: EV=(\S+)", pblock).group(1), 16) if pblock else 0
for bit, name, got, dev in [(EV_SYN, "EV_SYN", ev, "keyboard"),
                            (EV_KEY, "EV_KEY", ev, "keyboard"),
                            (EV_SYN, "EV_SYN", pev, "pointer"),
                            (EV_ABS, "EV_ABS", pev, "pointer")]:
    if not (got & (1 << bit)):
        fail("GG: %s EV bitmap 0x%x lacks %s" % (dev, got, name))
if ev & (1 << EV_ABS):
    fail("GG: the keyboard has EV_ABS -- the devices are not disjoint")
if ok:
    print("GG keyboard EV=0x%x (SYN+KEY), pointer EV=0x%x (SYN+KEY+REL+ABS)"
          % (ev, pev))

m = re.search(r"B: KEY=([0-9a-f ]+)", block)
if not m:
    fail("GG: device has no KEY bitmap at all")
else:
    words = m.group(1).split()
    # The five buttons the POINTER device owns are deliberately absent
    # here (M5.5): the two devices must be disjoint where they overlap.
    POINTER_BUTTONS = {0x110, 0x111, 0x112, 0x113, 0x114}
    missing = [c for c in range(1, KEY_MAX + 1)
               if c not in POINTER_BUTTONS and not bitmap_has(words, c)]
    if missing:
        fail("GG: %d keycodes missing from the device, first few: %s"
             % (len(missing), missing[:8]))
    else:
        print("GG all %d keycodes 1..KEY_MAX registered, minus the %d "
              "buttons the pointer owns"
              % (KEY_MAX - len(POINTER_BUTTONS), len(POINTER_BUTTONS)))
    if any(bitmap_has(words, c) for c in POINTER_BUTTONS):
        fail("GG: the keyboard registered a pointer button -- the devices "
             "must be disjoint where they overlap")
    if bitmap_has(words, 0):
        fail("GG: KEY_RESERVED (0) was registered; the loop starts at 1")
    if not bitmap_has(words, KEY_POWER):
        fail("HH: KEY_POWER is not registered -- the device is supposed to be "
             "physically capable of it; policy is what refuses it")
    elif not bitmap_has(words, KEY_A):
        fail("HH: KEY_A is not registered")
    else:
        print("HH KEY_POWER and KEY_A both registered "
              "(capability is not permission)")

# --- II / JJ: what the daemon advertises ------------------------------
c = conn()
res, data = hello(c)
if res != OK or len(data) < 24:
    fail("II: handshake failed (result=%s, %d bytes)" % (res, len(data)))
else:
    proto_sel, caps, absmax, opmap, dver, reserved = struct.unpack_from(
        "<HHIQII", data, 0)
    if not (caps & CAP_KEYBOARD):
        fail("II: device_caps=0x%x does not advertise CAP_KEYBOARD" % caps)
    elif not (caps & CAP_POINTER_ABS):
        fail("II: device_caps=0x%x lost CAP_POINTER_ABS" % caps)
    else:
        print("II daemon advertises device_caps=0x%x (pointer-abs + keyboard)"
              % caps)

    if opmap != uictl_expect.EXPECTED_BITMAP:
        fail("JJ: opcode_bitmap=0x%x is not the implemented set (%s)"
             % (opmap, uictl_expect.describe(opmap)))
    else:
        print("JJ advertised opcodes match the implemented set (0x%x)" % opmap)

# Opcode 4 (OP_KEY_TAP) IS answered since step 5 -- by a stub that
# validates and acks without injecting -- so the check that matters is
# the bitmap above, not the result code. The next free opcode must still
# be unknown, which is what catches an RPC added without advertising it.
# Derived from the bitmap rather than hardcoded: this was `6` until M4.5
# used 6 and 7, and a probe that needs editing every time an opcode lands
# is a probe that will one day be edited into always passing.
probe = opmap.bit_length()
c.sendall(struct.pack(HDR, 1, probe, 1, 2, 0))
if reply(c)[0] != ERR_OPCODE_UNKNOWN:
    fail("JJ: opcode %d was not refused -- something added an RPC without "
         "updating the bitmap" % probe)
else:
    print("JJ next free opcode (%d) still ERR_OPCODE_UNKNOWN" % probe)
c.close()

# --- regression: the pointer still works ------------------------------
c = conn()
hello(c)
c.sendall(struct.pack(HDR, 1, OP_MOVE_ABS, 1, 2, 8) + struct.pack("<ii", 42, 42))
if reply(c)[0] != OK:
    fail("MOVE_ABS broke when the device gained EV_KEY")
else:
    print("-- MOVE_ABS still works on the now-keyboard-capable device")
c.close()

print("\n== PASS ==" if ok else "\n== FAIL ==")
sys.exit(0 if ok else 1)
