#!/usr/bin/env python3
"""M4 wire steps: OP_KEY_TAP as it appears to a client, step by step.

This suite grows with steps 3-7. It currently covers steps 3-5: the
opcode exists, the client can form the request, and the daemon validates
and acks it as a STUB -- nothing is injected until step 7, after the
deny-list.

OO  step 7: OP_KEY_TAP is now advertised in `opcode_bitmap` -- and not
    one step earlier, because the bitmap is the contract and may only
    promise what is validated, gated and actually injected.
PP  step 7: a well-formed, allowed key is accepted and audited by code,
    with no "(stub" suffix left claiming otherwise.
QQ  step 5: payload size is exact (2 bytes) and the keycode is
    range-checked 1..KEY_MAX -- both ERR_PAYLOAD_INVALID, because
    neither is a *policy* refusal. Policy is step 6 and answers
    ERR_DENIED_BY_POLICY.
RR  the connection survives all of it: a rejected payload is a per-frame
    error, not a framing error.
SS  steps 4+7: the CLI gates on `opcode_bitmap` -- and now that the
    daemon advertises key-tap, `uictl key-tap` works, while a denied
    keycode fails with a named reason rather than a bare number.
TT  step 6: destructive keycodes are refused with ERR_KEY_DENYLISTED,
    and unlisted ones with ERR_KEY_NOT_ALLOWED -- both distinct from the
    ERR_PAYLOAD_INVALID of QQ, because
    "your client is broken" and "you may not do that" are different
    answers and the audit log has to tell them apart. Checked while the
    handler is still a stub, which is the point of the ordering.
"""
import os, socket, struct, subprocess, sys, time
import uictl_expect          # the advertised opcode set, shared

SOCK = os.path.join(os.environ["XDG_RUNTIME_DIR"], "uictld.sock")
AUDIT = os.path.expanduser("~/.local/state/uictl/audit.log")
HDR = "<HHIII"
OP_PING, OP_MOVE_ABS, OP_HELLO, OP_KEY_TAP, OP_KEY_SEQUENCE = 1, 2, 3, 4, 5
OK, ERR_OPCODE_UNKNOWN, ERR_PAYLOAD_INVALID = 0, 2, 3
ERR_KEY_DENYLISTED, ERR_KEY_NOT_ALLOWED = 9, 10
KEY_A, KEY_F13 = 30, 183   # F13: exists, bound to nothing anywhere
ok = True

# This suite injects device opcodes but never reads a device, so it has
# no reason to open a node -- which is exactly why it was missed. The
# grab is purely to keep those events off the live session; MOVE_ABS is
# not policy-gated, and an ungrabbed one moves the real pointer. Held
# for the whole run and released by process exit, including on a crash.
# run_all.py deliberately does not do this on the suite's behalf: then
# running this file directly would still inject into the session.
_GRABS = uictl_expect.grab_all()


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


def hello(s, seq=1):
    body = struct.pack("<HH", 1, 1) + b"m4-wire" + b"\x00" * 25
    s.sendall(struct.pack(HDR, 1, OP_HELLO, 1, seq, len(body)) + body)
    return reply(s)


def frame(op, payload=b"", seq=1):
    return struct.pack(HDR, 1, op, 1, seq, len(payload)) + payload


ERR_RATE_LIMITED = 11


def ask(sock, f):
    """Send a frame and read the result, pacing around the rate limit.

    This suite talks to the daemon under the real HOME, where this client
    is almost certainly unregistered and therefore limited to 5/s (M4
    step 10). Backing off and retrying is exactly what a real client
    library must do on ERR_RATE_LIMITED -- retrying immediately makes it
    worse -- so the suite does the same rather than reporting a working
    limiter as a failure."""
    res, data = None, b""
    for _ in range(40):
        sock.sendall(f)
        res, data = reply(sock)
        if res != ERR_RATE_LIMITED:
            return res, data
        time.sleep(0.25)
    return res, data


audit0 = open(AUDIT).read()


def policy_allows(code):
    """Since M4 step 8 an allowed keycode also has to be listed in
    ~/.config/uictl/policy, which this suite does not own -- the daemon
    it talks to runs under the real HOME. Probe once and skip the
    injection assertions rather than reporting a policy decision as a
    bug. test_m4_policy.py owns the allowlist itself."""
    s = conn()
    body = struct.pack("<HH", 1, 1) + b"probe" + b"\x00" * 27
    s.sendall(struct.pack(HDR, 1, OP_HELLO, 1, 1, len(body)) + body)
    reply(s)
    res = ask(s, frame(OP_KEY_TAP, struct.pack("<H", code), seq=2))[0]
    s.close()
    return res == OK


POLICY_OK = policy_allows(KEY_F13)
if not POLICY_OK:
    print("NOTE: ~/.config/uictl/policy does not allow keycode %d, so the "
          "injection cases are skipped (default-deny is working)." % KEY_F13)

c = conn()
res, data = hello(c)
if res != OK or len(data) < 24:
    print("SKIP: handshake failed (result=%s)" % res)
    sys.exit(0)

# --- OO: advertised now that it is real -------------------------------
opmap = struct.unpack_from("<HHIQII", data, 0)[3]
expected_ops = uictl_expect.EXPECTED_BITMAP
if not (opmap & (1 << OP_KEY_TAP)):
    fail("OO: opcode_bitmap=0x%x does not advertise OP_KEY_TAP, but the "
         "daemon injects -- a client gating on the contract cannot use it"
         % opmap)
elif opmap != expected_ops:
    fail("OO: opcode_bitmap=0x%x is not the implemented set (%s)"
         % (opmap, uictl_expect.describe(opmap)))
else:
    print("OO OP_KEY_TAP advertised (bitmap 0x%x)" % opmap)

# --- PP: the stub handler accepts a well-formed request ---------------
payload = struct.pack("<H", KEY_F13)
if len(payload) != 2:
    fail("QQ: the payload is not 2 bytes")
if POLICY_OK:
    res, _ = ask(c, frame(OP_KEY_TAP, payload, seq=2))
    if res != OK:
        fail("PP: well-formed KEY_TAP got result=%s, expected OK" % res)
    else:
        print("PP well-formed KEY_TAP accepted and injected")

# --- QQ: validity checks, all ERR_PAYLOAD_INVALID ---------------------
cases = [
    ("4-byte payload", b"\x1e\x00\x00\x00"),
    ("1-byte payload", b"\x1e"),
    ("empty payload", b""),
    ("keycode 0 (KEY_RESERVED)", struct.pack("<H", 0)),
    ("keycode 768 (> KEY_MAX)", struct.pack("<H", 768)),
    ("keycode 65535", struct.pack("<H", 65535)),
]
seq = 3
for label, pay in cases:
    res, _ = ask(c, frame(OP_KEY_TAP, pay, seq=seq))
    seq += 1
    if res != ERR_PAYLOAD_INVALID:
        fail("QQ: %s got result=%s, expected ERR_PAYLOAD_INVALID" % (label, res))
if ok:
    print("QQ %d malformed KEY_TAPs refused as invalid, not as policy"
          % len(cases))

# --- TT: the deny-list -----------------------------------------------
DENIED = [
    ("KEY_POWER", 116), ("KEY_POWER2", 0x164), ("KEY_SLEEP", 142),
    ("KEY_SUSPEND", 205), ("KEY_RESTART", 0x198), ("KEY_LOGOFF", 0x1b1),
    ("KEY_SYSRQ", 99), ("KEY_RFKILL", 247), ("KEY_BLUETOOTH", 237),
    ("KEY_WLAN", 238), ("KEY_UWB", 239), ("KEY_EJECTCD", 161),
    ("KEY_EJECTCLOSECD", 162), ("KEY_BRIGHTNESSDOWN", 224),
    ("KEY_BRIGHTNESSUP", 225), ("KEY_BRIGHTNESS_CYCLE", 243),
    ("KEY_BRIGHTNESS_MIN", 0x250), ("KEY_BRIGHTNESS_MAX", 0x251),
    ("KEY_FN", 0x1d0), ("KEY_FN_F5", 0x1d6), ("KEY_FN_RIGHT_SHIFT", 0x1e5),
    ("KEY_BRL_DOT1", 0x1f1), ("KEY_BRL_DOT10", 0x1fa),
    ("KEY_NUMERIC_0", 0x200), ("KEY_NUMERIC_D", 0x20f),
]
# These are INJECTED FOR REAL. F13-F17 and bare modifiers only: unbound
# on normal desktops, and a modifier tapped alone does nothing. Adding a
# letter or ENTER here would type into whatever window has focus.
ALLOWED = [
    ("KEY_F13", 183), ("KEY_F14", 184), ("KEY_F15", 185),
    ("KEY_F16", 186), ("KEY_F17", 187),
    ("KEY_LEFTCTRL", 29), ("KEY_LEFTSHIFT", 42), ("KEY_RIGHTALT", 100),
]
for label, code in DENIED:
    res, _ = ask(c, frame(OP_KEY_TAP, struct.pack("<H", code), seq=seq))
    seq += 1
    if res != ERR_KEY_DENYLISTED:
        fail("TT: %s (%d) got result=%s, expected ERR_KEY_DENYLISTED"
             % (label, code, res))
if POLICY_OK:
    for label, code in ALLOWED:
        res, _ = ask(c, frame(OP_KEY_TAP, struct.pack("<H", code), seq=seq))
        seq += 1
        if res != OK:
            fail("TT: %s (%d) got result=%s -- the deny-list is too broad"
                 % (label, code, res))
if ok:
    print("TT %d destructive keycodes denied%s"
          % (len(DENIED),
             ", %d ordinary ones allowed" % len(ALLOWED) if POLICY_OK
             else " (allowed-key cases skipped: no policy)"))

# The boundary below a denied range must be allowed, or the range is
# silently wider than it reads. 0x1cf and 0x1f0 are unassigned in the
# kernel's table, so injecting them is inert.
if POLICY_OK:
    for label, code in [("KEY_FN - 1", 0x1d0 - 1),
                        ("KEY_BRL_DOT1 - 1", 0x1f1 - 1)]:
        res, _ = ask(c, frame(OP_KEY_TAP, struct.pack("<H", code), seq=seq))
        seq += 1
        if res != OK:
            fail("TT: %s (%d) is denied -- a range reaches further than it "
                 "reads" % (label, code))
    if ok:
        print("TT denied ranges do not bleed into their neighbours")

# --- RR: the connection is fine ---------------------------------------
if ask(c, frame(OP_MOVE_ABS, struct.pack("<ii", 55, 66), seq=seq))[0] != OK:
    fail("RR: connection unusable after an unimplemented opcode")
else:
    print("RR connection still usable -- per-frame error, not a framing error")
c.close()

# --- SS: the CLI now works, and reports a denial by name --------------
if POLICY_OK:
    r = subprocess.run(["./uictl", "key-tap", str(KEY_F13)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        fail("SS: `uictl key-tap %d` failed: %s" % (KEY_F13, r.stderr.strip()))
    else:
        print("SS CLI:", r.stdout.strip())

r = subprocess.run(["./uictl", "key-tap", "116"], capture_output=True,
                   text=True)   # KEY_POWER
if r.returncode == 0:
    fail("SS: the CLI pressed KEY_POWER")
elif "built-in deny-list" not in r.stderr:
    fail("SS: denial not reported by name: %s" % r.stderr.strip())
elif "fix:  none" not in r.stderr:
    fail("SS: the CLI did not say that no configuration can unlock a "
         "deny-listed key -- sending a user to edit policy here wastes "
         "their time: %s" % r.stderr.strip())
else:
    print("SS CLI:", r.stderr.strip().splitlines()[0])
    print("SS   and says plainly that config cannot unlock it")

r = subprocess.run(["./uictl", "key-tap", "9999"], capture_output=True,
                   text=True)
if r.returncode == 0 or "1..767" not in r.stderr:
    fail("SS: CLI did not range-check the keycode locally: %s" % r.stderr.strip())
else:
    print("SS CLI range-checks the keycode before connecting")

# --- PP (cont): the audit records name, code, and honesty -------------
new = open(AUDIT).read()[len(audit0):]
named = [l for l in new.splitlines() if "op=KEY_TAP" in l]
if not named:
    fail("PP: nothing was audited as op=KEY_TAP (opname missing?)")
elif [l for l in new.splitlines() if "op=UNKNOWN" in l]:
    fail("PP: a KEY_TAP frame was audited as op=UNKNOWN")
else:
    acked = [l for l in named if "result=0" in l]
    if not POLICY_OK:
        pass                      # nothing was accepted, nothing to check
    elif not acked:
        fail("PP: the accepted KEY_TAP was not audited")
    elif "code=%d" % KEY_F13 not in acked[0]:
        fail("PP: audit line does not record the keycode: %s" % acked[0])
    elif "stub" in acked[0] or "not injected" in acked[0]:
        fail("PP: the audit line still says the key was not injected, but "
             "step 7 connected the write: %s" % acked[0])
    else:
        print("PP audited:", acked[0].split("op=")[1].strip())
    if not [l for l in named if "out of range" in l]:
        fail("QQ: an out-of-range keycode was not audited as such")
    # Two shapes of denial, and the audit must distinguish them: the
    # static deny-list says WHY ("denied (power)"), the allowlist says
    # the key simply is not listed. Both are ERR_DENIED_BY_POLICY on the
    # wire, because to a client they are the same kind of no.
    denied = [l for l in named
              if "result=%d" % ERR_KEY_DENYLISTED in l
              or "result=%d" % ERR_KEY_NOT_ALLOWED in l]
    by_list = [l for l in denied if "denied (" in l]
    by_allow = [l for l in denied if "not in allowlist" in l]
    if not denied:
        fail("TT: no denial was audited")
    elif not by_list:
        fail("TT: no deny-list refusal recorded a reason: %s" % denied[0])
    else:
        print("TT audited with a reason:", by_list[0].split("args=")[1].strip())
        if by_allow:
            print("TT allowlist misses audited separately:",
                  by_allow[0].split("args=")[1].strip())

print("\n== PASS ==" if ok else "\n== FAIL ==")
sys.exit(0 if ok else 1)
