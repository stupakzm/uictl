#!/usr/bin/env python3
"""M4 step 8: the per-user key allowlist, strict default-deny.

Runs its own daemon with HOME in a temp dir, so it can control
~/.config/uictl/policy without touching the real one. Requires that no
uictld is already running.

A keycode must pass BOTH lists to be injected: the static deny-list
(platform layer, destructive keys, not overridable) and this allowlist
(per-user config). Absent, empty or unreadable policy means NO keys.

UU  no policy file -> every key refused, audited "not in allowlist", and
    the daemon says so at startup. MOVE_ABS is unaffected: the allowlist
    governs keys, not the pointer.
VV  a policy file allows exactly what it lists, singles and lo-hi ranges;
    everything else stays refused.
WW  the deny-list wins over the allowlist. Listing KEY_POWER in policy
    does not unlock it, the denial still reports "power" rather than
    "not in allowlist", and startup warns that the entry is dead.
XX  malformed lines are reported with the RIGHT line number (blank lines
    included in the count) and skipped without taking good lines down.
YY  a policy file with group/world bits is ignored entirely -- which
    under default-deny means no keys, i.e. it fails safe.
"""
import os, re, shutil, signal, socket, struct, subprocess, sys, tempfile, time
import uictl_expect          # grab_all: keep injection off the live session

SOCK = os.path.join(os.environ["XDG_RUNTIME_DIR"], "uictld.sock")
HDR = "<HHIII"
OP_PING, OP_MOVE_ABS, OP_HELLO, OP_KEY_TAP = 1, 2, 3, 4
OK, ERR_KEY_DENYLISTED, ERR_KEY_NOT_ALLOWED = 0, 9, 10
KEY_F13, KEY_F14, KEY_F15, KEY_A, KEY_POWER = 183, 184, 185, 30, 116
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


def tap(code):
    """One connection per tap: handshake, then KEY_TAP."""
    s = conn()
    body = struct.pack("<HH", 1, 1) + b"policy" + b"\x00" * 26
    s.sendall(struct.pack(HDR, 1, OP_HELLO, 1, 1, len(body)) + body)
    reply(s)
    s.sendall(struct.pack(HDR, 1, OP_KEY_TAP, 1, 2, 2) + struct.pack("<H", code))
    res = reply(s)[0]
    s.close()
    return res


def move():
    s = conn()
    body = struct.pack("<HH", 1, 1) + b"policy" + b"\x00" * 26
    s.sendall(struct.pack(HDR, 1, OP_HELLO, 1, 1, len(body)) + body)
    reply(s)
    s.sendall(struct.pack(HDR, 1, OP_MOVE_ABS, 1, 2, 8) +
              struct.pack("<ii", 10, 10))
    res = reply(s)[0]
    s.close()
    return res


def start(home, policy=None, mode=0o600):
    cfg = os.path.join(home, ".config", "uictl")
    os.makedirs(cfg, exist_ok=True)
    os.makedirs(os.path.join(home, ".local", "state"), exist_ok=True)
    # Register this suite as `interactive` so M4 step 10's rate limit
    # (5/s for an unregistered client) does not turn its bursts of taps
    # into ERR_RATE_LIMITED. The allowlist is what this suite tests.
    with open(os.path.join(cfg, "clients"), "w") as f:
        f.write("policy   interactive\n")
    os.chmod(os.path.join(cfg, "clients"), 0o600)

    path = os.path.join(cfg, "policy")
    if policy is None:
        if os.path.exists(path):
            os.unlink(path)
    else:
        with open(path, "w") as f:
            f.write(policy)
        os.chmod(path, mode)
    d = subprocess.Popen(["./uictld"], env=dict(os.environ, HOME=home),
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         text=True)
    time.sleep(0.8)
    # This suite never reads a device -- it asserts on result codes and
    # the audit log -- but it does inject, and an ungrabbed MOVE_ABS
    # moves the real pointer into whatever is at those coordinates. The
    # grab lives here rather than at the top of the run because the
    # suite restarts the daemon for every policy case, and each restart
    # creates a fresh pair of device nodes to grab.
    if d.poll() is None:
        _grabs.extend(uictl_expect.grab_all())
    return d


_grabs = []


def stop(d):
    # Release before the daemon dies, so the fds we close are the nodes
    # we actually took.
    while _grabs:
        os.close(_grabs.pop())
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

home = tempfile.mkdtemp(prefix="uictl-policy-")
audit_path = os.path.join(home, ".local", "state", "uictl", "audit.log")
try:
    # --- UU: no policy at all -----------------------------------------
    d = start(home, policy=None)
    if d.poll() is not None:
        print("SKIP: daemon would not start:", d.stderr.read())
        sys.exit(0)
    results = {code: tap(code) for code in (KEY_F13, KEY_A, 30, 57)}
    moved = move()
    err = stop(d)
    audit = open(audit_path).read()

    if set(results.values()) != {ERR_KEY_NOT_ALLOWED}:
        fail("UU: with no policy file, some keys were allowed: %s" % results)
    elif moved != OK:
        fail("UU: MOVE_ABS was refused (%s) -- the key allowlist must not "
             "govern the pointer" % moved)
    elif "ALL key injection will be refused" not in err:
        fail("UU: the daemon did not say the policy file was missing")
    elif "not in allowlist" not in audit:
        fail("UU: refusals were not audited as allowlist misses")
    else:
        print("UU no policy file -> every key refused, pointer unaffected")

    # --- VV / WW / XX: a real policy ----------------------------------
    POLICY = """# uictl key policy
183          # KEY_F13

184-185      # KEY_F14..KEY_F15
116          # KEY_POWER -- shadowed by the static deny-list

garbage
900
5-2
"""
    d = start(home, policy=POLICY)
    if d.poll() is not None:
        fail("VV: daemon would not start with a policy file")
    else:
        allowed = {c: tap(c) for c in (KEY_F13, KEY_F14, KEY_F15)}
        refused = {c: tap(c) for c in (KEY_A, 57, 59)}
        power = tap(KEY_POWER)
        err = stop(d)
        audit = open(audit_path).read()

        if set(allowed.values()) != {OK}:
            fail("VV: listed keycodes were refused: %s" % allowed)
        elif set(refused.values()) != {ERR_KEY_NOT_ALLOWED}:
            fail("VV: unlisted keycodes were allowed: %s" % refused)
        else:
            print("VV policy allows exactly what it lists (singles + ranges)")

        if power != ERR_KEY_DENYLISTED:
            fail("WW: KEY_POWER was ALLOWED by putting it in policy -- the "
                 "static deny-list must not be overridable")
        elif "denied (power)" not in audit:
            fail("WW: KEY_POWER denial did not report the deny-list reason")
        elif "on the static deny-list and stay denied" not in err:
            fail("WW: startup did not warn that a policy entry is shadowed")
        else:
            print("WW deny-list beats allowlist, and startup says so")

        # XX: counting the two blank lines, 'garbage' is line 7, '900'
        # line 8, '5-2' line 9. Getting these right is the whole point:
        # strtok_r would have collapsed the blanks and reported 5/6/7.
        for want in ("line 7", "line 8", "line 9"):
            if want not in err:
                fail("XX: malformed policy %s was not reported:\n%s"
                     % (want, err))
        if "3 keycode(s) allowed" not in err:
            fail("XX: expected exactly 3 allowed keycodes, got:\n%s" % err)
        if ok:
            print("XX malformed lines reported with correct numbers, good "
                  "lines survived")

    # --- YY: loose permissions fail safe ------------------------------
    d = start(home, policy=POLICY, mode=0o644)
    if d.poll() is not None:
        fail("YY: daemon would not start")
    else:
        loose = {c: tap(c) for c in (KEY_F13, KEY_F14)}
        err = stop(d)
        if set(loose.values()) != {ERR_KEY_NOT_ALLOWED}:
            fail("YY: a world-readable policy file was honoured: %s" % loose)
        elif "ignoring it, ALL key injection refused" not in err:
            fail("YY: the daemon did not say why the policy was ignored")
        else:
            print("YY loose-permission policy ignored -> no keys (fails safe)")
finally:
    shutil.rmtree(home, ignore_errors=True)

print("\n== PASS ==" if ok else "\n== FAIL ==")
sys.exit(0 if ok else 1)
