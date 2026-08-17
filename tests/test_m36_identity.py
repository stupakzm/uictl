#!/usr/bin/env python3
"""M3.6 task 5: daemon-derived client class (gap G2, second half).

Runs its own daemon with HOME pointed at a temp dir, so the client
registry, the audit log and the lock file are all isolated from the real
ones. Requires that no uictld is already running -- the socket path comes
from XDG_RUNTIME_DIR and would collide.

AA  a name listed in ~/.config/uictl/clients gets that class; it appears
    in the audit line and in the SIGUSR1 dump.
BB  an unregistered name gets 'untrusted' -- the floor is the default,
    so a name can only ever *raise* privilege by an explicit local
    decision.
CC  a connection that never said HELLO is 'untrusted' too.
DD  source_tag cannot influence the class. This is the whole of G2: the
    client sends SRC_LLM and SRC_CLI for the same registered name and
    gets the same class both times.
EE  a registry with group/world bits is ignored entirely, and says so.
FF  malformed registry lines are reported and skipped without taking the
    good lines down with them.
"""
import os, re, shutil, signal, socket, struct, subprocess, sys, tempfile, time

SOCK = os.path.join(os.environ["XDG_RUNTIME_DIR"], "uictld.sock")
HDR = "<HHIII"
OP_PING, OP_HELLO = 1, 3
OK = 0
NAME_MAX = 32
SRC_CLI, SRC_LLM = 1 << 0, 1 << 2
ok = True


def fail(msg):
    global ok
    print("FAIL:", msg)
    ok = False


def hello_payload(name: bytes, lo=1, hi=1):
    return struct.pack("<HH", lo, hi) + name + b"\x00" * (NAME_MAX - len(name))


def frame(op, payload=b"", seq=1, src=SRC_CLI):
    return struct.pack(HDR, 1, op, src, seq, len(payload)) + payload


def conn():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(SOCK)
    s.settimeout(5)
    return s


def result_of(s):
    r = s.recv(16)
    if len(r) != 16:
        return None
    plen = struct.unpack(HDR, r)[4]
    body = b""
    while len(body) < plen:
        chunk = s.recv(plen - len(body))
        if not chunk:
            break
        body += chunk
    return struct.unpack_from("<H", body, 0)[0] if len(body) >= 2 else None


def start_daemon(home, registry=None, mode=0o600):
    cfg = os.path.join(home, ".config", "uictl")
    os.makedirs(cfg, exist_ok=True)
    # prepare_state_dir() does a single mkdir, not mkdir -p, so the
    # parent has to exist. (Same is true on a real first run with no
    # ~/.local/state -- noted as an open item, not this task's job.)
    os.makedirs(os.path.join(home, ".local", "state"), exist_ok=True)
    path = os.path.join(cfg, "clients")
    if registry is not None:
        with open(path, "w") as f:
            f.write(registry)
        os.chmod(path, mode)
    env = dict(os.environ, HOME=home)
    d = subprocess.Popen(["./uictld"], env=env, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, text=True)
    time.sleep(0.7)
    return d


def stop_daemon(d):
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

REGISTRY = """# uictl client registry
muvor           interactive
auto-c          standard
agent           untrusted

bad-line-no-class
name.with.bad.class     wizard
"invalid name"          standard
"""

home = tempfile.mkdtemp(prefix="uictl-home-")
try:
    d = start_daemon(home, REGISTRY)
    if d.poll() is not None:
        print("SKIP: daemon would not start:", d.stderr.read())
        sys.exit(0)

    audit_path = os.path.join(home, ".local", "state", "uictl", "audit.log")

    # --- AA / BB / DD: class comes from the registry, not the frame ---
    # Sequential, one connection at a time: MAX_CONNS_PER_PID is 4 and
    # this whole suite is one pid, so holding all of these open would
    # start getting ERR_BUSY from M3.7's cap.
    for name, src in [(b"muvor", SRC_CLI),
                      (b"muvor", SRC_LLM),      # DD: same name, other tag
                      (b"auto-c", SRC_CLI),
                      (b"agent", SRC_CLI),
                      (b"stranger", SRC_CLI)]:  # BB: unregistered
        c = conn()
        c.sendall(frame(OP_HELLO, hello_payload(name), src=src))
        if result_of(c) != OK:
            fail("AA: HELLO from %s refused" % name.decode())
        c.close()

    # --- CC + dump: at most 4 live at once ----------------------------
    held = []
    for name in (b"muvor", b"auto-c", b"agent"):
        c = conn()
        c.sendall(frame(OP_HELLO, hello_payload(name)))
        result_of(c)
        held.append(c)
    quiet = conn()                      # never says HELLO
    quiet.sendall(frame(OP_PING, seq=9))
    if result_of(quiet) != OK:
        fail("CC: PING without HELLO refused")

    d.send_signal(signal.SIGUSR1)
    time.sleep(0.4)
    for c in held:
        c.close()
    quiet.close()
    err = stop_daemon(d)

    audit = open(audit_path).read() if os.path.exists(audit_path) else ""

    # DD is the load-bearing one: same name, two different source_tags,
    # one class. A client cannot pick its own tier.
    for name, want in [("muvor", "interactive"), ("auto-c", "standard"),
                       ("agent", "untrusted"), ("stranger", "untrusted")]:
        got = re.findall(r"op=HELLO .*name=%s proto=\d+ asked=\S+ class=(\w+)" % name,
                         audit)
        if not got:
            fail("AA: no audit line for %s" % name)
        elif set(got) != {want}:
            fail("AA/DD: %s audited as class %s, expected only %s"
                 % (name, set(got), want))
    if ok:
        print("AA registry classes applied: interactive / standard / untrusted")
        print("BB unregistered name defaulted to the floor")
        print("DD source_tag did not change the class (SRC_LLM == SRC_CLI)")

    dump = [l for l in err.splitlines() if l.startswith("  slot=")]
    classes = sorted(re.search(r"class=(\w+)", l).group(1) for l in dump)
    named = sorted(re.search(r"name=(\S+)", l).group(1) for l in dump)
    if not dump:
        fail("AA: SIGUSR1 dump had no connection lines")
    else:
        if classes != sorted(["interactive", "standard", "untrusted",
                              "untrusted"]):
            fail("AA: dump classes %s" % classes)
        elif "-" not in named:
            fail("CC: the connection that never said HELLO is missing")
        else:
            print("CC dump shows the handshake-less connection as "
                  "name=- class=untrusted")

    # --- FF: bad registry lines reported, good ones survive -----------
    if "line 6" not in err or "line 7" not in err or "line 8" not in err:
        fail("FF: malformed registry lines were not all reported:\n%s" % err)
    elif "registered as 'interactive'" not in err:
        fail("FF: a good line was dropped along with the bad ones")
    else:
        print("FF malformed registry lines reported and skipped")

    # --- EE: a loose-permission registry is ignored -------------------
    d2 = start_daemon(home, REGISTRY, mode=0o644)
    if d2.poll() is None:
        c = conn()
        c.sendall(frame(OP_HELLO, hello_payload(b"muvor")))
        result_of(c)
        c.close()
        err2 = stop_daemon(d2)
        audit2 = open(audit_path).read()
        last = re.findall(r"op=HELLO .*name=muvor proto=\d+ asked=\S+ class=(\w+)",
                          audit2)[-1]
        if "ignoring it" not in err2:
            fail("EE: world-readable registry was not rejected")
        elif last != "untrusted":
            fail("EE: registry with group/world bits still granted class %s"
                 % last)
        else:
            print("EE registry with group/world bits ignored, class fell "
                  "back to the floor")
    else:
        fail("EE: daemon would not start for the permissions case")
finally:
    shutil.rmtree(home, ignore_errors=True)

print("\n== PASS ==" if ok else "\n== FAIL ==")
sys.exit(0 if ok else 1)
