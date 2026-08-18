#!/usr/bin/env python3
"""M4 step 11: the test matrix, run in one command.

The suites came one per step and each one documents itself. What was
missing is the thing that makes them a *matrix* rather than a pile: the
ordering constraint between them, and a statement of which behaviour
each one is the evidence for.

The ordering is not a nicety. Suites split into two kinds and the split
is invisible from the outside:

  own     starts its own daemon, usually with HOME in a temp dir so it
          controls the policy file. Fails confusingly if a uictld is
          already listening -- the socket is taken.
  shared  talks to a daemon that is already up, under the real HOME.
          Fails confusingly if one is not.

Running them in the wrong order produces failures that look like bugs in
the daemon (that is exactly how `test_m35_evkey_churn` was first seen to
"fail"), so this script owns the daemon lifecycle instead of the reader.

Usage:  python3 tests/run_all.py [-k SUBSTRING]
Exit:   0 if every suite passed or skipped for an environmental reason.
"""
import os, re, signal, subprocess, socket, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)        # the suites get this for free; the runner
import uictl_expect             # is invoked as tests/run_all.py, so it does not
REPO = os.path.dirname(HERE)
SOCK = os.path.join(os.environ["XDG_RUNTIME_DIR"], "uictld.sock")

# (suite, mode, what this suite is the evidence for)
SUITES = [
    ("test_m35_reaper.py",       "shared", "a half-delivered frame is reaped, not parked"),
    ("test_m35_backpressure.py", "shared", "EPOLLOUT stall and drain"),
    ("test_m35_evkey_churn.py",  "shared", "fd recycling cannot alias a connection"),
    ("test_m37_admission.py",    "shared", "frame budget, per-pid connection cap, ERR_BUSY"),
    ("test_m36_hello.py",        "shared", "handshake enforcement, no forged audit lines"),
    ("test_m4_evkey.py",         "shared", "device keybits vs advertised capabilities"),
    ("test_m4_wire.py",          "shared", "OP_KEY_TAP as a client sees it; deny-list on the wire"),
    ("test_wire9_vectors.py",    "shared", "WIRE.md 9: the vectors match the header AND the daemon"),
    ("test_mlib_lib.py",         "shared", "libuictl: no replay, visible reconnect, local validation"),
    ("test_mlib_proto_json.py",  "shared", "proto.json: generated, current, and true to daemon + vectors"),

    ("test_m36_version.py",      "own",    "version range intersection, pinned after HELLO"),
    ("test_m36_identity.py",     "own",    "client registry -> class; source_tag is audit-only"),
    ("test_m37_sigusr1.py",      "own",    "connection table dump is metadata only"),
    ("test_m4_keytap.py",        "own",    "TYPE: a key reaches the device; DENIED: none of it does"),
    ("test_m4_policy.py",        "own",    "ALLOWLIST on/off, strict default-deny"),
    ("test_m4_sequence.py",      "own",    "atomic balanced sequences, all-or-nothing"),
    ("test_m4_rate.py",          "own",    "RATE LIMIT trip: per-pid buckets and the daemon-wide ceiling"),
    ("test_m45_release.py",      "own",    "held keys released on disconnect, kill -9 included"),
    ("test_m45_arbitration.py",  "own",    "held-key arbitration and the dead-man timer"),
    ("test_m5_confirm.py",       "own",    "confirmation: parked requests, fails closed, no source_tag"),
    ("test_m55_pointer.py",      "own",    "device split, buttons, rel/scroll, batch, audit coalescing"),
    ("test_m6_activation.py",    "own",    "M6: socket activation, Type=notify readiness, the shipped units"),
    ("test_m6_idle.py",          "own",    "M6: idle exit is keyed on the connection table, and only under activation"),
    ("test_wire831_forgive.py",  "own",    "WIRE.md 8.3.1: the first release on a connection is forgiven"),
    ("test_wire87_storm.py",     "own",    "WIRE.md 8.7: the connection-attempt backstop"),
    ("test_wire5a_pointer.py",   "own",    "WIRE.md 5A: every normative claim about the pointer opcodes"),
    ("test_wire5b_keyboard.py",  "own",    "WIRE.md 5B: keyboard opcodes and BATCH, the refusals"),
]

# M4 step 11 named four cells; M4.5 added three more. Each maps to the
# suite that is its evidence, so "covered" is a claim with a name on it
# rather than an assertion in a plan file.
MATRIX = [
    ("type a key",              "test_m4_keytap.py"),
    ("denied key",              "test_m4_wire.py"),
    ("allowlist on/off",        "test_m4_policy.py"),
    ("rate-limit trip",         "test_m4_rate.py"),
    ("held key released",       "test_m45_release.py"),
    ("two clients contending",  "test_m45_arbitration.py"),
    ("dead-man timer",          "test_m45_arbitration.py"),
    ("confirmation gate",       "test_m5_confirm.py"),
    ("device split",            "test_m55_pointer.py"),
    ("buttons + drag release",  "test_m55_pointer.py"),
    ("batch all-or-nothing",    "test_m55_pointer.py"),
    ("audit volume (G10)",      "test_m55_pointer.py"),
    ("reconnect release (8.3.1)", "test_wire831_forgive.py"),
    ("reconnect storm (8.7)",     "test_wire87_storm.py"),
    ("pointer spec (5A)",         "test_wire5a_pointer.py"),
    ("keyboard spec (5B)",        "test_wire5b_keyboard.py"),
    ("conformance vectors (9)",   "test_wire9_vectors.py"),
    ("libuictl (M-lib 2)",        "test_mlib_lib.py"),
    ("proto.json (M-lib 3)",      "test_mlib_proto_json.py"),
    ("socket activation (M6)",    "test_m6_activation.py"),
    ("idle exit (M6)",            "test_m6_idle.py"),
]


# ---- the grab invariant, checked rather than remembered --------------
# A suite that sends any of these makes the kernel emit a real event on a
# real device, which the compositor delivers to whatever has focus. It
# must therefore hold an EVIOCGRAB on the nodes first -- open_node() if
# it reads events, grab_all() if it only injects.
#
# This check exists because the rule was already stated in a comment and
# still missed three suites: the two that never read a device were easy
# to overlook precisely because they had no reason to open one. They
# moved the pointer into a hot corner instead.
DEVICE_OPS = ("OP_MOVE_ABS", "OP_MOVE_REL", "OP_SCROLL", "OP_BUTTON",
              "OP_KEY_TAP", "OP_KEY_SEQUENCE", "OP_KEY_DOWN", "OP_BATCH")


def check_grabs(suites):
    """Static scan. Returns a list of offending suite names."""
    bad = []
    for suite, _, _ in suites:
        try:
            src = open(os.path.join(HERE, suite)).read()
        except OSError:
            continue
        body = "\n".join(l for l in src.splitlines()
                         if not re.match(r"\s*\(?OP_[\w, ()]*=", l))
        if any(op in body for op in DEVICE_OPS) and \
           "open_node(" not in src and "grab_all(" not in src:
            bad.append(suite)
    return bad


def daemon_up():
    if not os.path.exists(SOCK):
        return False
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.connect(SOCK)
        return True
    except OSError:
        return False
    finally:
        s.close()


def run(suite):
    t0 = time.monotonic()
    r = subprocess.run([sys.executable, os.path.join("tests", suite)],
                       cwd=REPO, capture_output=True, text=True, timeout=600)
    dt = time.monotonic() - t0
    out = r.stdout + r.stderr
    if r.returncode == 0 and "== PASS ==" in out:
        return "PASS", dt, out
    if r.returncode == 0 and re.search(r"^SKIP:", out, re.M):
        return "SKIP", dt, out
    return "FAIL", dt, out


def main():
    only = None
    if len(sys.argv) == 3 and sys.argv[1] == "-k":
        only = sys.argv[2]
    suites = [s for s in SUITES if only is None or only in s[0]]

    if daemon_up():
        print("refusing to run: a uictld is already listening on %s\n"
              "  the 'own' suites start their own daemon and would fail on a "
              "taken socket.\n  stop it first: kill -TERM $(pgrep -x uictld)"
              % SOCK)
        return 2

    ungrabbed = check_grabs(suites)
    if ungrabbed:
        print("refusing to run: these suites inject device events without "
              "grabbing a node first,\n  so their keystrokes and pointer "
              "motion would reach your live session:\n")
        for suite in ungrabbed:
            print("    %s" % suite)
        print("\n  add `uictl_expect.grab_all()` after the daemon starts "
              "(or open_node() if\n  the suite reads events), and close the "
              "fds in its finally block.")
        return 2

    results = {}
    failed_output = []

    def do(group):
        for suite, mode, what in suites:
            if mode != group:
                continue
            print("  %-28s " % suite, end="", flush=True)
            verdict, dt, out = run(suite)
            results[suite] = verdict
            print("%-5s %5.1fs  %s" % (verdict, dt, what))
            if verdict == "FAIL":
                failed_output.append((suite, out))
            elif verdict == "SKIP":
                skip = re.search(r"^SKIP:.*", out, re.M)
                print("  %-28s        %s" % ("", skip.group(0) if skip else ""))

    print("\n== suites that start their own daemon ==")
    do("own")

    shared = [s for s in suites if s[1] == "shared"]
    if shared:
        print("\n== suites that need a daemon already running ==")
        errlog = open(os.path.join(REPO, ".run_all_daemon.err"), "w+")
        d = subprocess.Popen([os.path.join(REPO, "uictld")], cwd=REPO,
                             stdout=subprocess.DEVNULL, stderr=errlog)
        time.sleep(1.0)
        if d.poll() is not None:
            errlog.seek(0)
            print("  daemon would not start:\n" + errlog.read())
            for suite, _, _ in shared:
                results[suite] = "FAIL"
        else:
            # The runner deliberately does NOT grab on the suites' behalf.
            # It could, for this phase -- but then the same suite run on
            # its own would inject into the live session, and the grab
            # would be a property of how you invoked the tests rather
            # than of the tests. Each suite grabs for itself; check_grabs
            # below is what makes that true rather than intended.
            try:
                do("shared")
            finally:
                d.send_signal(signal.SIGTERM)
                try:
                    d.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    d.kill()
        errlog.seek(0)
        derr = errlog.read()
        errlog.close()
        os.unlink(os.path.join(REPO, ".run_all_daemon.err"))
        # The daemon printing BUG at any point is a failure even if every
        # suite passed -- it is how conn_close reports a held-state
        # invariant it could not honour.
        if "BUG" in derr:
            print("\n  !! the daemon reported a BUG during the run:")
            for line in derr.splitlines():
                if "BUG" in line:
                    print("     " + line)
            results["daemon stderr"] = "FAIL"
        if os.path.exists(SOCK):
            print("\n  !! the socket outlived the daemon: %s" % SOCK)
            results["socket cleanup"] = "FAIL"

    print("\n== matrix ==")
    for cell, suite in MATRIX:
        verdict = results.get(suite, "not run")
        print("  %-24s %-28s %s" % (cell, suite, verdict))

    for suite, out in failed_output:
        print("\n== %s ==" % suite)
        for line in out.splitlines():
            if line.startswith("FAIL") or line.startswith("Traceback"):
                print("  " + line)

    npass = sum(1 for v in results.values() if v == "PASS")
    nskip = sum(1 for v in results.values() if v == "SKIP")
    nfail = sum(1 for v in results.values() if v == "FAIL")
    print("\n%d passed, %d skipped, %d failed" % (npass, nskip, nfail))
    return 1 if nfail else 0


if __name__ == "__main__":
    sys.exit(main())
