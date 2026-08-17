"""The advertised opcode set, in one place.

Four suites assert that `opcode_bitmap` is exactly the implemented set,
and each one used to carry its own copy of the expression. Every
milestone that added an opcode therefore broke four tests in the same
way, and the fix was four identical edits -- which is the shape of a
check that eventually gets "fixed" by loosening it to a subset test.

The exact-match assertion is worth keeping: the bitmap is the contract
clients gate on, and unintended drift in it should fail loudly. So the
expectation moves here instead, and updating it is one edit that every
suite sees.

Kept in sync with src/proto.h by hand -- deliberately. A test that
derived its expectation from the header would agree with the daemon
however wrong both were.
"""

OPCODES = {
    "OP_INVALID": 0,
    "OP_PING": 1,
    "OP_MOVE_ABS": 2,
    "OP_HELLO": 3,
    "OP_KEY_TAP": 4,
    "OP_KEY_SEQUENCE": 5,
    "OP_KEY_DOWN": 6,
    "OP_KEY_UP": 7,
    "OP_CONFIRM_SUBSCRIBE": 8,
    "OP_CONFIRM_REQUEST": 9,
    "OP_CONFIRM_DECIDE": 10,
    "OP_BUTTON": 11,
    "OP_MOVE_REL": 12,
    "OP_SCROLL": 13,
    "OP_BATCH": 14,
}

# Every opcode the daemon implements. OP_INVALID is never advertised;
# OP_CONFIRM_REQUEST is, even though no client sends it, because the bit
# means "this daemon speaks that frame" and a confirmer needs to know the
# daemon can push before it subscribes and waits forever.
ADVERTISED = [n for n in OPCODES if n != "OP_INVALID"]

EXPECTED_BITMAP = 0
for _n in ADVERTISED:
    EXPECTED_BITMAP |= 1 << OPCODES[_n]


def describe(bitmap):
    """Name the bits that differ from what is expected."""
    got, want = set(), set()
    for name, num in OPCODES.items():
        if bitmap & (1 << num):
            got.add(name)
        if EXPECTED_BITMAP & (1 << num):
            want.add(name)
    extra = sorted(got - want)
    missing = sorted(want - got)
    unknown = [i for i in range(64)
               if (bitmap & (1 << i)) and i not in OPCODES.values()]
    parts = []
    if missing:
        parts.append("missing " + ",".join(missing))
    if extra:
        parts.append("unexpected " + ",".join(extra))
    if unknown:
        parts.append("unknown bits " + ",".join(str(i) for i in unknown))
    return "; ".join(parts) or "matches"


# ---- the only key range a suite may inject ---------------------------
# The suites inject for real, into the live session. This is the range
# that is safe to do it with, in one place, because getting it wrong is
# not a failing test -- it is the developer's desktop reacting.
#
# 183-194 is KEY_F13..KEY_F24, which xkeyboard-config maps to X keycodes
# 191-202 (<FK13>..<FK24>) and which no desktop binds by default.
#
# DO NOT extend this to 195-199 on the grounds that the kernel header
# leaves them unassigned. It does, and they are still not free: the X
# keycode is the Linux keycode + 8, and
# /usr/share/X11/xkb/keycodes/evdev assigns 203-207 to <LVL5>, <ALT>,
# <META>, <SUPR>, <HYPR>. Linux 198 is therefore Super -- injecting it
# opens the launcher or overview and whatever window then takes focus
# receives the rest of the run -- and Linux 195 is a level-5 shift that
# silently changes what every subsequent key produces. Both sat in a
# suite's policy file until 2026-08-17 under a comment asserting they
# were unbound, and both were observed doing exactly this.
#
# Anything outside this range belongs in a deny-list assertion, where
# the point is that the daemon refuses it and nothing reaches the
# device. Never in a policy file.
SAFE_KEY_MIN, SAFE_KEY_MAX = 183, 194
SAFE_POLICY = "%d-%d\n" % (SAFE_KEY_MIN, SAFE_KEY_MAX)


# ---- device nodes (M5.5 split the one device into two) ---------------
# Key events moved to "uictl virtual keyboard"; the pointer keeps its
# name (M3 decision 1: compositors key per-device config off it, so it
# must never be renamed). Suites that read key events off the pointer
# node used to work by accident and now find nothing there, which is the
# split being real rather than a test bug.
import re as _re

DEVICES = "/proc/bus/input/devices"
POINTER_NAME = "uictl virtual pointer"
KEYBOARD_NAME = "uictl virtual keyboard"


def event_node(name):
    """/dev/input/eventN for a uictl device, or None."""
    try:
        blob = open(DEVICES).read()
    except OSError:
        return None
    for chunk in blob.split("\n\n"):
        if 'Name="%s"' % name in chunk:
            m = _re.search(r"Handlers=.*?(event\d+)", chunk)
            if m:
                return "/dev/input/" + m.group(1)
    return None


def keyboard_node():
    return event_node(KEYBOARD_NAME)


def pointer_node():
    return event_node(POINTER_NAME)
