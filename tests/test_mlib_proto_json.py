#!/usr/bin/env python3
"""M-lib 3: proto.json is generated, current, and true.

The schema exists so that three things stop being maintained by hand:
the opcode table a client hardcodes, the op list in the spec, and the
LLM tool definitions auto-c v2.x will build from it. Three hand-kept
copies is three chances to disagree, and the copy that disagrees
silently is the tool definition -- an agent calling a tool whose schema
drifted produces a confidently wrong keystroke.

So the file is worth only as much as the checking around it. Four
independent sources have to agree, and none of them is this suite's own
opinion:

  the generator   layout from src/proto.h via offsetof/sizeof, result
                  classes and hints by CALLING libuictl rather than
                  copying WIRE.md 4.2 a second time
  WIRE.md 9       the conformance vectors, whose bytes say what each
                  payload length really is
  the daemon      its HELLO opcode_bitmap says what it actually
                  implements
  the file        what is committed for consumers who will never build
                  any of the above

Shared mode: needs a running daemon for PD.

PA  the committed proto.json is exactly what the generator emits.
PB  it is valid JSON with the structure a consumer can rely on: unique
    opcode numbers, unique result numbers, known class names.
PC  every fixed payload length in the schema matches the bytes of the
    corresponding vector in WIRE.md 9, and the two variable ones match
    their stated formula.
PD  the daemon's advertised opcode set and the schema's are the same
    set, with the same numbers.
PE  the confirmable flag is exactly "touches the device and is not a
    release" -- it is derived, so a stored copy cannot drift from the
    two flags it is made of.
"""
import json, os, re, socket, struct, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
JSON_PATH = os.path.join(REPO, "proto.json")
WIRE = os.path.join(REPO, "WIRE.md")
SOCK = os.path.join(os.environ["XDG_RUNTIME_DIR"], "uictld.sock")
HDR = "<HHIII"
HDR_SIZE = struct.calcsize(HDR)
CLASSES = {"ok", "terminal", "fixable", "retryable", "client_bug",
           "correctable"}

ok = True


def fail(msg):
    global ok
    ok = False
    print("FAIL: " + msg)


def skip(msg):
    print("SKIP: " + msg)
    sys.exit(0)


# ---- PA: the file is what the generator prints ------------------------

# Compared as text rather than through `git diff`, because git reports
# no difference for a file it is not tracking -- which would turn "the
# schema was never committed" into a pass. The regenerated file is
# restored on a mismatch: a test that quietly fixes the thing it is
# testing leaves nothing for anyone to notice.
before = open(JSON_PATH).read()
b = subprocess.run(["make", "proto.json"], cwd=REPO, capture_output=True,
                   text=True)
if b.returncode != 0:
    fail("PA: make proto.json failed:\n" + b.stderr[-2000:])
    print("\n== FAIL ==")
    sys.exit(1)
after = open(JSON_PATH).read()
if before == after:
    print("PA proto.json is exactly what the generator emits")
else:
    open(JSON_PATH, "w").write(before)
    fail("PA: the committed proto.json differs from the generator's "
         "output (%d vs %d bytes). Regenerate with `make proto.json` and "
         "commit it; never hand-edit it." % (len(before), len(after)))

# ---- PB: structure ----------------------------------------------------

schema = json.load(open(JSON_PATH))
ops = schema["opcodes"]
results = schema["results"]

by_name = {o["name"]: o for o in ops}
values = [o["value"] for o in ops]
rvalues = [r["value"] for r in results]
bad_class = [r["name"] for r in results if r["class"] not in CLASSES]

if len(set(values)) != len(values):
    fail("PB: duplicate opcode numbers: %s" % values)
elif len(set(rvalues)) != len(rvalues):
    fail("PB: duplicate result numbers: %s" % rvalues)
elif bad_class:
    fail("PB: unknown class name on %s" % ", ".join(bad_class))
elif schema["limits"]["max_payload"] != schema["transport"]["max_payload"]:
    fail("PB: max_payload disagrees with itself between transport and limits")
else:
    print("PB %d opcodes, %d results, unique numbering, known classes"
          % (len(ops), len(results)))

# ---- PC: the schema's lengths against WIRE.md 9's bytes ---------------

doc = open(WIRE).read()
body = doc.split("<!-- BEGIN GENERATED VECTORS -->", 1)[1] \
          .split("<!-- END GENERATED VECTORS -->", 1)[0]

vectors = {}
for m in re.finditer(r"^#### ([RSPN]\d+) — .*?\n\n(.*?)```\n(.*?)```",
                     body, re.S | re.M):
    raw = bytearray()
    for line in m.group(3).splitlines():
        for byte in line.split()[1:]:
            raw += bytes([int(byte, 16)])
    vectors[m.group(1)] = bytes(raw)

by_value = {o["value"]: o for o in ops}
checked, mismatch = 0, []
for vid, raw in sorted(vectors.items()):
    if not vid.startswith(("R", "P")) or len(raw) < HDR_SIZE:
        continue        # responses carry a result, not an op payload
    _, opcode, _, _, plen = struct.unpack(HDR, raw[:HDR_SIZE])
    o = by_value.get(opcode)
    if o is None:
        mismatch.append("%s: opcode %d is not in the schema" % (vid, opcode))
        continue
    if o["payload_len"] is None:
        # 4 + N * count, with count the first u16 of the payload
        count = struct.unpack("<H", raw[HDR_SIZE:HDR_SIZE + 2])[0]
        per = int(re.search(r"(\d+) \* count", o["payload_formula"]).group(1))
        base = int(re.search(r"^(\d+) \+", o["payload_formula"]).group(1))
        expect = base + per * count
    else:
        expect = o["payload_len"]
    if plen != expect:
        mismatch.append("%s (%s): vector says payload_len=%d, schema says %d"
                        % (vid, o["name"], plen, expect))
    checked += 1

if mismatch:
    fail("PC: " + "; ".join(mismatch))
else:
    print("PC %d vectors in WIRE.md 9 agree with the schema's payload "
          "lengths" % checked)

# ---- PD: the daemon's advertised set ----------------------------------

if not os.path.exists(SOCK):
    skip("no daemon at %s (PD is shared-mode)" % SOCK)

try:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect(SOCK)
except OSError as e:
    skip("cannot reach the daemon: %s" % e)

payload = struct.pack("<HH", 1, 1) + b"schema".ljust(32, b"\0")
s.sendall(struct.pack(HDR, 1, by_name["HELLO"]["value"], 1, 1,
                      len(payload)) + payload)
head = s.recv(HDR_SIZE)
_, _, _, _, plen = struct.unpack(HDR, head)
body_bytes = b""
while len(body_bytes) < plen:
    body_bytes += s.recv(plen - len(body_bytes))
s.close()

result = struct.unpack("<H", body_bytes[:2])[0]
if result != 0:
    fail("PD: the handshake was refused with result=%d" % result)
else:
    bitmap = struct.unpack("<Q", body_bytes[10:18])[0]
    advertised = {v for v in range(64) if bitmap & (1 << v)}
    scheduled = set(values)
    if advertised != scheduled:
        fail("PD: the daemon advertises %s and the schema lists %s"
             % (sorted(advertised), sorted(scheduled)))
    else:
        print("PD the daemon advertises exactly the %d opcodes the schema "
              "lists" % len(advertised))

# ---- PE: confirmable is derived, not stored ---------------------------

wrong = [o["name"] for o in ops
         if o["confirmable"] != (o["touches_device"] and not o["is_release"])]
if wrong:
    fail("PE: confirmable disagrees with touches_device/is_release on %s"
         % ", ".join(wrong))
else:
    n = sum(1 for o in ops if o["confirmable"])
    print("PE confirmable is derived from touches_device and is_release "
          "(%d of %d opcodes)" % (n, len(ops)))

print("\n== PASS ==" if ok else "\n== FAIL ==")
sys.exit(0 if ok else 1)
