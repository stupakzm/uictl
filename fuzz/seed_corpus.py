#!/usr/bin/env python3
"""Seed fuzz/corpus from WIRE.md §9's conformance vectors.

Real frames, not random bytes. A fuzzer starting from nothing spends its
early campaign discovering that a 16-byte header exists and that
payload_len has a bound; starting from the vectors it reaches the opcode
handlers on the first run, which is where the interesting state lives.

The negative vectors (N*) are seeded too, and deliberately: they are the
inputs the daemon must reject, so they sit exactly on the boundary the
fuzzer wants to explore from.
"""
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
CORPUS = os.path.join(HERE, "corpus")

doc = open(os.path.join(REPO, "WIRE.md")).read()
body = doc.split("<!-- BEGIN GENERATED VECTORS -->", 1)[1] \
          .split("<!-- END GENERATED VECTORS -->", 1)[0]

os.makedirs(CORPUS, exist_ok=True)
n = 0
for m in re.finditer(r"^#### ([RSPN]\d+) — .*?\n\n(.*?)```\n(.*?)```",
                     body, re.S | re.M):
    raw = bytearray()
    for line in m.group(3).splitlines():
        for byte in line.split()[1:]:
            raw += bytes([int(byte, 16)])
    open(os.path.join(CORPUS, m.group(1)), "wb").write(bytes(raw))
    n += 1

# One hand-made seed the vectors cannot provide: a HELLO followed by a
# command on the same connection. Every vector is a single frame, and the
# harness's whole point is that an input is a SEQUENCE -- so the corpus
# should contain at least one example of the shape it is meant to
# explore.
hello = open(os.path.join(CORPUS, "R1"), "rb").read()
keytap = open(os.path.join(CORPUS, "R8"), "rb").read()
open(os.path.join(CORPUS, "seq-hello-then-tap"), "wb").write(hello + keytap)
n += 1

print("seeded %d inputs into %s" % (n, CORPUS))
