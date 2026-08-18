#!/usr/bin/env python3
"""Seed fuzz/corpus from vectors.json — WIRE.md §9's vectors, machine-readable.

Real frames, not random bytes. A fuzzer starting from nothing spends its
early campaign discovering that a 16-byte header exists and that
payload_len has a bound; starting from the vectors it reaches the opcode
handlers on the first run, which is where the interesting state lives.

The negative vectors (N*) are seeded too, and deliberately: they are the
inputs the daemon must reject, so they sit exactly on the boundary the
fuzzer wants to explore from.

This used to scrape the hex dumps out of WIRE.md with a regex. It reads
vectors.json instead, which exists because this file needed it: a
markdown scraper in the fuzz harness was the first evidence that shipping
the vectors as prose made every consumer write a parser. Run
`make vectors.json` if it is missing.
"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
CORPUS = os.path.join(HERE, "corpus")

with open(os.path.join(REPO, "vectors.json")) as f:
    vectors = json.load(f)["vectors"]

os.makedirs(CORPUS, exist_ok=True)
n = 0
for v in vectors:
    with open(os.path.join(CORPUS, v["id"]), "wb") as f:
        f.write(bytes.fromhex(v["bytes"]))
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
