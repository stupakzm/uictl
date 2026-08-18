# uictl

A typed-RPC broker for `/dev/uinput` on Linux. `uictld` holds the kernel
file descriptor; clients ask it to move the pointer and press keys over
an `AF_UNIX` socket, and it decides whether they may.

## Why this exists

`/dev/uinput` is `0660 root:input`. Linux permissions are UID + GID +
mode, so the kernel cannot gate that device per-binary: **every process
running as a user in the `input` group can inject input and read
`/dev/input/event*`.** Adding one program to that group adds all of
them.

The broker is the per-application boundary plain Unix permissions cannot
provide. Take `input` membership away from everything else, leave
`uictld` as the sole holder of the device, and every injection request
becomes something a policy can see: rate-limited by client class,
checked against a static destructive-key deny-list and a per-user
allowlist, recorded in an audit log, and — for clients you flag —
answered by a human.

Installing this does not make anything safer on its own. Removing
`input` from everything else is what does.

## What it does not do

It is **output-only**. It writes to `/dev/uinput` and never reads
`/dev/input/event*`, so a compromised broker cannot become a keylogger.
Hotkey and evdev logic belongs in clients. The AppArmor profile in
`apparmor/` enforces that from outside the process.

It has **no network surface**, never `fork`s, never `exec`s, and never
runs as root or with setuid or setcap.

Client names in `~/.config/uictl/clients` are self-asserted, so by
default any process of your uid can claim one. Adding `exe=/abs/path` to
an entry binds that name to a binary, checked against
`/proc/<pid>/exe` at connect time. That raises the cost of claiming a
privileged name from "type it" to "run that program", which is worth
having — but it is checked once, at accept, so treat it as strong
evidence rather than as a capability.

## Building and running

```
make                       # uictl, uictld, uictl-confirm, libuictl.a
sudo usermod -aG input $USER    # log out and back in
./uictld                        # in one terminal
./uictl ping                    # in another  ->  PONG
```

Under systemd, prefer socket activation — the daemon starts on the first
client connection and clients never have to know whether it is running:

```
make install-user
systemctl --user daemon-reload
systemctl --user enable --now uictld.socket
```

Enable the **socket**, not the service.

Nothing types anything until you say so: the keycode allowlist at
`~/.config/uictl/policy` is strict default-deny, so a fresh install
refuses every key. One keycode or `lo-hi` range per line, mode 0600.

## The protocol is the deliverable

**[`WIRE.md`](WIRE.md) is the normative specification** — framing,
handshake, every opcode, every result code, connection lifecycle, and
byte-exact conformance vectors generated from the headers the daemon
compiles against. A client in any language can be written from it
without linking anything.

`proto.json` is the same contract, machine-readable, for code
generators and for LLM tool definitions.

`libuictl` is a convenience for C clients, not the contract. It never
prints, never replays a request whose outcome is unknown, and makes a
reconnect visible to its caller — see `src/lib/uictl.h`.

## Layout

| | |
|---|---|
| `src/uictld.c` | the daemon: socket, policy, audit, held state |
| `src/platform/` | the only place kernel headers appear |
| `src/lib/` | `libuictl` |
| `src/uictl.c` | the CLI, and the library's first consumer |
| `src/uictl-confirm.c` | the human-in-the-loop prompter |
| `tests/` | 27 suites; `python3 tests/run_all.py` |
| `fuzz/` | libFuzzer harness over the real frame path |
| `systemd/`, `apparmor/`, `packaging/` | deployment |

**The test suites inject into your live session.** They grab both event
nodes with `EVIOCGRAB` so nothing escapes into your desktop, and
`run_all.py` refuses to start if a suite that touches the device has not
taken the grab. Run them on a machine you are sitting at, not over SSH
into something you care about.

## Prior art

Architecture and protocol shape were informed by studying
[ydotool](https://github.com/ReimuNotMoe/ydotool) (AGPL-3.0) as prior
art, and `ydotool-analysis.md` records what that study found. **No code
was copied.** This is a cleanroom implementation with a different wire
protocol, a policy and audit layer ydotool does not have, and a
permissive licence chosen so that dependent projects are not
contaminated.

## Licence

MIT. See [LICENSE](LICENSE).
