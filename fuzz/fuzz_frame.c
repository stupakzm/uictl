/* fuzz_frame — the request decoder, fuzzed (M8, closes analysis §B3).
 *
 * WHAT IS BEING FUZZED, AND WHY IT IS THE REAL THING. This harness
 * #includes src/uictld.c rather than reimplementing its parser. The
 * plan called the decoder "a pure function bytes -> uictl_req", and it
 * is not one: validation is spread across conn_readable's framing and
 * conn_handle_frame's per-opcode cases, entangled with the rate limiter,
 * the confirmation gate and the held-state bookkeeping. Extracting a
 * clean copy to fuzz would have produced a second decoder that agrees
 * with itself and proves nothing about the daemon -- the same mistake
 * proto.json avoids by calling libuictl instead of copying WIRE.md §4.2.
 *
 * So the harness includes the translation unit, which makes its static
 * functions reachable, and drives the actual frame path. `main` is
 * renamed away because libFuzzer supplies its own.
 *
 * NOTHING IS INJECTED. Both device fds point at /dev/null, so every
 * uinput write succeeds and reaches nothing. That is what makes this
 * safe to run on a desktop and safe to run in CI, where there is no
 * /dev/uinput at all.
 *
 * A SINGLE INPUT IS A SEQUENCE OF FRAMES, not one frame. The interesting
 * bugs in this daemon are not in decoding one header -- they are in the
 * state a frame leaves behind: a HELLO that pins a version, a KEY_DOWN
 * that records a hold, a CONFIRM_SUBSCRIBE that makes this connection
 * the confirmer. Feeding one frame per input would leave every one of
 * those unreachable. So the input is chopped into frames and replayed
 * into one fresh connection.
 *
 * Determinism is preserved by resetting everything global that would
 * otherwise leak between inputs -- see reset_daemon_state(). The rate
 * limiter is the one that matters most: leave it accumulating and the
 * fuzzer spends the whole campaign getting ERR_RATE_LIMITED, which is
 * one branch.
 *
 * Build:
 *   make fuzz          # clang, libFuzzer + ASan + UBSan
 *   ./fuzz-frame corpus/ -runs=100000
 *   make fuzz-frame-repro   # any compiler, replays files as arguments
 *   ./fuzz-frame-repro crash-abc123
 */
#define main uictld_main_not_used
#include "../src/uictld.c"
#undef main

#include <fcntl.h>

static int fuzz_ready;
static int fuzz_devnull = -1;
static int fuzz_epfd = -1;
static struct uinput_devs fuzz_devs;

static void fuzz_setup(void) {
  fuzz_devnull = open("/dev/null", O_RDWR | O_CLOEXEC);
  if (fuzz_devnull < 0)
    abort();
  /* An epoll set the daemon can add to and remove from. The confirmation
     path calls conn_update_events(), which needs a real epfd; nothing
     ever waits on it here. */
  fuzz_epfd = epoll_create1(EPOLL_CLOEXEC);
  if (fuzz_epfd < 0)
    abort();
  fuzz_devs.pointer = fuzz_devnull;
  fuzz_devs.keyboard = fuzz_devnull;
  /* The device is reported as fully capable so the HELLO response and
     the opcode gates behave as they do in production. */
  g_device_caps = CAP_POINTER_ABS | CAP_KEYBOARD | CAP_POINTER_REL |
                  CAP_BUTTONS;
}

/* Everything global that survives a connection, reset between inputs.
   Without this the fuzzer is non-deterministic: the same input replays
   differently depending on what ran before it, and a crash cannot be
   reproduced from the file libFuzzer writes out. */
static void reset_daemon_state(void) {
  conn_table_init();
  memset(&pending_confirm, 0, sizeof(pending_confirm));
  memset(rate_buckets, 0, sizeof(rate_buckets));
  rate_global.used = 1;
  rate_global.pid = 0;
  rate_global.milli = RATE_GLOBAL_BURST * RATE_UNIT;
  rate_global.last_ms = 0;
  memset(motion_accs, 0, sizeof(motion_accs));
  memset(attempt_slots, 0, sizeof(attempt_slots));
}

/* One connection, owned by this input, standing in for one that
   accept4() would have produced. cred is fabricated: SO_PEERCRED is the
   kernel's word and cannot be fuzzed through the socket, so pinning it
   here keeps the peer-identity paths on their real branch instead of
   spending the campaign on a uid mismatch. */
static struct conn *fuzz_conn(void) {
  struct ucred cred;
  memset(&cred, 0, sizeof(cred));
  cred.pid = getpid();
  cred.uid = getuid();
  cred.gid = getgid();
  return conn_alloc(fuzz_devnull, &cred);
}

static void run_one(const uint8_t *data, size_t size) {
  reset_daemon_state();
  struct conn *c = fuzz_conn();
  if (!c)
    return;

  size_t off = 0;
  /* A bound on frames per input. Without it a 4 KB input of PINGs is
     4000 dispatches and the campaign crawls; the state depth that
     actually finds bugs is a handful of frames, not thousands. */
  for (int frame = 0; frame < 64; frame++) {
    if (size - off < HDR_SIZE)
      break;
    memcpy(c->buf, data + off, HDR_SIZE);
    decode_frame_header(c->buf, &c->hdr);
    off += HDR_SIZE;

    /* The two checks conn_readable makes before it will read a payload
       at all. Replicated rather than skipped: they are the bounds that
       keep payload_len from being used as a length into a 4 KB buffer,
       and a harness that bypassed them would be fuzzing a daemon that
       does not exist. */
    if (!conn_version_ok(c, c->hdr.version, c->hdr.opcode))
      break;
    if (c->hdr.payload_len > UICTL_MAX_PAYLOAD)
      break;

    /* Take the payload from the stream, short-changed if the input ends
       early. payload_len is then corrected to what is really there --
       the kernel would have delivered exactly that many bytes before
       conn_readable dispatched, so a frame claiming more than the stream
       holds is a truncated stream, not a short payload. */
    size_t avail = size - off;
    size_t want = c->hdr.payload_len;
    if (want > avail)
      break;
    if (want > sizeof(c->buf))
      break;
    memcpy(c->buf, data + off, want);
    off += want;

    c->phase = CONN_WANT_PAYLOAD;
    c->have = want;
    c->want = want;

    conn_handle_frame(fuzz_epfd, c, &fuzz_devs, fuzz_devnull, 0);

    c->phase = CONN_WANT_HEADER;
    c->have = 0;
    c->want = HDR_SIZE;
    c->out_len = 0;
    c->out_sent = 0;

    /* A parked request stops the connection being read (WIRE.md §7), so
       continuing to feed it would be feeding a connection the daemon
       has muted. Stop, exactly as the daemon would. */
    if (c->awaiting_confirm)
      break;
  }

  /* The teardown a real disconnect performs, so the held-key release
     path is exercised on every input rather than never. */
  conn_close(fuzz_epfd, c, &fuzz_devs, fuzz_devnull);
}

#ifdef UICTL_FUZZ_STANDALONE
/* Reproducer: replays each file named on the command line. Builds with
   any compiler, which matters because the machine that hits a crash in
   CI is not always the machine with clang on it. */
int main(int argc, char **argv) {
  fuzz_setup();
  for (int i = 1; i < argc; i++) {
    FILE *f = fopen(argv[i], "rb");
    if (!f) {
      perror(argv[i]);
      return 1;
    }
    static uint8_t buf[1 << 16];
    size_t n = fread(buf, 1, sizeof(buf), f);
    fclose(f);
    fprintf(stderr, "replaying %s (%zu bytes)\n", argv[i], n);
    run_one(buf, n);
  }
  fprintf(stderr, "done, no crash\n");
  return 0;
}
#else
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (!fuzz_ready) {
    fuzz_setup();
    fuzz_ready = 1;
  }
  run_one(data, size);
  return 0;
}
#endif
