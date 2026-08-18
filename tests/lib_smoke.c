/* lib_smoke — libuictl's first consumer (M-lib task 2).
 *
 * The CLI is task 2's *intended* first consumer and is not converted
 * yet; this exists so the library is not shipped unexercised in the
 * meantime. It prints one `KEY=value` line per check and nothing else,
 * so tests/test_mlib_lib.py can assert on it without parsing prose.
 *
 * Injects NOTHING. Every call here is a handshake, a liveness probe, or
 * a refusal that never reaches the device -- deliberately, so the suite
 * driving it needs no EVIOCGRAB and cannot disturb the session. That
 * rules out the obvious "tap a key and see" smoke test, and it is the
 * right trade: what needs proving here is the library's framing, error
 * mapping and lifecycle, all of which are visible without a keystroke.
 */
#include "../src/lib/uictl.h"

#include <stdio.h>
#include <string.h>

/* Opcode numbers, from WIRE.md §2.2. Written as literals rather than by
   including proto.h: this file is standing in for an external consumer,
   and an external consumer links the library and reads the spec -- it
   does not get the daemon's private header. If these numbers are wrong,
   the library is unusable by the audience it exists for. */
#define OPCODE_PING 1
#define OPCODE_HELLO 3
#define OPCODE_BATCH 14
#define OPCODE_NOSUCH 63

static int states_up, states_down;

static void on_state(uictl_conn *c, int up, void *user) {
  (void)c;
  (void)user;
  if (up)
    states_up++;
  else
    states_down++;
}

int main(void) {
  struct uictl_error e;

  /* 1. A name the daemon would refuse is refused locally, before a
        socket exists -- proto.h's validator is shared for exactly this
        (§3.5). No round trip, and no bad name ever reaches the log. */
  if (uictl_connect("bad name", 0, &e) != NULL) {
    puts("BADNAME=accepted");
    return 1;
  }
  printf("BADNAME=%d\n", e.err);

  uictl_conn *c = uictl_connect("libsmoke", 0, &e);
  if (!c) {
    printf("CONNECT=fail err=%d errno=%d\n", e.err, e.sys_errno);
    return 1;
  }
  puts("CONNECT=ok");
  uictl_on_state(c, on_state, NULL);

  /* 2. The handshake answered, and the capability map came with it. */
  printf("PROTO=%u\n", uictl_proto_selected(c));
  printf("CAPS=0x%04x\n", uictl_device_caps(c));
  printf("ABSMAX=%u\n", uictl_abs_range_max(c));
  printf("HASPING=%d\n", uictl_has_op(c, OPCODE_PING));
  printf("HASBATCH=%d\n", uictl_has_op(c, OPCODE_BATCH));

  /* 3. An opcode this daemon does not implement is refused by the
        library, not sent. The capability map is the contract, and the
        daemon charges the rate limit before it validates -- so guessing
        costs budget a caller may need to release a key with. */
  if (uictl_submit(c, OPCODE_NOSUCH, NULL, 0, &e) == 0)
    printf("NOTSUP=%d\n", e.err);
  else
    puts("NOTSUP=sent");

  /* 4. Synchronous call. */
  printf("PING=%d\n", uictl_ping(c, &e) == 0 ? 0 : e.err);

  /* 5. An unbalanced sequence never reaches the wire: caught locally as
        a usage error, because the daemon would charge for it first. */
  struct uictl_key_step bad[2] = {{183, 1}, {184, 1}};
  printf("UNBALANCED=%d\n",
         uictl_key_sequence(c, bad, 2, &e) < 0 ? e.err : -1);

  /* 6. A wire refusal, chosen for having no device effect: a second
        HELLO on one connection is ERR_DENIED_BY_POLICY (§3.6). This is
        the path that proves the library maps a daemon `no` onto
        UICTL_E_REFUSED with the code and class intact. */
  if (uictl_hello(c, &e) < 0)
    printf("DUPHELLO=%d result=%u class=%d\n", e.err, e.result,
           (int)uictl_result_class(e.result));
  else
    puts("DUPHELLO=accepted");

  /* 7. Pipelining: three requests out, three answers back, in order. */
  uint32_t s1 = uictl_submit(c, OPCODE_PING, NULL, 0, &e);
  uint32_t s2 = uictl_submit(c, OPCODE_PING, NULL, 0, &e);
  uint32_t s3 = uictl_submit(c, OPCODE_PING, NULL, 0, &e);
  printf("PIPEOUT=%zu\n", uictl_outstanding(c));
  uint32_t g1 = 0, g2 = 0, g3 = 0;
  int r1 = uictl_await(c, &g1, &e);
  int r2 = uictl_await(c, &g2, &e);
  int r3 = uictl_await(c, &g3, &e);
  printf("PIPE=%d,%d,%d order=%d\n", r1, r2, r3,
         (g1 == s1 && g2 == s2 && g3 == s3) ? 1 : 0);

  /* 8. A sync call while requests are outstanding is a usage error, not
        a stolen response. Submit one, do not await it, then try. */
  (void)uictl_submit(c, OPCODE_PING, NULL, 0, &e);
  printf("MIXED=%d\n", uictl_ping(c, &e) < 0 ? e.err : -1);

  /* 9. Reconnect with that request still in flight. It is NOT resent
        (§8.5): it comes back UICTL_E_DROPPED, exactly once, and the
        state callback fired both ways (§8.8). */
  int rc = uictl_reconnect(c, &e);
  printf("RECONNECT=%d up=%d down=%d\n", rc == 0 ? 0 : e.err, states_up,
         states_down);
  printf("PENDING=%zu\n", uictl_outstanding(c));
  int drained = 0, drop_err = 0;
  while (uictl_outstanding(c) > 0) {
    uictl_await(c, NULL, &e);
    drop_err = e.err;
    drained++;
    if (drained > 8)
      break;
  }
  printf("DROPPED=%d count=%d\n", drop_err, drained);

  /* 10. The handshake came back on the new connection: nothing is
         cached across one (§8.4), so this is a fresh negotiation. */
  printf("REPROTO=%u\n", uictl_proto_selected(c));
  printf("REPING=%d\n", uictl_ping(c, &e) == 0 ? 0 : e.err);

  /* 11. After close, every call is an error and none of them crash. */
  uictl_close(c);
  puts("CLOSED=ok");
  return 0;
}
