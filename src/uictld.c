#include "platform/uinput.h"
#include "proto.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h> /* explicit_bzero */
#include <sys/epoll.h>
#include <sys/file.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

/* (the M1 `static volatile sig_atomic_t stop` died with signalfd — the
   loop's own local `stop` is the only one now) */

static const char *opname(uint16_t op) {
  switch (op) {
  case OP_PING:
    return "PING";
  case OP_MOVE_ABS:
    return "MOVE_ABS";
  case OP_HELLO:
    return "HELLO";
  case OP_KEY_SEQUENCE:
    return "KEY_SEQUENCE";
  case OP_KEY_TAP:
    /* Named before it is implemented, on purpose. Until step 5 a
       KEY_TAP frame is refused with ERR_OPCODE_UNKNOWN — and the audit
       line should say *which* opcode was refused. "someone asked for
       KEY_TAP and was turned away" is exactly the kind of intent the
       audit log exists to record; "UNKNOWN" would throw it away. */
    return "KEY_TAP";
  case OP_KEY_DOWN:
    return "KEY_DOWN";
  case OP_KEY_UP:
    return "KEY_UP";
  case OP_CONFIRM_SUBSCRIBE:
    return "CONFIRM_SUBSCRIBE";
  case OP_CONFIRM_REQUEST:
    return "CONFIRM_REQUEST";
  case OP_CONFIRM_DECIDE:
    return "CONFIRM_DECIDE";
  case OP_BUTTON:
    return "BUTTON";
  case OP_MOVE_REL:
    return "MOVE_REL";
  case OP_SCROLL:
    return "SCROLL";
  case OP_BATCH:
    return "BATCH";
  default:
    return "UNKNOWN";
  }
}

/* Create one directory at 0700, reporting the first time it appears.

   Saying so on stderr is not chatter: this is the daemon quietly
   creating something under a user's home, and the one moment that is
   worth a line is the moment it happens. It also tells an operator
   where the audit log and the singleton lock went to live. */
static int mkdir_0700(const char *path, const char *what) {
  if (mkdir(path, 0700) == 0) {
    fprintf(stderr, "uictld: created %s (%s), mode 0700\n", path, what);
    return 0;
  }
  if (errno == EEXIST)
    return 0;
  fprintf(stderr, "uictld: mkdir %s: %s\n", path, strerror(errno));
  return -1;
}

static int prepare_state_dir(char *out, size_t outlen) {
  const char *home = getenv("HOME");
  if (!home) {
    fprintf(stderr, "uictld: HOME not set\n");
    return -1;
  }
  int n = snprintf(out, outlen, "%s/.local/state/uictl", home);
  if (n < 0 || (size_t)n >= outlen) {
    fprintf(stderr, "uictld: state dir path too long\n");
    return -1;
  }

  /* The whole path, not just the leaf. A single mkdir() fails with
     ENOENT on any account that has never had a ~/.local/state -- a fresh
     user, a system account, a test running with HOME in a temp dir --
     and the daemon then refuses to start for a reason that reads like a
     permissions problem. Socket activation (M6) makes this sharper
     still: the first start now happens on somebody's first login, not
     when a developer runs ./uictld by hand.

     It is also the honest fix rather than the convenient one. Eight test
     suites currently create ~/.local/state themselves before starting a
     daemon, which is eight copies of a workaround for this function --
     and a workaround that lives in the callers is a bug that never gets
     found by the callers who are not tests.

     Intermediates are 0700 like the leaf. ~/.local is more usually
     0755, but this daemon's whole posture is that nothing it creates is
     readable by anyone else, and a user who wants it looser can chmod
     it. Creating it tighter than needed is the mistake that is easy to
     undo. */
  char parent[256];
  int p = snprintf(parent, sizeof(parent), "%s/.local", home);
  if (p < 0 || (size_t)p >= sizeof(parent)) {
    fprintf(stderr, "uictld: state dir path too long\n");
    return -1;
  }
  if (mkdir_0700(parent, "XDG base") < 0)
    return -1;
  p = snprintf(parent, sizeof(parent), "%s/.local/state", home);
  if (p < 0 || (size_t)p >= sizeof(parent)) {
    fprintf(stderr, "uictld: state dir path too long\n");
    return -1;
  }
  if (mkdir_0700(parent, "XDG state home") < 0)
    return -1;
  if (mkdir_0700(out, "uictld state: audit log and singleton lock") < 0)
    return -1;
  struct stat st;
  if (stat(out, &st) < 0) {
    perror("uictld: stat state dir");
    return -1;
  }
  if (st.st_uid != getuid()) {
    fprintf(stderr, "uictld: state dir not owned by current uid\n");
    return -1;
  }
  if (st.st_mode & 0077) {
    fprintf(stderr, "uictld: state dir has group/world bits\n");
    return -1;
  }
  return 0;
}

static int open_audit_log(const char *state_dir) {
  char path[256];
  int n = snprintf(path, sizeof(path), "%s/audit.log", state_dir);
  if (n < 0 || (size_t)n >= sizeof(path)) {
    fprintf(stderr, "uictld: audit log path too long\n");
    return -1;
  }
  int fd = open(path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0600);
  if (fd < 0) {
    perror("uictld: open audit.log");
    return -1;
  }
  struct stat st;
  if (fstat(fd, &st) < 0) {
    perror("uictld: fstat audit.log");
    close(fd);
    return -1;
  }
  if (st.st_uid != getuid()) {
    fprintf(stderr, "uictld: audit.log not owned by current uid\n");
    close(fd);
    return -1;
  }
  if (st.st_mode & 0077) {
    fprintf(stderr, "uictld: audit.log has group/world bits\n");
    close(fd);
    return -1;
  }
  return fd;
}

/* ---- client identity (M3.6 task 5) ----------------------------------
   Two halves, and keeping them straight is the whole point:

     pid   — from SO_PEERCRED, filled in by the kernel, unforgeable.
             Already the basis of the per-pid connection cap, and it is
             what a future rate-limit bucket must key on.
     name  — from HELLO, self-asserted, a label. It selects a *class*
             from a local registry the user writes.

   A name is not a credential and never becomes one. What makes the
   scheme worth having is the direction of the default: an unregistered
   name gets the most restrictive class, so asserting a name can only
   ever *raise* privilege by an explicit decision the user already wrote
   down, and asserting nothing (or lying) leaves you at the floor. That
   is strictly better than `source_tag`, where a client picks its own
   tier per frame (G2).

   What this does NOT defend against: every peer is the same uid
   (invariant 9), so a hostile local process can claim "muvor" and get
   muvor's class — it could equally just run the real muvor binary. If
   classes ever need to differ in *trust* rather than in blast radius,
   the answer is option C from the M3.6 notes (per-class socket paths,
   authenticated by filesystem permissions), not a stricter name check. */
enum client_class {
  /* 0 is the floor on purpose: a zeroed struct conn is untrusted, so
     forgetting to assign a class fails closed rather than open. */
  CLASS_UNTRUSTED = 0,
  CLASS_STANDARD,
  CLASS_INTERACTIVE,
  CLASS__COUNT
};

static const char *class_name(enum client_class cl) {
  switch (cl) {
  case CLASS_STANDARD:
    return "standard";
  case CLASS_INTERACTIVE:
    return "interactive";
  case CLASS_UNTRUSTED:
  default:
    return "untrusted";
  }
}

static int class_from_word(const char *word, enum client_class *out) {
  for (enum client_class cl = 0; cl < CLASS__COUNT; cl++) {
    if (strcmp(word, class_name(cl)) == 0) {
      *out = cl;
      return 0;
    }
  }
  return -1;
}

#define MAX_REGISTERED_CLIENTS 16
#define REGISTRY_MAX_BYTES 4096

/* ---- per-binary peer identity (M9) ----------------------------------
   What the kernel will tell us about the program on the other end of the
   socket, as opposed to what that program says about itself.

   THE HONEST FRAMING FIRST. A client name is self-asserted at HELLO
   (WIRE.md §3.5): a hostile process of the same uid can claim any name
   in the registry, which is why §7.0 says confirmation is a speed bump
   in front of a cooperative client rather than a boundary against a
   hostile one. /proc/<pid>/exe is the first identity in this project
   that a client cannot simply declare. It is not a capability either --
   see the race below -- but binding a registry entry to a path means
   claiming a privileged name now requires running the actual binary,
   which is a different and much higher bar than typing its name into a
   HELLO.

   THE RACE, stated rather than hidden. The link is read once, just after
   accept4(), and a process can exec() something else immediately
   afterwards while keeping the connected fd. So the reading describes
   the program that was running at accept time, not necessarily the one
   running now. Two things bound the damage: to become a trusted binary a
   process must exec it, which destroys its own image, and the fd it
   keeps across a later exec was still opened by the trusted program. It
   is a strictly better signal than a name, and it is still evidence
   rather than proof. Anything that must be unforgeable stays with
   SO_PEERCRED, which the kernel fills in and nobody can influence.

   512 bytes, and a longer path FAILS CLOSED rather than being stored
   truncated. A truncated path that then compares equal to a registry
   prefix would be exactly the kind of silent weakening this project
   keeps refusing -- and no real installation path is anywhere near
   this. */
#define UICTL_EXE_MAX 512

/* Reads /proc/<pid>/exe. Returns 0 and fills `out`, or -1 for every
   reason the answer cannot be trusted: the process is gone, /proc is
   mounted with hidepid, the path does not fit, or the executable has
   been replaced or deleted since it started.

   "(deleted)" is refused rather than stripped. The kernel appends it
   when the inode the link named is gone -- a package upgrade, or a
   binary that unlinked itself -- and at that point the path is a
   historical note, not something to compare a policy against. A daemon
   that stripped the suffix and matched anyway would happily bind a
   registry entry to a file that no longer exists. */
static int peer_exe(pid_t pid, char *out, size_t outlen) {
  char link[64];
  int n = snprintf(link, sizeof(link), "/proc/%d/exe", (int)pid);
  if (n < 0 || (size_t)n >= sizeof(link))
    return -1;

  ssize_t r = readlink(link, out, outlen - 1);
  if (r < 0)
    return -1;
  if ((size_t)r >= outlen - 1) /* truncated: fail closed */
    return -1;
  out[r] = '\0';

  static const char deleted[] = " (deleted)";
  size_t len = (size_t)r;
  if (len >= sizeof(deleted) - 1 &&
      strcmp(out + len - (sizeof(deleted) - 1), deleted) == 0)
    return -1;

  /* An exe path that is not absolute cannot have come from a normal
     exec, and comparing it against a registry entry would be comparing
     against something unanchored. */
  if (out[0] != '/')
    return -1;
  return 0;
}

/* Roles are orthogonal to class, and deliberately so (M5). Class answers
   "how fast may this client go"; a role answers "what is this client
   *for*". The LLM agent is untrusted AND needs a human in the loop; a
   confirmer needs no rate tier at all. Folding them into one enum would
   have produced classes like `untrusted-confirm` that multiply with
   every future axis.

   ROLE_CONFIRM   this client's device requests are parked until a human
                  approves them.
   ROLE_CONFIRMER this client may answer those prompts. Config-gated on
                  purpose: without it, any client could subscribe and
                  approve its own requests. */
#define ROLE_CONFIRM (1u << 0)
#define ROLE_CONFIRMER (1u << 1)

/* Defaults when an entry says `reconnect=backoff` with no numbers. 100 ms
   doubling is slow enough not to be a storm and fast enough that a
   socket-activated daemon is back before a user notices. */
#define RECONNECT_DEFAULT_BASE_MS 100
#define RECONNECT_DEFAULT_MAX_TRIES 0 /* unbounded */

struct client_reg {
  char name[UICTL_CLIENT_NAME_MAX];
  enum client_class cl;
  unsigned roles;
  /* WIRE.md §8.6. Advice handed to this client at HELLO, for it to use
     during the *next* outage — which is the only time it can be used, so
     it has to arrive before the outage. The daemon cannot enforce it and
     does not try; §8.7's admission backstop is what actually holds. */
  uint8_t reconnect_mode;
  uint8_t reconnect_max_tries;
  uint16_t reconnect_base_ms;

  /* M9. When set, this name may only be claimed by a peer whose
     /proc/<pid>/exe is exactly this path. Empty means the name is
     claimable by anything, which is the pre-M9 behaviour and stays the
     default -- binding is opt-in per entry, because it is the operator
     who knows where their binaries live. */
  char exe[UICTL_EXE_MAX];
  int has_exe;
};

static struct client_reg registry[MAX_REGISTERED_CLIENTS];
static int registry_len;

/* Read ~/.config/uictl/clients once at startup: one `name class` pair
   per line, `#` comments, blanks ignored.

   Startup and not per-HELLO, deliberately. Re-reading per request would
   put file I/O in the request path and make a client's class depend on
   whatever the file said at that instant — a config edit would take
   effect halfway through a session, for some connections and not
   others. Loaded once, the daemon's policy is whatever it started with,
   which is also what the audit log then means. A reload belongs on
   SIGHUP if it is ever wanted.

   Same ownership posture as the audit log (security rule 4): the file
   decides who gets elevated, so another user being able to write it
   would be the whole game. */
static void load_client_registry(void) {
  const char *home = getenv("HOME");
  if (!home)
    return;

  char path[256];
  int n = snprintf(path, sizeof(path), "%s/.config/uictl/clients", home);
  if (n < 0 || (size_t)n >= sizeof(path))
    return;

  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    if (errno != ENOENT)
      perror("uictld: open client registry");
    fprintf(stderr,
            "uictld: no client registry at %s — every client is '%s'\n", path,
            class_name(CLASS_UNTRUSTED));
    return;
  }

  struct stat st;
  if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) || st.st_uid != getuid() ||
      (st.st_mode & 0077)) {
    fprintf(stderr, "uictld: %s must be a regular file owned by this uid "
                    "with no group/world bits — ignoring it\n",
            path);
    close(fd);
    return;
  }

  char buf[REGISTRY_MAX_BYTES + 1];
  ssize_t got = read_full(fd, buf, REGISTRY_MAX_BYTES);
  close(fd);
  if (got < 0) {
    perror("uictld: read client registry");
    return;
  }
  buf[got] = '\0';

  /* Split lines by hand rather than with strtok_r: strtok collapses
     runs of delimiters, so two consecutive newlines are one separator
     and every blank line silently shifts the reported line number. A
     config error that points at the wrong line is worse than no line
     number at all. */
  int line_no = 0;
  for (char *p = buf; *p;) {
    char *line = p;
    char *eol = strchr(p, '\n');
    if (eol) {
      *eol = '\0';
      p = eol + 1;
    } else {
      p += strlen(p);
    }
    line_no++;

    char *hash = strchr(line, '#');
    if (hash)
      *hash = '\0';

    char *fsave = NULL;
    const char *name = strtok_r(line, " \t\r", &fsave);
    if (!name)
      continue; /* blank or comment-only */
    const char *word = strtok_r(NULL, " \t\r", &fsave);

    if (registry_len == MAX_REGISTERED_CLIENTS) {
      fprintf(stderr, "uictld: client registry line %d: more than %d entries, "
                      "ignoring the rest\n",
              line_no, MAX_REGISTERED_CLIENTS);
      break;
    }

    struct client_reg entry;
    memset(&entry, 0, sizeof(entry));
    size_t len = strlen(name);
    if (len >= sizeof(entry.name)) {
      fprintf(stderr, "uictld: client registry line %d: name too long\n",
              line_no);
      continue;
    }
    memcpy(entry.name, name, len);
    /* Same validation the wire gets. A registry entry that could never
       match a legal HELLO name is a typo, and saying so at startup beats
       silently never matching. */
    if (!uictl_client_name_valid(entry.name)) {
      fprintf(stderr, "uictld: client registry line %d: invalid name\n",
              line_no);
      continue;
    }
    if (!word || class_from_word(word, &entry.cl) < 0) {
      fprintf(stderr,
              "uictld: client registry line %d: expected 'NAME CLASS "
              "[ROLE...]' with CLASS one of untrusted|standard|interactive\n",
              line_no);
      continue;
    }

    /* Trailing role words (M5). An unrecognised one is reported and the
       line is dropped rather than accepted-minus-the-role: a typo'd
       `confrim` would otherwise leave the agent running ungated, which
       is exactly the silent weakening this project keeps refusing. */
    int role_ok = 1;
    for (const char *r = strtok_r(NULL, " \t\r", &fsave); r;
         r = strtok_r(NULL, " \t\r", &fsave)) {
      if (strcmp(r, "confirm") == 0)
        entry.roles |= ROLE_CONFIRM;
      else if (strcmp(r, "confirmer") == 0)
        entry.roles |= ROLE_CONFIRMER;
      else if (strncmp(r, "exe=", 4) == 0) {
        /* exe=/absolute/path (M9). Binds this name to one binary.
           Absolute only: a relative path would be compared against
           whatever /proc reports, which is always absolute, so it could
           never match -- and a rule that can never match is a rule an
           operator believes is protecting them. */
        const char *v = r + 4;
        size_t vlen = strlen(v);
        if (v[0] != '/' || vlen == 0 || vlen >= sizeof(entry.exe)) {
          fprintf(stderr,
                  "uictld: client registry line %d: exe= needs an absolute "
                  "path under %zu characters\n",
                  line_no, sizeof(entry.exe));
          role_ok = 0;
          break;
        }
        memcpy(entry.exe, v, vlen + 1);
        entry.has_exe = 1;
      } else if (strncmp(r, "reconnect=", 10) == 0) {
        /* reconnect=never
           reconnect=backoff
           reconnect=backoff:BASE_MS
           reconnect=backoff:BASE_MS:MAX_TRIES

           Parsed here rather than at HELLO for the same reason the class
           is: config read once at startup means a client's advice cannot
           change halfway through a session depending on when it
           connected. */
        const char *v = r + 10;
        if (strcmp(v, "never") == 0) {
          entry.reconnect_mode = (uint8_t)RECONNECT_NEVER;
        } else if (strncmp(v, "backoff", 7) == 0 &&
                   (v[7] == '\0' || v[7] == ':')) {
          entry.reconnect_mode = (uint8_t)RECONNECT_BACKOFF;
          entry.reconnect_base_ms = RECONNECT_DEFAULT_BASE_MS;
          entry.reconnect_max_tries = RECONNECT_DEFAULT_MAX_TRIES;
          if (v[7] == ':') {
            char *end = NULL;
            long base = strtol(v + 8, &end, 10);
            /* Bounded by the field, not just by taste: reconnect_base_ms
               is a uint16_t, and a value that does not fit would be
               silently truncated into a much more aggressive retry than
               the operator asked for. */
            if (end == v + 8 || base < 1 || base > 65535) {
              fprintf(stderr,
                      "uictld: client registry line %d: reconnect base ms "
                      "must be 1..65535 — dropping the whole entry\n",
                      line_no);
              role_ok = 0;
              break;
            }
            entry.reconnect_base_ms = (uint16_t)base;
            if (*end == ':') {
              const char *t = end + 1;
              long tries = strtol(t, &end, 10);
              if (end == t || *end != '\0' || tries < 0 || tries > 255) {
                fprintf(stderr,
                        "uictld: client registry line %d: reconnect max "
                        "tries must be 0..255 — dropping the whole entry\n",
                        line_no);
                role_ok = 0;
                break;
              }
              entry.reconnect_max_tries = (uint8_t)tries;
            } else if (*end != '\0') {
              fprintf(stderr,
                      "uictld: client registry line %d: trailing junk in "
                      "'%s' — dropping the whole entry\n",
                      line_no, r);
              role_ok = 0;
              break;
            }
          }
        } else {
          fprintf(stderr,
                  "uictld: client registry line %d: bad reconnect '%s' "
                  "(expected never|backoff[:BASE_MS[:MAX_TRIES]]) — "
                  "dropping the whole entry\n",
                  line_no, v);
          role_ok = 0;
          break;
        }
      } else {
        fprintf(stderr,
                "uictld: client registry line %d: unknown role '%s' "
                "(expected confirm|confirmer|exe=|reconnect=…) — dropping the "
                "whole entry\n",
                line_no, r);
        role_ok = 0;
        break;
      }
    }
    if (!role_ok)
      continue;

    registry[registry_len++] = entry;
    char rc[64] = "";
    if (entry.reconnect_mode == RECONNECT_NEVER)
      snprintf(rc, sizeof(rc), " +reconnect=never");
    else if (entry.reconnect_mode == RECONNECT_BACKOFF) {
      if (entry.reconnect_max_tries)
        snprintf(rc, sizeof(rc), " +reconnect=backoff:%ums:%u tries",
                 entry.reconnect_base_ms, entry.reconnect_max_tries);
      else
        snprintf(rc, sizeof(rc), " +reconnect=backoff:%ums:unbounded",
                 entry.reconnect_base_ms);
    }
    fprintf(stderr, "uictld: client '%s' registered as '%s'%s%s%s\n",
            entry.name, class_name(entry.cl),
            (entry.roles & ROLE_CONFIRM) ? " +confirm" : "",
            (entry.roles & ROLE_CONFIRMER) ? " +confirmer" : "", rc);
    /* On its own line because it is a path and paths are long. Printed
       at startup rather than only on a denial: an operator who has bound
       a name wants to see, once, that the daemon read the path they
       meant -- not to discover a typo the first time the client is
       refused. */
    if (entry.has_exe)
      fprintf(stderr, "uictld:   bound to %s\n", entry.exe);
  }
}

/* ---- key allowlist (M4 step 8) --------------------------------------
   The default-deny half of the keyboard policy. A keycode must pass BOTH
   lists to be injected:

     deny-list   static, in the platform layer, destructive keys. Cannot
                 be overridden by configuration — that is the point of it
                 being static.
     allowlist   this. Per-user, from ~/.config/uictl/policy. Absent,
                 empty, or unreadable means **no keys at all**.

   Strict by choice (user's call, 2026-08-16). "Absent file means the
   deny-list alone governs" would be friendlier and weaker: a fresh
   install, or a typo'd path, would silently grant every non-destructive
   key on the keyboard. Default-deny means the failure mode of a missing
   or misspelled config is "nothing works", which is loud, safe, and
   fixable — the opposite of a security hole you never notice.

   A bitset rather than ranges: lookups happen per request, the whole
   keyspace is 768 bits (96 bytes), and unlike the deny-list this table
   is built from user input where "one entry shadows another" would be a
   real hazard. Set-membership has no ordering to get wrong. */
#define ALLOW_BITS_BYTES ((UINPUT_KEY_CODE_MAX / 8) + 1)
static unsigned char key_allow_bits[ALLOW_BITS_BYTES];
static int key_allow_count;

static void key_allow_set(uint16_t code) {
  if (code <= UINPUT_KEY_CODE_MAX &&
      !(key_allow_bits[code / 8] & (1u << (code % 8)))) {
    key_allow_bits[code / 8] |= (unsigned char)(1u << (code % 8));
    key_allow_count++;
  }
}

static int key_allowed(uint16_t code) {
  if (code > UINPUT_KEY_CODE_MAX)
    return 0;
  return (key_allow_bits[code / 8] & (1u << (code % 8))) != 0;
}

/* Parse `lo` or `lo-hi`. Returns 0 on success. Rejects anything the
   keyspace cannot hold, so a typo becomes a reported line rather than a
   silently empty range. */
static int parse_key_range(const char *tok, unsigned *lo, unsigned *hi) {
  char *end;
  errno = 0;
  unsigned long a = strtoul(tok, &end, 10);
  if (errno != 0 || end == tok)
    return -1;
  unsigned long b = a;
  if (*end == '-') {
    const char *p = end + 1;
    errno = 0;
    b = strtoul(p, &end, 10);
    if (errno != 0 || end == p)
      return -1;
  }
  if (*end != '\0')
    return -1;
  if (a < 1 || b < a || b > UINPUT_KEY_CODE_MAX)
    return -1;
  *lo = (unsigned)a;
  *hi = (unsigned)b;
  return 0;
}

/* Read ~/.config/uictl/policy: one keycode or `lo-hi` range per line,
   `#` comments, blanks ignored. Same ownership posture as the audit log
   and the client registry — this file decides what may be typed into the
   user's session, so another user being able to write it would be the
   whole game.

   Loaded once at startup, like the client registry, and for the same
   reason: policy that changes mid-session is policy nobody can audit
   afterwards. */
static void load_key_policy(void) {
  const char *home = getenv("HOME");
  char path[256];
  if (!home)
    return;
  int n = snprintf(path, sizeof(path), "%s/.config/uictl/policy", home);
  if (n < 0 || (size_t)n >= sizeof(path))
    return;

  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    if (errno != ENOENT)
      perror("uictld: open key policy");
    fprintf(stderr,
            "uictld: no key policy at %s — ALL key injection will be "
            "refused (default-deny)\n",
            path);
    return;
  }

  struct stat st;
  if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) || st.st_uid != getuid() ||
      (st.st_mode & 0077)) {
    /* Ignored entirely, not partially honoured — and under default-deny
       that means no keys, which is the safe direction to fail. */
    fprintf(stderr,
            "uictld: %s must be a regular file owned by this uid with no "
            "group/world bits — ignoring it, ALL key injection refused\n",
            path);
    close(fd);
    return;
  }

  char buf[REGISTRY_MAX_BYTES + 1];
  ssize_t got = read_full(fd, buf, REGISTRY_MAX_BYTES);
  close(fd);
  if (got < 0) {
    perror("uictld: read key policy");
    return;
  }
  buf[got] = '\0';

  int line_no = 0, shadowed = 0;
  uint16_t first_shadowed = 0;
  /* By hand, not strtok_r: it collapses blank lines and would misreport
     every line number after the first empty one. Same fix as the client
     registry loader. */
  for (char *p = buf; *p;) {
    char *line = p;
    char *eol = strchr(p, '\n');
    if (eol) {
      *eol = '\0';
      p = eol + 1;
    } else {
      p += strlen(p);
    }
    line_no++;

    char *hash = strchr(line, '#');
    if (hash)
      *hash = '\0';

    char *save = NULL;
    for (const char *tok = strtok_r(line, " \t\r", &save); tok;
         tok = strtok_r(NULL, " \t\r", &save)) {
      unsigned lo, hi;
      if (parse_key_range(tok, &lo, &hi) < 0) {
        fprintf(stderr,
                "uictld: key policy line %d: '%s' is not a keycode or "
                "lo-hi range within 1..%d\n",
                line_no, tok, UINPUT_KEY_CODE_MAX);
        continue;
      }
      for (unsigned code = lo; code <= hi; code++) {
        /* Telling the user their entry is dead is worth four lines: an
           allowlist entry the deny-list overrides looks like it works
           until the day someone needs it. The deny-list wins — it is
           static precisely so config cannot unlock it. */
        if (uinput_keycode_denied((uint16_t)code, NULL)) {
          if (!shadowed)
            first_shadowed = (uint16_t)code;
          shadowed++;
          continue;
        }
        key_allow_set((uint16_t)code);
      }
    }
  }

  if (shadowed)
    fprintf(stderr,
            "uictld: key policy: %d allowed code(s) are on the static "
            "deny-list and stay denied (first: %u)\n",
            shadowed, first_shadowed);
  fprintf(stderr, "uictld: key policy: %d keycode(s) allowed\n",
          key_allow_count);
}

/* Unregistered name -> the floor. Default-deny, same posture M4's
   keyboard allowlist takes. */
static enum client_class class_for_name(const char *name) {
  for (int i = 0; i < registry_len; i++)
    if (strcmp(registry[i].name, name) == 0)
      return registry[i].cl;
  return CLASS_UNTRUSTED;
}

/* The registry entry, or NULL for an unregistered name. Used only for
   the §8.6 advice, which is the one piece of per-client config that is
   not a security decision — so unlike class_for_name and roles_for_name
   there is no restrictive floor to fall back to. An unknown client gets
   RECONNECT_UNSPEC and picks its own default, which is correct: the
   daemon genuinely has no opinion about a client it has never heard of. */
static const struct client_reg *reg_for_name(const char *name) {
  for (int i = 0; i < registry_len; i++)
    if (strcmp(registry[i].name, name) == 0)
      return &registry[i];
  return NULL;
}

/* Roles are opt-in per registry entry, so an unregistered client gets
   none. Note which direction that fails in: an unknown client is NOT
   asked for confirmation.

   That is the opposite of the allowlist's default-deny, and it is a
   considered trade rather than an oversight. Requiring confirmation for
   every unregistered client would mean the CLI — and every test — needs
   a confirmer running before a single key can be pressed, and a control
   that everyone has to switch off to get work done is a control nobody
   has. What actually bounds an unknown client is the deny-list, the
   allowlist and its 5/s floor; confirmation is a speed bump for a
   *named* client that the user has decided needs one. */
static unsigned roles_for_name(const char *name) {
  for (int i = 0; i < registry_len; i++)
    if (strcmp(registry[i].name, name) == 0)
      return registry[i].roles;
  return 0;
}

static void audit_log(int fd, pid_t peer_pid, uid_t peer_uid, uint32_t src,
                      uint16_t op, uint32_t seq, uint16_t result,
                      const char *args) {
  struct timespec now;
  clock_gettime(CLOCK_REALTIME, &now);
  struct tm tm;
  gmtime_r(&now.tv_sec, &tm);
  char ts[32];
  strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tm);

  char line[512];
  int n = snprintf(line, sizeof(line),
                   "%s pid=%d uid=%u src=0x%x op=%s seq=%u result=%u args=%s\n",
                   ts, (int)peer_pid, (unsigned)peer_uid, src, opname(op), seq,
                   result, args ? args : "");
  if (n < 0)
    return;
  if ((size_t)n >= sizeof(line))
    n = (int)sizeof(line) - 1;
  (void)write(fd, line, (size_t)n);
}

/* ---- connection objects (M3.5) --------------------------------------
   A connection is no longer a function call inside the accept branch;
   it is an object registered in the epoll set with its own parse state.
   The daemon must never block on a client: a peer that sends 3 bytes of
   a 16-byte header and then sleeps used to park the whole daemon inside
   read_full().                                                          */

#define MAX_CONNS 32
#define HDR_SIZE (sizeof(struct uictl_frame_header))
#define CONN_BUF_SIZE UICTL_MAX_PAYLOAD /* header phase reuses this buffer */
#define CONN_OUT_SIZE (HDR_SIZE + UICTL_MAX_PAYLOAD)

/* How long a *half-delivered frame* may sit before the connection is
   reaped, and how often the reaper scans. The effective deadline is
   therefore 5–6 s, not exactly 5 — a frame that goes quiet just after a
   tick waits nearly a full extra tick for the next one. Do not tighten
   the tick to hide that; a coarse periodic scan is the point. */
#define CONN_PARTIAL_TIMEOUT_SEC 5
#define REAPER_TICK_SEC 1

/* ---- idle exit (M6) --------------------------------------------------
   Off by default, and off entirely unless systemd is holding the
   listening socket. Exiting when nothing will restart us does not make
   the daemon cheap, it makes it absent: the socket file goes away with
   the process and every later client gets ECONNREFUSED with nothing to
   fix it. Under activation the same exit costs a cold start on the next
   connect() and nothing else.

   Enabled with UICTL_IDLE_EXIT_SEC in the unit's Environment=. A floor
   applies (see IDLE_EXIT_MIN_SEC) because a very short timer races the
   activation itself: systemd starts us BECAUSE a client connected, and a
   daemon that gave up before that connection was accepted would be
   restarted immediately, forever.

   What it costs, so the choice is made with open eyes: exiting closes
   /dev/uinput, so the two virtual devices are destroyed and recreated on
   the next start. The compositor sees that as a hotplug, and the first
   request after an idle exit pays device registration — tens of
   milliseconds, which is most of muvor's 50 ms budget. A long-lived
   client that wants predictable latency should leave this off. */
#define IDLE_EXIT_MIN_SEC 5

static long g_idle_exit_sec;  /* 0 = disabled */
static time_t g_idle_since;   /* when the connection table last emptied */
static int g_idle_expired;    /* set by the reaper, read by the loop */

/* ---- admission + fairness (M3.7) ------------------------------------
   How many frames one connection may have dispatched for it in a single
   epoll_wait turn (G6), and how many concurrent connections one peer pid
   may hold (G7).

   The budget is not a rate limit — it does not slow anyone down over
   time. It only bounds how long one connection can own the loop before
   the others are looked at: 32 frames is one uinput write and one audit
   write apiece, microseconds, while an unbounded drain of a 1000-frame
   pipeline is milliseconds and blows muvor's sub-50 ms budget.

   4 connections per pid is generous for every profile we know: the CLI
   opens one and exits, muvor and auto-c hold one long-lived each. It
   exists so a buggy or hostile peer cannot take all 32 slots. */
#define CONN_FRAMES_PER_TURN 32
#define MAX_CONNS_PER_PID 4


enum conn_phase { CONN_WANT_HEADER, CONN_WANT_PAYLOAD };

/* Same keyspace as the allowlist, and the same reasons for a bitset:
   768 bits is 96 bytes, membership has no ordering to get wrong, and
   the test is per request. Sized independently of ALLOW_BITS_BYTES on
   purpose — they happen to be equal because both index keycodes, not
   because one is derived from the other. */
#define HELD_BITS_BYTES ((UINPUT_KEY_CODE_MAX / 8) + 1)

/* How many keys one connection may hold at once, and for how long
   (M4.5 tasks 3 and 4).

   16 is far past any real gesture — a drag is one button, a shortcut is
   a modifier or three — and it is also UINPUT_SEQ_MAX_EVENTS, so a
   connection's entire held set always fits in one release frame. That
   is what makes the disconnect path a single write() no matter what the
   client did.

   30 seconds is a ceiling, not a target. A human drag finishes in a
   couple of seconds; a modifier held for half a minute is a wedged
   client, not a gesture. The cost of being wrong in the generous
   direction is a client that has to press again; the cost of being
   wrong in the other direction is Ctrl stuck on the user's desktop with
   the input broker itself as the wedged component. */
#define MAX_HELD_PER_CONN 16
#define HOLD_MAX_SEC 30

/* ---- confirmation (M5) ----------------------------------------------
   The largest request that can be parked awaiting a human. Every
   confirmable opcode's payload fits: KEY_* is 2 bytes, MOVE_ABS 8, and
   a full 16-item KEY_SEQUENCE is 68. Anything larger is refused rather
   than truncated — a prompt that describes less than what would execute
   is worse than no prompt.

   One pending confirmation daemon-wide, not a queue. Confirmations run
   at human speed; a queue of prompts is a worse experience than a
   refusal, and it would also let one client fill the daemon's memory
   with parked requests. A second confirmable request while one is
   pending gets ERR_BUSY, which is already the "no room, try again" code.

   30 seconds to answer, after which the request is denied. A timeout
   that approved would be a confirmation gate that opens when nobody is
   watching. */
#define CONFIRM_MAX_PAYLOAD 128
#define CONFIRM_TIMEOUT_SEC 30

/* ---- epoll event keys ------------------------------------------------
   `epoll_event.data` is a union and the obvious choice, `.fd`, is a trap
   here. fd numbers are recycled: the kernel hands out the lowest free
   one, so the instant conn_close() closes fd 9, the very next accept4()
   in the SAME epoll_wait batch can be handed 9 again. A later event in
   that batch still says "fd 9" and would resolve to the brand-new
   connection — delivering a dead peer's EPOLLHUP, or an EPOLLIN, to a
   client that just connected.

   So an event key names the connection *object*, not its fd:

     bits 63..32  generation — 0 for the three static fds, >= 1 for conns
     bits 31..0   the fd for static sources, the conns[] slot for clients

   The generation is bumped on every conn_alloc, so a stale event for a
   reused slot fails the match and is dropped. Generation 0 is reserved
   for the static sources, which is what makes one decode cover both
   kinds without a separate tag field. Wraparound needs 2^32 accepts
   between two events of one batch — not reachable. */
#define EVKEY_STATIC(fd) ((uint64_t)(uint32_t)(fd))
#define EVKEY_CONN(slot, gen) (((uint64_t)(gen) << 32) | (uint32_t)(slot))
#define EVKEY_GEN(u) ((uint32_t)((u) >> 32))
#define EVKEY_LOW(u) ((uint32_t)((u) & 0xffffffffu))

struct conn {
  int fd;            /* < 0 => slot free. the ONLY free marker.        */
  struct ucred cred; /* captured once at accept; never re-read.        */

  /* M9: what /proc said the peer was running, read once at accept for
     the same reason cred is -- re-reading later would sample a different
     moment and give the answer a false freshness it cannot have. Empty
     when unknown, and unknown FAILS every binding check. */
  char exe[UICTL_EXE_MAX];

  /* --- read side --- invariant: have <= want <= sizeof(buf) --------- */
  enum conn_phase phase;
  size_t want;                   /* bytes this phase still needs total */
  size_t have;                   /* bytes currently in buf             */
  struct uictl_frame_header hdr; /* valid only in CONN_WANT_PAYLOAD    */
  char buf[CONN_BUF_SIZE];

  /* --- write side --- invariant: out_sent <= out_len <= sizeof(out).
     A response is pending iff out_sent < out_len. There is exactly ONE
     out buffer, so while a response is pending the connection must not
     parse another frame — the next reply would overwrite the one still
     going out. That is enforced by dropping EPOLLIN, see
     conn_update_events. --------------------------------------------- */
  char out[CONN_OUT_SIZE];
  size_t out_len;
  size_t out_sent;
  int close_after_flush; /* fatal frame: finish the reply, then close  */
  time_t out_since;      /* mono secs when the response first stalled  */

  /* What this fd is currently registered for in the epoll set. Cached so
     conn_update_events can skip a redundant EPOLL_CTL_MOD syscall on the
     common path where nothing changed. */
  uint32_t events;

  /* Bumped every time this slot is handed to a new peer. Makes a stale
     epoll event for a previous occupant identifiable. */
  uint32_t generation;

  /* CLOCK_MONOTONIC seconds when the current frame's first byte
     arrived. Valid only while a frame is in progress, i.e.
     (have > 0 || phase == CONN_WANT_PAYLOAD). Read by the M3.5 task 6
     reaper; nothing consumes it yet. */
  time_t frame_since;

  /* --- handshake state (M3.6 task 2) -------------------------------
     Set once by OP_HELLO and never again on this connection — see the
     duplicate-HELLO refusal in conn_handle_frame. Scoped to the
     connection, not the pid: two connections from one process may
     legitimately be different consumers of a future client library, and
     a pid is not an identity anyway (they recycle).

     proto_min/proto_max are recorded but not yet acted on; task 4 turns
     the header's version-equality check into a range intersection. */
  int hello_seen;
  uint16_t proto_min;
  uint16_t proto_max;
  /* 0 until a HELLO succeeds. Once set, every later frame on this
     connection must carry exactly this version — see conn_version_ok. */
  uint16_t proto_selected;
  char client_name[UICTL_CLIENT_NAME_MAX];
  /* Derived by the daemon, never sent by the peer. Starts at the floor
     at accept and is only ever raised by a successful HELLO whose name
     the local registry lists. M4's rate limiter reads this; it must
     never read source_tag. */
  enum client_class cl;

  /* Operator introspection only (M3.7 task 4 / SIGUSR1). Deliberately
     not policy inputs: a rate limit keyed on frames_served would be a
     policy decision made below the identity layer, which is the mistake
     G2 is about. accepted_at is CLOCK_MONOTONIC seconds. */
  time_t accepted_at;
  uint64_t frames_served;

  /* --- held state (M4.5 task 1) -------------------------------------
     Which keycodes this connection currently holds down. Nothing writes
     to it yet: OP_KEY_DOWN/OP_KEY_UP do not exist, and OP_KEY_SEQUENCE
     releases everything it presses inside one request, so it never
     leaves a hold behind. The bookkeeping lands first, exactly as the
     deny-list landed before injection — there must be no build in which
     a socket can press a key with no record of who is holding it.

     Owned by the *connection*, not the pid: task 2 has to answer "what
     does this dying fd hold" while the peer's other connections stay
     alive, and a pid-keyed set cannot separate them. Task 3's other
     question — "does anyone else hold this code" — is a 32-slot scan,
     see conn_holder_of.

     One bitset for keys and buttons together, deliberately: BTN_LEFT is
     keycode 0x110 and lives in the same keyspace. M5.5 may split the
     device in two, and splitting this later is mechanical.

     held_since is CLOCK_MONOTONIC seconds at the 0 -> 1 transition, and
     0 while nothing is held — the *oldest* hold on the connection, not
     a per-code stamp. Task 4's dead-man timer asks "has this client
     been holding something too long", which a 768-entry timestamp array
     per connection would answer more precisely at 6 KB a slot and no
     practical gain: a drag has a plausible ceiling, and that ceiling is
     what the timer enforces. */
  unsigned char held_bits[HELD_BITS_BYTES];
  int held_count;
  time_t held_since;

  /* Sticky: set at the first successful hold on this connection and
     never cleared while the connection lives. It is NOT a count and not
     derivable from held_count, which returns to 0 every time the client
     releases what it had.

     WIRE.md §8.3.1: a release for something this connection never held
     is forgiven with OK *before* the connection has held anything, and
     refused with ERR_KEY_NOT_HELD afterwards. The first case cannot be
     distinguished from a client whose previous connection died
     mid-gesture — the daemon released its holds (§8.3) and the client's
     in-flight release arrived on the new connection — and there is
     nothing for that client to fix. The second is a client that lost
     track of its own state within one connection, which is a real bug
     and still worth reporting. Without this flag the two collapse into
     one case and the diagnostic is gone. */
  int held_ever;

  /* --- confirmation (M5) --------------------------------------------
     `roles` is derived at HELLO from the local registry, exactly like
     `cl`, and for the same reason: the client says a name, the daemon
     decides what that name means.

     A parked request is one the daemon has accepted, charged and
     validated as far as policy, and is now holding while a human is
     asked. It is stored as a copy rather than left in c->buf, because
     conn_readable wipes that buffer after every dispatch (security rule
     6) — and because a connection with a parked request stops reading,
     so there is exactly one. */
  unsigned roles;
  int is_confirmer;
  int awaiting_confirm;
  /* Set by the OP_CONFIRM_DECIDE handler, consumed once by conn_readable
     after that reply is staged: +1 allow, -1 deny, 0 nothing pending.
     Deferred rather than applied inline because the decision acts on a
     *different* connection, and doing that mid-dispatch would stage two
     replies through one code path. */
  int confirm_verdict;
  struct uictl_frame_header parked_hdr;
  char parked_payload[CONFIRM_MAX_PAYLOAD];
};

static struct conn conns[MAX_CONNS];

static time_t mono_secs(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0)
    return 0;
  return ts.tv_sec;
}

/* ---- motion audit coalescing (G10, forced by M5.5) -------------------
   Every request has had its own audit line since M2, which was right
   while every request was a discrete act. M5.5 makes pointer motion
   real: muvor streams 30-60 nudges a second while a key is held, and one
   line each is roughly 450 MB a day from that client alone. A log nobody
   can keep is a log nobody reads.

   Security rule 5 is the guide here, not an obstacle. It says the audit
   records *intent*, and the intent behind 47 nudges in a second is "this
   client moved the pointer" — one line saying so, with the count and
   where it ended up, carries more of that than 47 lines each carrying a
   pixel. So successful motion is accumulated per (pid, opcode) and
   flushed once a second by the reaper.

   What is NOT coalesced, deliberately:
     - anything that failed. Refusals are rare, individually meaningful,
       and exactly what someone greps for.
     - keys, buttons, sequences and batches. Those are discrete acts
       whose count is the point.
   So the property that matters — every keystroke and every click has its
   own line, forever — is untouched. */
#define MOTION_ACC_SLOTS 8
#define MOTION_FLUSH_SEC 1

struct motion_acc {
  int used;
  pid_t pid;
  uid_t uid;
  uint32_t src; /* last source_tag seen, advisory as always */
  uint16_t op;
  uint32_t count;
  int32_t last_a, last_b;
  time_t since;
};

static struct motion_acc motion_accs[MOTION_ACC_SLOTS];

static int op_is_motion(uint16_t op) {
  return op == OP_MOVE_ABS || op == OP_MOVE_REL || op == OP_SCROLL;
}

static void motion_emit(int audit_fd, struct motion_acc *m, time_t now) {
  if (!m || !m->used)
    return;
  char args[128];
  snprintf(args, sizeof(args), "coalesced n=%u over %llds, last a=%d b=%d",
           m->count, (long long)(now - m->since), m->last_a, m->last_b);
  audit_log(audit_fd, m->pid, m->uid, m->src, m->op, 0, OK, args);
  m->used = 0;
}

static void motion_note(int audit_fd, pid_t pid, uid_t uid, uint32_t src,
                        uint16_t op, int32_t a, int32_t b) {
  time_t now = mono_secs();
  struct motion_acc *free_slot = NULL, *oldest = NULL;
  for (int i = 0; i < MOTION_ACC_SLOTS; i++) {
    struct motion_acc *m = &motion_accs[i];
    if (m->used && m->pid == pid && m->op == op) {
      m->count++;
      m->last_a = a;
      m->last_b = b;
      m->src = src;
      return;
    }
    if (!m->used && !free_slot)
      free_slot = m;
    if (m->used && (!oldest || m->since < oldest->since))
      oldest = m;
  }
  if (!free_slot) {
    /* More than 8 (pid, opcode) motion streams at once. Flush the oldest
       to make room rather than dropping the new one: nothing is silently
       discarded either way, and the stream that has been running longest
       is the one whose line is most complete. */
    motion_emit(audit_fd, oldest, now);
    free_slot = oldest;
  }
  free_slot->used = 1;
  free_slot->pid = pid;
  free_slot->uid = uid;
  free_slot->src = src;
  free_slot->op = op;
  free_slot->count = 1;
  free_slot->last_a = a;
  free_slot->last_b = b;
  free_slot->since = now;
}

/* Flush anything older than MOTION_FLUSH_SEC, or everything if forced
   (shutdown). Called from the reaper tick, so the coarse 1 s deadline is
   really 1-2 s — same as every other deadline in this daemon. */
static void motion_flush(int audit_fd, int force) {
  time_t now = mono_secs();
  for (int i = 0; i < MOTION_ACC_SLOTS; i++) {
    struct motion_acc *m = &motion_accs[i];
    if (m->used && (force || now - m->since >= MOTION_FLUSH_SEC))
      motion_emit(audit_fd, m, now);
  }
}

static void conn_table_init(void) {
  for (int i = 0; i < MAX_CONNS; i++)
    conns[i].fd = -1;
}

/* Monotonic, never reset, never 0 for a live connection — see
   EVKEY_CONN. Starts at 1 so the first allocation is distinguishable
   from the zero-initialised `generation` of an untouched slot. */
static uint32_t conn_generation_next = 1;

static struct conn *conn_alloc(int fd, const struct ucred *cred) {
  for (int i = 0; i < MAX_CONNS; i++) {
    if (conns[i].fd >= 0)
      continue;
    struct conn *c = &conns[i];
    c->generation = conn_generation_next++;
    if (conn_generation_next == 0)
      conn_generation_next = 1; /* skip 0: reserved for static fds */
    c->fd = fd;
    c->cred = *cred;
    c->phase = CONN_WANT_HEADER;
    c->want = HDR_SIZE;
    c->have = 0;
    c->out_len = 0;
    c->out_sent = 0;
    c->close_after_flush = 0;
    c->out_since = 0;
    c->events = EPOLLIN; /* caller registers with exactly this */
    c->frame_since = 0;
    c->accepted_at = mono_secs();
    c->frames_served = 0;
    c->hello_seen = 0;
    c->proto_min = 0;
    c->proto_max = 0;
    c->proto_selected = 0;
    /* The floor is assigned at accept, before the peer has said
       anything at all — identity that starts permissive and gets
       narrowed later is how a race becomes a privilege. */
    c->cl = CLASS_UNTRUSTED;
    /* Not just [0] = '\0': the whole array is compared and printed, and
       a reused slot must not carry a previous peer's name in its tail. */
    memset(c->client_name, 0, sizeof(c->client_name));
    /* Same reasoning, and it matters more here: a stale exe path in a
       reused slot would satisfy a registry binding for a peer that
       never had it. The caller fills this immediately (M9). */
    memset(c->exe, 0, sizeof(c->exe));
    /* A reused slot inheriting the previous peer's holds would make the
       new client unable to press a key it never pressed (task 3 would
       see it as already held) and would leave task 2 synthesizing a
       release for someone else's keystroke. conn_close clears this
       already; clearing it again here is the cheap half of the pair. */
    memset(c->held_bits, 0, sizeof(c->held_bits));
    c->held_count = 0;
    c->held_since = 0;
    /* Must start clear on every accept, or the forgiving window in
       §8.3.1 never opens for a client landing on a slot whose previous
       occupant held something. */
    c->held_ever = 0;
    /* A reused slot must not inherit the previous peer's role: the
       confirmer flag in particular would let an unrelated client answer
       prompts simply by landing on the right index. */
    c->roles = 0;
    c->is_confirmer = 0;
    c->awaiting_confirm = 0;
    c->confirm_verdict = 0;
    memset(c->parked_payload, 0, sizeof(c->parked_payload));
    return c;
  }
  return NULL; /* table full — caller refuses the connection */
}

/* How many live connections this peer pid already holds (M3.7 task 2).
   Why *pid* and not uid: every peer is the same uid — that is invariant
   9 — so uid discriminates nothing between two processes of this user.
   pid comes from SO_PEERCRED, is captured by the kernel at accept, and
   cannot be forged by the client. It is not a stable identity (pids get
   recycled), but that does not matter for a cap on *concurrently open*
   connections: the only question is how many live conns share this pid
   right now, and a recycled pid means the old ones are long closed.

   pid 0 is not special-cased. SO_PEERCRED reports 0 when the peer lives
   in another pid namespace or has already exited, so all such peers do
   share one bucket of 4 — a real but tiny unfairness. The alternative,
   exempting pid 0 from the cap, is an unbounded hole reachable by any
   peer that can arrange to look unmappable. Prefer the unfairness. */
static int conn_count_pid(pid_t pid) {
  int n = 0;
  for (int i = 0; i < MAX_CONNS; i++)
    if (conns[i].fd >= 0 && conns[i].cred.pid == pid)
      n++;
  return n;
}

/* Live connections, any peer. The idle-exit test, and deliberately a
   count of CONNECTIONS rather than of held keys: a key can only be held
   by a connection, so an empty table is the strongest statement
   available that nothing is mid-gesture. Testing "no keys held" instead
   would let the daemon exit under a client that is connected, idle and
   about to send something. */
static int conn_count_live(void) {
  int n = 0;
  for (int i = 0; i < MAX_CONNS; i++)
    if (conns[i].fd >= 0)
      n++;
  return n;
}

/* ---- held state accessors (M4.5 task 1) -----------------------------
   The only three functions that touch held_bits. held_count and
   held_since are derived state, and derived state maintained at more
   than one call site drifts: a count that disagrees with the bitset
   would make task 2 stop synthesizing releases one key early, which
   presents as a randomly stuck key, hours later, with nothing in the
   audit log to point at. Everything below goes through these. */

static int conn_holds(const struct conn *c, uint16_t code) {
  if (code > UINPUT_KEY_CODE_MAX)
    return 0;
  return (c->held_bits[code / 8] & (1u << (code % 8))) != 0;
}

/* Idempotent by construction: a second add of a code already held is a
   no-op, not a double count. The caller is expected to have refused the
   duplicate DOWN already (task 3), but a bookkeeping primitive that
   corrupts its own count when called twice is a landmine. */
static void conn_hold_add(struct conn *c, uint16_t code) {
  if (code > UINPUT_KEY_CODE_MAX || conn_holds(c, code))
    return;
  c->held_bits[code / 8] |= (unsigned char)(1u << (code % 8));
  c->held_ever = 1; /* sticky — see the struct comment and WIRE.md §8.3.1 */
  if (c->held_count++ == 0)
    c->held_since = mono_secs(); /* oldest hold — see the struct comment */
}

static void conn_hold_drop(struct conn *c, uint16_t code) {
  if (code > UINPUT_KEY_CODE_MAX || !conn_holds(c, code))
    return;
  c->held_bits[code / 8] &= (unsigned char)~(1u << (code % 8));
  if (--c->held_count == 0)
    c->held_since = 0;
}

/* ---- release on disconnect (M4.5 task 2) ----------------------------
   Emit the release for everything this connection holds, then forget it.
   This is the safety property the whole milestone exists for: the fd is
   going away, and the kernel does not care — a key pressed by a process
   that has since died stays down until something writes value 0 for it.
   "Something" is only ever this function.

   Called from conn_close, so it covers *every* way a connection ends:
   clean close, EPOLLHUP, kill -9, reaped stall, epoll registration
   failure, daemon shutdown. There is deliberately no separate
   "client disconnected cleanly" path — a clean disconnect is not the
   case that strands a key, so a fix that only handles it is no fix.

   Reuses uinput_key_seq rather than adding a primitive: it already
   writes N transitions and exactly one SYN_REPORT in one write(), and
   it is already verified at the device by tests/test_m4_sequence.py.
   Chunked at UINPUT_SEQ_MAX_EVENTS because the bitset can hold more
   codes than one frame carries; releases do not need to be atomic with
   each other the way a modifier and its key do — each release is
   independently meaningful, and the requirement is only that all of
   them happen.

   Descending keycode order: modifiers live low (KEY_LEFTCTRL is 29,
   KEY_A is 30), so descending releases the ordinary key before the
   modifier that was held with it. Within one frame the order is
   cosmetic — one SYN means the compositor sees them together — but
   across chunks it is real, and "released Ctrl while A was still down"
   is a state no real keyboard produces.

   Returns the number of codes that could not be written. */
static int conn_release_held(struct conn *c, const struct uinput_devs *devs,
                          int audit_fd,
                             const char *why) {
  if (c->held_count == 0)
    return 0; /* the overwhelming majority of closes: no work, no audit */

  const int total = c->held_count;
  int failed = 0;
  struct uinput_key_event batch[UINPUT_SEQ_MAX_EVENTS];
  size_t n = 0;

  /* First few codes, for the audit line. Truncated on purpose: the line
     has to answer "what came back up" for a human debugging a stuck key,
     and a 700-code list in a 512-byte record answers nothing. */
  char list[96];
  size_t used = 0;
  int listed = 0;

  for (int code = UINPUT_KEY_CODE_MAX; code >= 1; code--) {
    if (!conn_holds(c, (uint16_t)code))
      continue;

    if (listed < 8 && used < sizeof(list) - 1) {
      int w = snprintf(list + used, sizeof(list) - used, "%s%d",
                       listed ? "," : "", code);
      if (w > 0 && (size_t)w < sizeof(list) - used) {
        used += (size_t)w;
        listed++;
      }
    }

    /* M5.5: a held BUTTON lives on the pointer device, a held key on the
       keyboard, and releasing one through the other writes an event the
       kernel silently drops — a stuck button that the release path
       *thinks* it released, which is worse than never having tried.
       Buttons go out one at a time; there are five of them, and batching
       across a device boundary is what this is avoiding. */
    if (uinput_is_button((uint16_t)code)) {
      if (uinput_button(devs->pointer, (uint16_t)code, 0) < 0)
        failed++;
      continue;
    }

    batch[n].code = (uint16_t)code;
    batch[n].value = 0;
    n++;
    if (n == UINPUT_SEQ_MAX_EVENTS) {
      if (uinput_key_seq(devs->keyboard, batch, n) < 0)
        failed += (int)n;
      n = 0;
    }
  }
  if (n > 0 && uinput_key_seq(devs->keyboard, batch, n) < 0)
    failed += (int)n;

  /* Cleared through the one writer, after the writes and regardless of
     whether they succeeded. Keeping the bits on a failure would look
     like caution but buys nothing: the connection is being destroyed and
     the slot reused, so nobody would ever read them again. A write that
     failed here means the device itself is broken, which is what the
     ERR_INTERNAL audit line and uinput_key_seq's own stderr are for. */
  for (int code = UINPUT_KEY_CODE_MAX; code >= 1; code--)
    conn_hold_drop(c, (uint16_t)code);

  /* One grep-able token, `held-release:`, with the reason as a field —
     not "release-on-close", which was true of the only caller when this
     was written and stopped being true one task later when the dead-man
     timer started calling it too. */
  char args[256];
  if (failed)
    snprintf(args, sizeof(args),
             "held-release: %d key(s) [%s%s], %d FAILED, reason=%s", total,
             list, listed < total ? ",..." : "", failed, why);
  else
    snprintf(args, sizeof(args), "held-release: %d key(s) [%s%s], reason=%s",
             total, list, listed < total ? ",..." : "", why);

  /* OP_INVALID with descriptive args, the same shape conn_reap_partial
     uses: no client asked for this, so echoing an opcode or a seq would
     invent a request that never existed. Logged unconditionally — a key
     going up without a client asking is exactly the "intent" security
     rule 5 wants on the record, and it is the only trace that will exist
     when someone asks why their Ctrl unstuck itself. */
  audit_log(audit_fd, c->cred.pid, c->cred.uid, 0, OP_INVALID, 0,
            failed ? ERR_INTERNAL : OK, args);
  return failed;
}

/* Who else currently holds `code` (M4.5 task 3), or NULL.

   A linear scan of 32 slots per DOWN, which is nothing next to the
   write() that follows. The alternative — a daemon-wide code -> owner
   table — would be O(1) and would introduce a second copy of the truth
   that has to be kept in step with 32 bitsets. Task 1's note about
   derived state applies with more force here: the failure mode of a
   stale owner table is a key nobody can press again.

   `except` is always the asking connection. Holding a key you already
   hold is a different error from someone else holding it (client bug vs
   contention), so the two questions are answered separately. */
static struct conn *conn_holder_of(uint16_t code, const struct conn *self) {
  for (int i = 0; i < MAX_CONNS; i++) {
    if (conns[i].fd < 0 || &conns[i] == self)
      continue;
    if (conn_holds(&conns[i], code))
      return &conns[i];
  }
  return NULL;
}

/* Startup selftest, in the house style of uinput_denylist_selftest():
   prove the bit math on the boundaries rather than trust it. An
   off-by-one in the byte/shift arithmetic is the classic bug here, and
   its symptom — one keycode that can be pressed but never released, or
   a hold recorded against the neighbouring code — would surface as a
   stuck key long after the cause. Runs on a scratch connection so it
   cannot disturb the live table. Returns non-zero to refuse startup. */
static int conn_held_selftest(void) {
  static struct conn probe; /* static: 96 B + buffers, too big for stack */
  int bad = 0;

  const uint16_t edges[] = {1, 7, 8, 272 /* BTN_LEFT */,
                            UINPUT_KEY_CODE_MAX - 1, UINPUT_KEY_CODE_MAX};
  for (size_t i = 0; i < sizeof(edges) / sizeof(edges[0]); i++) {
    uint16_t code = edges[i];
    conn_hold_add(&probe, code);
    if (!conn_holds(&probe, code)) {
      fprintf(stderr, "uictld: held selftest: %u did not set\n", code);
      bad = 1;
    }
    /* The neighbours must be untouched — this is the check that catches
       a shift applied to the wrong byte. */
    if ((code > 1 && conn_holds(&probe, (uint16_t)(code - 1))) ||
        (code < UINPUT_KEY_CODE_MAX && conn_holds(&probe, (uint16_t)(code + 1)))) {
      fprintf(stderr, "uictld: held selftest: %u bled into a neighbour\n", code);
      bad = 1;
    }
    conn_hold_add(&probe, code); /* idempotence: must not double count */
    if (probe.held_count != 1) {
      fprintf(stderr, "uictld: held selftest: %u count=%d, want 1\n", code,
              probe.held_count);
      bad = 1;
    }
    if (probe.held_since == 0) {
      fprintf(stderr, "uictld: held selftest: %u left held_since unset\n", code);
      bad = 1;
    }
    conn_hold_drop(&probe, code);
    conn_hold_drop(&probe, code); /* dropping twice must not go negative */
    if (conn_holds(&probe, code) || probe.held_count != 0 ||
        probe.held_since != 0) {
      fprintf(stderr, "uictld: held selftest: %u did not clear (count=%d)\n",
              code, probe.held_count);
      bad = 1;
    }
    /* held_ever must NOT come back with held_count. If a drop cleared it,
       §8.3.1's window would reopen every time a client released what it
       held, and a mid-connection double-release — the client bug the
       error exists to report — would be forgiven instead. */
    if (!probe.held_ever) {
      fprintf(stderr, "uictld: held selftest: %u cleared held_ever\n", code);
      bad = 1;
    }
  }

  /* Out of range must be refused, not wrapped into some other byte. */
  conn_hold_add(&probe, (uint16_t)(UINPUT_KEY_CODE_MAX + 1));
  if (probe.held_count != 0) {
    fprintf(stderr, "uictld: held selftest: out-of-range code was recorded\n");
    bad = 1;
  }
  return bad;
}

/* ---- connection-attempt backstop (WIRE.md §8.7) ---------------------
   MAX_CONNS_PER_PID bounds how many connections a pid holds AT ONCE. It
   says nothing about how fast a pid may open and close them, and under
   socket activation that is the gap that matters: connect() succeeds
   whether or not a daemon is running, so a client whose reconnect loop
   has no backoff will spin as fast as the scheduler allows and each
   attempt is, individually, within every limit the daemon has.

   §8.6's advertised advice does not close this. It cannot: it is read by
   the client, in the client's process, at the moment the daemon is
   least able to influence anything. This is the enforcing half, and the
   only rule in §8 that survives a client ignoring everything else.

   Sliding window per pid, not a token bucket. A bucket would let a
   client trickle at exactly the refill rate forever, which is the
   behaviour of a broken retry loop and precisely what should be
   refused. The window asks a blunter question -- "how many attempts in
   the last N seconds" -- and a client obeying any backoff at all cannot
   reach it: 100 ms doubling gives ~7 attempts in the first 10 seconds.

   The CLI is unaffected by construction. Every `uictl` invocation is a
   new process, so a new pid, so a fresh window; the budget is spent only
   by one long-lived process reconnecting in a loop, which is exactly the
   thing being bounded. */
#define CONN_ATTEMPT_WINDOW_SEC 10
#define CONN_ATTEMPTS_PER_WINDOW 60
#define ATTEMPT_SLOTS MAX_CONNS

struct attempt_slot {
  pid_t pid;
  time_t window_start; /* CLOCK_MONOTONIC seconds */
  unsigned count;
  int used;
};

static struct attempt_slot attempt_slots[ATTEMPT_SLOTS];

/* Record one connection attempt by `pid`. Returns 1 if it is within the
   window budget, 0 if the pid is storming.

   Counts EVERY attempt, including ones the caps below will refuse: a
   client hammering a full connection table is the same storm as one
   hammering an empty one, and the table cap alone would let it retry
   forever at full speed. */
static int attempt_admit(pid_t pid) {
  time_t now = mono_secs();
  struct attempt_slot *slot = NULL;

  for (int i = 0; i < ATTEMPT_SLOTS; i++)
    if (attempt_slots[i].used && attempt_slots[i].pid == pid) {
      slot = &attempt_slots[i];
      break;
    }

  if (!slot) {
    for (int i = 0; i < ATTEMPT_SLOTS; i++)
      if (!attempt_slots[i].used) {
        slot = &attempt_slots[i];
        break;
      }
  }
  if (!slot) {
    /* Full: reclaim the slot whose window is oldest. Unlike the rate
       buckets this may steal from a live pid, and that is safe here
       precisely because it is the direction that FORGIVES -- the victim
       gets a fresh window, i.e. more budget, never less. A backstop that
       could be made stricter by table pressure would refuse innocent
       clients when a storm filled the table, which is the storm winning. */
    slot = &attempt_slots[0];
    for (int i = 1; i < ATTEMPT_SLOTS; i++)
      if (attempt_slots[i].window_start < slot->window_start)
        slot = &attempt_slots[i];
    slot->used = 0;
  }

  if (!slot->used || slot->pid != pid ||
      now - slot->window_start >= CONN_ATTEMPT_WINDOW_SEC) {
    slot->used = 1;
    slot->pid = pid;
    slot->window_start = now;
    slot->count = 0;
  }

  slot->count++;
  return slot->count <= CONN_ATTEMPTS_PER_WINDOW;
}

/* ---- rate limiting (M4 step 10) -------------------------------------
   A token bucket per peer **pid**, sized by the peer's **class**.

   Why pid and not connection: a per-connection bucket is multiplied by
   however many connections a client opens (up to MAX_CONNS_PER_PID = 4),
   which turns the limit into a suggestion. Why pid and not `source_tag`:
   that is G2 — the client picks the field, so it would pick its own
   limit. pid comes from SO_PEERCRED and cannot be forged.

   The bucket survives disconnect: it is keyed on pid and reclaimed only
   when that pid has no live connection AND its slot is needed. Otherwise
   reconnecting would reset the budget, and "close and reopen the socket"
   would be a rate-limit bypass anyone would find in an afternoon.

   Integer milli-tokens, not floats: exact, and the daemon has no other
   floating point in it. RATE_UNIT milli-tokens is one request. */
#define RATE_UNIT 1000
#define RATE_BUCKETS MAX_CONNS

struct rate_class {
  unsigned per_sec; /* sustained rate  */
  unsigned burst;   /* bucket capacity */
};

/* Indexed by enum client_class. The untrusted floor is what an
   unregistered client gets — and what the v2.x LLM agent will get until
   someone writes it into the registry deliberately. plan.md's original
   sketch was CLI 50 / HOTKEY 20 / LLM 5; the tiers survive, but they are
   now attached to a class the daemon derives rather than to a number the
   client sends. */
static const struct rate_class rate_classes[CLASS__COUNT] = {
    [CLASS_UNTRUSTED] = {5, 5},
    [CLASS_STANDARD] = {20, 20},
    [CLASS_INTERACTIVE] = {100, 100},
};

/* **Why interactive is 100 and not 50, raised 2026-08-27.** The number was
   never about the devices — uinput will take far more than this — it was
   about bounding what one trusted client can do to a desktop. 50/s was
   picked when the only pointer motion in sight was one nudge per keypress.
   muvor's movement mode is a *tick*, one MOVE_ABS per frame, and a pointer
   that updates 30 times a second on a 144 Hz panel is visibly steppy: it
   asked for 90 Hz, and 90 > 50 means the bucket empties in 1.25 s of
   sweeping and every other frame after that comes back ERR_RATE_LIMITED,
   which is a stutter and not a limit doing its job.

   100 keeps the shape of the thing — a sustained ceiling, a burst equal to
   it, a refusal rather than a queue — and leaves 10/s of headroom above
   muvor's 90 for the buttons it sends while sweeping. RATE_GLOBAL_PER_SEC
   stays 200: the daemon-wide backstop is what actually bounds total device
   traffic across every pid, and 90 + 20 + the odd CLI invocation still sits
   well inside it. */

struct rate_bucket {
  pid_t pid;
  int used;
  unsigned milli;  /* tokens * RATE_UNIT */
  long last_ms;    /* CLOCK_MONOTONIC ms at the last refill */
};

static struct rate_bucket rate_buckets[RATE_BUCKETS];

/* The backstop, and it exists because per-pid alone is bypassable:
   **fork per request and every request gets a fresh bucket.** The CLI
   does exactly that by accident — one process per invocation — and a
   hostile client can do it on purpose for the cost of a spawn.

   A daemon-wide bucket bounds total device traffic no matter how many
   pids appear. It is sized well above the sum of the intended clients
   (muvor 90/s + auto-c 20/s + occasional CLI) so it never shapes normal
   use; it is a ceiling on the pathological case, not a second tier.

   Every peer is the same uid (invariant 9), so daemon-wide and uid-wide
   are the same thing here. */
#define RATE_GLOBAL_PER_SEC 200
#define RATE_GLOBAL_BURST 200
static const struct rate_class rate_global_class = {RATE_GLOBAL_PER_SEC,
                                                    RATE_GLOBAL_BURST};
static struct rate_bucket rate_global = {0, 1, RATE_GLOBAL_BURST * RATE_UNIT,
                                         0};

static long mono_msecs(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0)
    return 0;
  return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

/* Is any live connection owned by this pid? Used to decide which bucket
   may be recycled. */
static int pid_has_conn(pid_t pid) {
  for (int i = 0; i < MAX_CONNS; i++)
    if (conns[i].fd >= 0 && conns[i].cred.pid == pid)
      return 1;
  return 0;
}

static struct rate_bucket *rate_bucket_for(pid_t pid, const struct rate_class *rc) {
  for (int i = 0; i < RATE_BUCKETS; i++)
    if (rate_buckets[i].used && rate_buckets[i].pid == pid)
      return &rate_buckets[i];

  struct rate_bucket *slot = NULL;
  for (int i = 0; i < RATE_BUCKETS; i++)
    if (!rate_buckets[i].used) {
      slot = &rate_buckets[i];
      break;
    }
  if (!slot) {
    /* Full: reclaim a bucket whose pid is gone. Never steal one that is
       still in use, or two clients would share a budget. */
    for (int i = 0; i < RATE_BUCKETS; i++)
      if (!pid_has_conn(rate_buckets[i].pid)) {
        slot = &rate_buckets[i];
        break;
      }
  }
  if (!slot)
    return NULL; /* caller treats this as "no budget": fail closed */

  slot->pid = pid;
  slot->used = 1;
  slot->milli = rc->burst * RATE_UNIT; /* a new client starts full */
  slot->last_ms = mono_msecs();
  return slot;
}

/* Bring one bucket up to date. Refill is computed lazily from elapsed
   time rather than on a timer: nothing to schedule, nothing to drift,
   and an idle client costs zero work. */
static void bucket_refill(struct rate_bucket *b, const struct rate_class *rc,
                          long now) {
  long elapsed = now - b->last_ms;
  if (elapsed <= 0) {
    /* Clock went backwards (or no time passed): refill nothing, and
       never punish — a client must not lose budget because of NTP. */
    if (elapsed < 0)
      b->last_ms = now;
    return;
  }
  unsigned long add = (unsigned long)elapsed * rc->per_sec;
  unsigned long cap = (unsigned long)rc->burst * RATE_UNIT;
  unsigned long total = (unsigned long)b->milli + add;
  b->milli = (unsigned)(total > cap ? cap : total);
  b->last_ms = now;
}

/* Take `cost` requests worth of budget from BOTH buckets, or refuse.
   `*global_out` reports which limit bit, for the audit line.

   Both are checked before either is charged: a request refused by the
   global ceiling must not still burn the client's own budget, or a busy
   daemon would silently throttle innocent clients twice over. */
static int rate_allow(pid_t pid, enum client_class cl, unsigned cost,
                      int *global_out) {
  const struct rate_class *rc = &rate_classes[cl];
  struct rate_bucket *b = rate_bucket_for(pid, rc);
  if (!b)
    return 0;

  long now = mono_msecs();
  bucket_refill(b, rc, now);
  bucket_refill(&rate_global, &rate_global_class, now);

  unsigned need = cost * RATE_UNIT;
  if (rate_global.milli < need) {
    *global_out = 1;
    return 0;
  }
  if (b->milli < need)
    return 0;

  b->milli -= need;
  rate_global.milli -= need;
  return 1;
}

static uint64_t conn_evkey(const struct conn *c) {
  return EVKEY_CONN(c - conns, c->generation);
}

/* Resolve an epoll event back to the connection that registered it, or
   NULL if that connection is gone. Replaces the old conn_find(fd) scan:
   this cannot alias, because the key carries the generation the event
   was registered under. */
static struct conn *conn_from_evkey(uint64_t key) {
  uint32_t slot = EVKEY_LOW(key);
  if (slot >= MAX_CONNS)
    return NULL;
  struct conn *c = &conns[slot];
  if (c->fd < 0 || c->generation != EVKEY_GEN(key))
    return NULL; /* closed, or the slot has since been reused */
  return c;
}

/* Forward declaration for one genuine cycle (M5): closing a connection
   can resolve a pending confirmation, resolving one can complete a
   parked request, and completing a request can close the connection it
   came from. The alternative is moving the confirmation block above this
   function, where it would sit above the reply helpers it needs — the
   cycle is real, so name it here rather than shuffle definitions until
   it hides. */
static void confirm_on_conn_closed(int epfd, struct conn *gone, const struct uinput_devs *devs,
                                   int audit_fd);

/* devs and audit_fd are threaded in rather than kept at file scope
   precisely so this is not easy to forget: a new close path does not
   compile until its author has said where the releases go. That is worth
   more than the noise, because a close path that skips the release is
   invisible at runtime until the day a client dies holding Ctrl. */
static void conn_close(int epfd, struct conn *c, const struct uinput_devs *devs,
                          int audit_fd) {
  if (!c || c->fd < 0)
    return;

  /* Before the fd goes away, and before the epoll deregistration — the
     order does not matter to the kernel device, but doing it first means
     no early return can ever be added above it. */
  conn_release_held(c, devs, audit_fd, "connection closed");

  /* M5: if this was the confirmer, whoever is waiting on it must be told
     now rather than left parked until the timeout — the prompter
     vanishing is not consent. If instead this is the parked requester,
     the pending confirmation is simply dropped. */
  confirm_on_conn_closed(epfd, c, devs, audit_fd);

  epoll_ctl(epfd, EPOLL_CTL_DEL, c->fd, NULL);
  close(c->fd);
  c->fd = -1;
  /* Security rule 6: the next client to land on this slot must not be
     able to read the previous one's payload. Today that's coordinates;
     at M4 it's keystrokes. explicit_bzero, not memset — memset on a
     buffer nothing reads afterwards is legal to optimise away. */
  explicit_bzero(c->buf, sizeof(c->buf));
  explicit_bzero(c->out, sizeof(c->out));
  c->have = 0;
  c->want = 0;
  c->out_len = 0;
  c->out_sent = 0;
  c->out_since = 0;
  c->events = 0;

  /* conn_release_held above already emptied the set through its own
     accessor. This is the belt to that braces: if it somehow did not,
     the slot must still not be handed to the next peer carrying a
     previous client's holds, which would make task 3 refuse keys the new
     client never pressed. */
  memset(c->held_bits, 0, sizeof(c->held_bits));
  c->held_count = 0;
  c->held_since = 0;
  c->held_ever = 0;
  c->is_confirmer = 0;
  c->awaiting_confirm = 0;
  c->confirm_verdict = 0;
  explicit_bzero(c->parked_payload, sizeof(c->parked_payload));
}

/* Best-effort refusal for a peer that never becomes a conn (bad uid,
   table full). The fd is non-blocking, so one write attempt only —
   never loop, never block on a client we are rejecting. */
static void deny_and_close(int cfd, uint16_t result) {
  struct uictl_frame_header deny = {.version = UICTL_PROTO_VERSION,
                                    .opcode = OP_INVALID,
                                    .source_tag = 0,
                                    .seq = 0,
                                    .payload_len = sizeof(uint16_t)};
  char deny_buf[HDR_SIZE + sizeof(uint16_t)];
  encode_frame_header(&deny, deny_buf);
  memcpy(deny_buf + HDR_SIZE, &result, sizeof(result));
  (void)write(cfd, deny_buf, sizeof(deny_buf));
  close(cfd);
}

/* Stage a response into the connection's out buffer. The request header
   is echoed (version, opcode, source_tag, seq) so the client can match
   the reply to its request; only payload_len is rewritten.

   `data` is the opcode-specific answer that follows the result code, and
   may be NULL/0 — which is every opcode today, and stays the shape of
   every pure command. OP_HELLO is what this exists for.

   Callers must not be able to overflow the out buffer by handing over a
   long answer, so an oversized one is refused rather than truncated: a
   truncated frame is worse than an error, because the length prefix
   would no longer describe the bytes and the stream would desync. This
   is a daemon bug if it ever fires, hence ERR_INTERNAL. */
static void conn_reply_data(struct conn *c, uint16_t result, const void *data,
                            size_t len) {
  if (len > UICTL_MAX_RESP_DATA) {
    fprintf(stderr, "uictld: reply payload %zu too large for op %u\n", len,
            c->hdr.opcode);
    result = ERR_INTERNAL;
    data = NULL;
    len = 0;
  }

  struct uictl_frame_header resp = c->hdr;
  resp.payload_len = (uint32_t)(UICTL_RESULT_SIZE + len);
  encode_frame_header(&resp, c->out);
  memcpy(c->out + HDR_SIZE, &result, UICTL_RESULT_SIZE);
  if (len)
    memcpy(c->out + HDR_SIZE + UICTL_RESULT_SIZE, data, len);
  c->out_len = HDR_SIZE + UICTL_RESULT_SIZE + len;
  c->out_sent = 0;
}

/* A bare acknowledgement: result code, no answer. */
static void conn_reply(struct conn *c, uint16_t result) {
  conn_reply_data(c, result, NULL, 0);
}

/* Push as much of the staged response as the socket will take.
     0  -> fully drained, out buffer is free again
     1  -> bytes remain; caller must arm EPOLLOUT and stop reading
    -1  -> fatal socket error, connection is dead
   Never spins on EAGAIN and never loops waiting for the peer: a client
   that stops reading must cost us one failed write() and nothing more.
   (M3.5 task 7. Before this, a partial write just killed the connection
   — correct but wrong: 18 bytes into a ~200KB socket buffer only fails
   when the peer is misbehaving *or* is a legitimate pipelining client
   that has queued thousands of frames without reading the replies.) */
static int conn_flush(struct conn *c) {
  while (c->out_sent < c->out_len) {
    ssize_t w = write(c->fd, c->out + c->out_sent, c->out_len - c->out_sent);
    if (w < 0) {
      if (errno == EINTR)
        continue;
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        return 1;
      return -1;
    }
    c->out_sent += (size_t)w;
  }
  /* Drained. Clearing both makes `out_sent < out_len` the single
     authoritative "response pending" test everywhere else. */
  c->out_len = 0;
  c->out_sent = 0;
  c->out_since = 0;
  return 0;
}

/* Point the epoll registration at whichever half of the socket we
   actually care about. EPOLLIN and EPOLLOUT are mutually exclusive here,
   and that is deliberate:

   - While a response is pending we must not parse another frame (one out
     buffer), so we stop reading. But merely *not calling read()* is not
     enough — this epoll set is level-triggered, so unread bytes sitting
     in the receive buffer would be re-reported on every single
     epoll_wait and spin the daemon at 100%. EPOLLIN has to come off the
     registration, not just be ignored.
   - Conversely, arming EPOLLOUT when nothing is queued is the classic
     busy-loop: a writable socket is almost always writable. */
static int conn_update_events(int epfd, struct conn *c) {
  /* Three states, not two, since M5. A connection whose request is
     parked awaiting a human wants NEITHER: not EPOLLOUT (there is no
     reply to send yet) and not EPOLLIN (the next frame must not be
     parsed, because answering it would jump the queue ahead of the
     request the user is still looking at — and because this connection
     has exactly one parked slot). 0 is a legal epoll mask: the fd stays
     registered, EPOLLHUP/EPOLLERR still arrive, and the confirmation
     path re-arms it. */
  uint32_t want;
  if (c->awaiting_confirm)
    want = 0;
  else
    want = (c->out_sent < c->out_len) ? (uint32_t)EPOLLOUT : (uint32_t)EPOLLIN;
  if (want == c->events)
    return 0; /* nothing to do; skip the syscall */
  /* MOD replaces `data` as well as `events`, so the key must be rebuilt
     identically — a MOD that dropped back to .fd would silently undo the
     aliasing fix. */
  struct epoll_event ev = {.events = want, .data.u64 = conn_evkey(c)};
  if (epoll_ctl(epfd, EPOLL_CTL_MOD, c->fd, &ev) < 0) {
    perror("uictld: epoll_ctl MOD client");
    return -1;
  }
  c->events = want;
  return 0;
}

/* Common tail for "we just staged (and tried to send) a response".
   Returns 0 if the connection survives and may keep parsing, -1 if it
   was closed. */
static int conn_after_flush(int epfd, struct conn *c, int flushed,
                            const struct uinput_devs *devs,
                          int audit_fd) {
  if (flushed < 0) { /* dead socket */
    conn_close(epfd, c, devs, audit_fd);
    return -1;
  }
  if (flushed > 0) { /* still queued: wait for EPOLLOUT */
    if (c->out_since == 0)
      c->out_since = mono_secs(); /* start the stall clock */
    if (conn_update_events(epfd, c) < 0) {
      conn_close(epfd, c, devs, audit_fd);
      return -1;
    }
    return -1; /* survives, but the caller must stop reading */
  }
  if (c->close_after_flush) { /* fatal frame, reply delivered */
    conn_close(epfd, c, devs, audit_fd);
    return -1;
  }
  return 0;
}

/* The peer drained enough of its receive buffer for us to continue. */
static void conn_writable(int epfd, struct conn *c, const struct uinput_devs *devs,
                          int audit_fd) {
  int flushed = conn_flush(c);
  if (flushed < 0) {
    conn_close(epfd, c, devs, audit_fd);
    return;
  }
  if (flushed > 0)
    return; /* still not drained; EPOLLOUT stays armed */
  if (c->close_after_flush) {
    conn_close(epfd, c, devs, audit_fd);
    return;
  }
  /* Re-arm EPOLLIN. We do NOT call conn_readable here: if the peer
     pipelined more frames while we were blocked, those bytes are already
     in the receive buffer and level-triggered epoll will hand us an
     EPOLLIN on the very next epoll_wait. Letting the loop do it keeps
     this function from recursing into the parser. */
  if (conn_update_events(epfd, c) < 0)
    conn_close(epfd, c, devs, audit_fd);
}

/* ---- confirmation (M5) ----------------------------------------------
   One pending confirmation daemon-wide. The requester's connection is
   parked (see conn_update_events) and the prompt is pushed to whichever
   connection holds the confirmer role.

   The token is what makes a slow "yes" safe. A confirmer that answers
   after the request timed out — or after the requester disconnected and
   the slot was reused — echoes a token that no longer matches, and the
   decision is dropped. Without it, "the user approved something" and
   "the user approved THIS" would be the same statement.

   The requester is identified by slot + generation, never by pointer:
   the same reasoning as the epoll event keys, and the same hazard. A
   pointer would still be valid memory after the connection closed and
   the slot was handed to someone else — and that someone else would
   inherit an approval meant for a different client. */
static struct {
  int active;
  uint32_t token;
  int slot;        /* requester: conns[] index ... */
  uint32_t gen;    /* ... and the generation it had when parked */
  time_t since;    /* CLOCK_MONOTONIC seconds, for the timeout */
  uint16_t opcode; /* what was asked, for the audit line */
} pending_confirm;

/* Never 0: 0 is the "no token" value a zeroed struct or a lazy client
   would produce, and it must never match a live confirmation. */
static uint32_t confirm_token_next = 1;

static struct conn *confirm_requester(void) {
  if (!pending_confirm.active)
    return NULL;
  struct conn *c = &conns[pending_confirm.slot];
  if (c->fd < 0 || c->generation != pending_confirm.gen)
    return NULL; /* the requester went away */
  return c;
}

static struct conn *confirmer_conn(void) {
  for (int i = 0; i < MAX_CONNS; i++)
    if (conns[i].fd >= 0 && conns[i].is_confirmer)
      return &conns[i];
  return NULL;
}

/* Does this opcode reach the device? That is the whole test for "must a
   human see it": the confirmation gate exists to put a person between a
   flagged client and the user's keyboard and pointer, not between it and
   a PING.

   Written as a switch over `enum uictl_op` with **no default**, so
   -Wswitch makes adding an opcode to the enum without answering this
   question a build warning. M5.5 adds buttons, relative motion and
   scroll; each one has to come here and say yes. An out-of-range value
   from the wire is validated by the dispatch switch below — reaching
   here it simply falls through to 0, which is safe because a frame that
   is not a known opcode never executes anything. */
/* Is this request a RELEASE of something already held?

   WIRE.md §6.3: the release path is never refused for a policy reason,
   because policy already had its say on the press — nothing can be held
   that was not allowed — so re-asking on the way up can only ever create
   a stuck key, never prevent one.

   The rate limiter got this right from M4 and exempts the same two
   cases. The confirmation gate did not: until this was written, a
   flagged client's OP_KEY_UP was parked for a human, and a denial, a
   timeout, or a missing confirmer left the key DOWN. Every one of those
   is a normal outcome of the confirmation flow — it fails closed by
   design — so the gate turned "the user said no" into a stuck modifier
   that only the 30-second dead-man timer would clear.

   Payload-aware, not opcode-aware, because OP_BUTTON carries both
   directions in one opcode. Same reason the rate limiter reads the
   buffer here rather than switching on the opcode alone. A malformed
   payload is NOT treated as a release: it falls through to the gate and
   then to the size check, so a client cannot dodge confirmation by
   sending a short frame. */
static int op_is_release(const struct conn *c) {
  if (c->hdr.opcode == OP_KEY_UP)
    return 1;
  if (c->hdr.opcode == OP_BUTTON &&
      c->hdr.payload_len == sizeof(struct uictl_payload_button))
    return ((const struct uictl_payload_button *)(const void *)c->buf)->down ==
           0;
  return 0;
}

static int op_touches_device(uint16_t op) {
  switch ((enum uictl_op)op) {
  case OP_MOVE_ABS:
  case OP_KEY_TAP:
  case OP_KEY_SEQUENCE:
  case OP_KEY_DOWN:
  case OP_KEY_UP:
  /* M5.5's four, each of which the -Wswitch above forced someone to
     answer for. All yes: a click, a nudge and a scroll all reach the
     user's pointer, and a batch is a container for the rest. There is no
     "pointer motion is harmless" exemption — a flagged client that can
     move the pointer and click can do anything the user can. */
  case OP_BUTTON:
  case OP_MOVE_REL:
  case OP_SCROLL:
  case OP_BATCH:
    return 1;
  case OP_INVALID:
  case OP_PING:
  case OP_HELLO:
  case OP_CONFIRM_SUBSCRIBE:
  case OP_CONFIRM_REQUEST:
  case OP_CONFIRM_DECIDE:
    return 0;
  }
  return 0;
}

/* The keycode a human needs to see, or 0 where the opcode has none.
   MOVE_ABS deliberately reports 0 rather than coordinates: the prompt
   says "this client wants to move the pointer", which is the decision
   being made, and pixel values would be content rather than intent. */
static uint16_t confirm_keycode_of(const struct conn *c) {
  if (c->parked_hdr.opcode == OP_KEY_TAP ||
      c->parked_hdr.opcode == OP_KEY_DOWN ||
      c->parked_hdr.opcode == OP_KEY_UP) {
    struct uictl_payload_key k;
    decode_key(c->parked_payload, &k);
    return k.keycode;
  }
  return 0;
}

/* Stage the prompt on the confirmer's connection. Unlike every other
   frame the daemon writes, this is not a response: the header is built
   here rather than echoed from a request, and `seq` carries the token so
   a confirmer can correlate without decoding the payload. */
static int confirm_push(struct conn *cf, const struct conn *req,
                        uint32_t token) {
  struct uictl_payload_confirm_req p;
  memset(&p, 0, sizeof(p));
  p.token = token;
  p.peer_pid = (uint32_t)req->cred.pid;
  p.opcode = req->parked_hdr.opcode;
  p.keycode = confirm_keycode_of(req);
  p.cl = (uint16_t)req->cl;
  memcpy(p.client_name, req->client_name, sizeof(p.client_name));

  struct uictl_frame_header h = {.version = cf->proto_selected,
                                 .opcode = OP_CONFIRM_REQUEST,
                                 .source_tag = 0,
                                 .seq = token,
                                 .payload_len = sizeof(p)};
  if (HDR_SIZE + sizeof(p) > sizeof(cf->out))
    return -1;
  encode_frame_header(&h, cf->out);
  memcpy(cf->out + HDR_SIZE, &p, sizeof(p));
  cf->out_len = HDR_SIZE + sizeof(p);
  cf->out_sent = 0;
  return 0;
}

/* Park `c`'s current frame and prompt. Returns OK if parked (the caller
   must NOT reply), or the result code to answer with instead. */
static uint16_t confirm_park(int epfd, struct conn *c) {
  if (pending_confirm.active)
    return ERR_BUSY; /* one at a time, see the CONFIRM_* constants */
  if (c->hdr.payload_len > CONFIRM_MAX_PAYLOAD)
    return ERR_TOO_LARGE;

  struct conn *cf = confirmer_conn();
  if (!cf)
    return ERR_CONFIRM_UNAVAILABLE;
  /* A confirmer with a reply still going out cannot be handed a prompt:
     there is one out buffer, and staging over it would drop whichever
     frame lost the race. Retryable, and in practice a millisecond. */
  if (cf->out_sent < cf->out_len)
    return ERR_BUSY;

  c->parked_hdr = c->hdr;
  memset(c->parked_payload, 0, sizeof(c->parked_payload));
  memcpy(c->parked_payload, c->buf, c->hdr.payload_len);

  uint32_t token = confirm_token_next++;
  if (confirm_token_next == 0)
    confirm_token_next = 1;

  if (confirm_push(cf, c, token) < 0)
    return ERR_INTERNAL;

  pending_confirm.active = 1;
  pending_confirm.token = token;
  pending_confirm.slot = (int)(c - conns);
  pending_confirm.gen = c->generation;
  pending_confirm.since = mono_secs();
  pending_confirm.opcode = c->hdr.opcode;

  c->awaiting_confirm = 1;
  /* Drop EPOLLIN on the requester now, not after the flush: until the
     answer arrives this connection must not be read from at all. */
  (void)conn_update_events(epfd, c);

  int flushed = conn_flush(cf);
  if (flushed < 0) {
    /* The confirmer's socket died between the check and the write. Undo
       the park rather than leave the requester waiting on a prompt that
       was never delivered. */
    pending_confirm.active = 0;
    c->awaiting_confirm = 0;
    (void)conn_update_events(epfd, c);
    return ERR_CONFIRM_UNAVAILABLE;
  }
  if (flushed > 0) {
    if (cf->out_since == 0)
      cf->out_since = mono_secs();
    (void)conn_update_events(epfd, cf);
  }
  return OK;
}

/* One complete, size-validated frame is in c->hdr + c->buf. */
/* The daemon's self-description, answered to every accepted HELLO
   (M3.6 task 3). Built once per call rather than held in a static so
   the fields stay next to the code that justifies them; it is 24 bytes.

   The two bitmaps are the contract. `daemon_version` is deliberately
   *not* — a client that branches on it is feature-sniffing, and the
   whole point of shipping a capability map is that it never has to. */
/* What the device actually came up with, from uinput_open(). File scope
   because conn_handle_frame answers HELLO and has no route to main's
   locals; written exactly once, before the first accept. */
static uint16_t g_device_caps;

/* The one place platform capabilities become wire capabilities.
   The assert is the guard rail: add a UINPUT_CAP_* flag without adding
   its wire bit here and the BUILD fails, instead of the daemon quietly
   advertising less than it can do. Drift between what the device is and
   what clients are told is exactly the kind of bug that surfaces as
   "muvor thinks there's no keyboard" three milestones later. */
static uint16_t wire_caps_from_uinput(uint32_t hal_caps) {
  _Static_assert(UINPUT_CAP__ALL ==
                     (UINPUT_CAP_POINTER_ABS | UINPUT_CAP_KEYBOARD |
                      UINPUT_CAP_POINTER_REL | UINPUT_CAP_BUTTONS),
                 "a platform capability was added — map it to a wire CAP_* "
                 "bit here and extend this assert");
  uint16_t caps = 0;
  if (hal_caps & UINPUT_CAP_POINTER_ABS)
    caps |= CAP_POINTER_ABS;
  if (hal_caps & UINPUT_CAP_KEYBOARD)
    caps |= CAP_KEYBOARD;
  if (hal_caps & UINPUT_CAP_POINTER_REL)
    caps |= CAP_POINTER_REL;
  if (hal_caps & UINPUT_CAP_BUTTONS)
    caps |= CAP_BUTTONS;
  return caps;
}

static struct uictl_resp_hello daemon_capabilities(uint16_t proto_selected) {
  struct uictl_resp_hello r = {
      .proto_selected = proto_selected,
      /* Reported, not asserted: whatever the device really has. Since
         M4 step 1 that includes CAP_KEYBOARD — the device can emit every
         keycode — while `opcode_bitmap` below still has no key opcode,
         because nothing can *ask* for one yet. That gap is the whole
         reason the two fields are separate: capability is not
         permission, and a client must gate on the opcode bit. */
      .device_caps = g_device_caps,
      .abs_range_max = (uint32_t)ABS_RANGE_MAX,
      /* OP_KEY_TAP joins the map in M4 step 7 and not before: the bitmap
         is the contract, and it may only advertise what is fully wired —
         validated, gated by the deny-list, and actually injected. */
      /* KEY_DOWN/KEY_UP join in M4.5 task 3, and only because tasks 1,
         2 and 4 are in the same build: ownership recorded, released on
         every way a connection can end, and force-released if a live
         client holds too long. Advertising a way to hold a key without
         all three would be advertising a stuck key. */
      /* All three confirmation opcodes are advertised, including
         OP_CONFIRM_REQUEST, which no client ever sends: the bit means
         "this daemon speaks that frame", and a confirmer needs to know
         the daemon can push before it subscribes and waits forever. */
      .opcode_bitmap = UICTL_OP_BIT(OP_PING) | UICTL_OP_BIT(OP_MOVE_ABS) |
                       UICTL_OP_BIT(OP_HELLO) | UICTL_OP_BIT(OP_KEY_TAP) |
                       UICTL_OP_BIT(OP_KEY_SEQUENCE) |
                       UICTL_OP_BIT(OP_KEY_DOWN) | UICTL_OP_BIT(OP_KEY_UP) |
                       UICTL_OP_BIT(OP_CONFIRM_SUBSCRIBE) |
                       UICTL_OP_BIT(OP_CONFIRM_REQUEST) |
                       UICTL_OP_BIT(OP_CONFIRM_DECIDE) |
                       UICTL_OP_BIT(OP_BUTTON) | UICTL_OP_BIT(OP_MOVE_REL) |
                       UICTL_OP_BIT(OP_SCROLL) | UICTL_OP_BIT(OP_BATCH),
      .daemon_version = UICTL_DAEMON_VERSION,
      .reserved = 0,
  };
  return r;
}

/* May this connection send a frame stamped with this version?
   (M3.6 task 4 — replaces a bare `version != UICTL_PROTO_VERSION`.)

   Two regimes, and the second is the one that matters. Before HELLO,
   anything the daemon speaks is admissible — a client has to be able to
   get a frame in to negotiate at all. After HELLO the version is
   *pinned* to what was selected: allowing a client to hop versions
   mid-connection would mean the same opcode could carry two different
   payload layouts on one stream, and the daemon would be guessing which
   one it just parsed. Negotiation that can be revised isn't
   negotiation. */
static int conn_version_ok(const struct conn *c, uint16_t version,
                           uint16_t opcode) {
  if (c->proto_selected != 0)
    return version == c->proto_selected;
  /* The bootstrap exemption. An un-negotiated HELLO is admitted at any
     version, because the alternative makes negotiation impossible for
     the only clients that need it: a client whose range excludes ours
     cannot send a frame we would admit, and cannot learn to until it has
     asked. Refusing it here would leave the intersection below
     unreachable — the frame would die at the header, and "we disagree
     about versions" would be indistinguishable from "your frame is
     garbage". The envelope is fixed across versions and payload_len is
     still bounded, so admitting it costs nothing. */
  if (opcode == OP_HELLO)
    return 1;
  return version >= UICTL_PROTO_MIN && version <= UICTL_PROTO_MAX;
}

/* `resumed` is set only by the confirmation path re-feeding a request a
   human just approved (M5). It skips the two steps that must happen
   exactly once per request rather than once per dispatch: the rate-limit
   charge, and the park itself. Charging twice would make confirmation
   cost a client double; parking twice would prompt forever. */
static void conn_handle_frame(int epfd, struct conn *c, const struct uinput_devs *devs,
                              int audit_fd, int resumed) {
  uint16_t result;
  /* 128, not 64: a 31-char client name plus the negotiated version, the
     range it asked for and its class does not fit in 64, and snprintf
     would truncate the *class* — the policy-relevant half — off the end
     of the one record that is supposed to explain a decision. */
  char args[128];
  args[0] = '\0';

  /* Most opcodes are commands and answer with a bare result. An opcode
     that answers a *question* points these at its payload before the
     shared reply at the bottom. */
  const void *resp_data = NULL;
  size_t resp_len = 0;
  struct uictl_resp_hello caps; /* must outlive the switch */

  /* Handshake enforcement (M3.6 task 7). Checked BEFORE the opcode
     switch, so an un-handshaked peer is told to handshake rather than
     told which opcodes exist — the refusal reveals nothing about the
     daemon's surface, and there is exactly one thing it can do next.
     ERR_OPCODE_UNKNOWN for an unknown opcode is a post-handshake answer.

     OP_PING is exempt on purpose: it stays usable as a bare liveness
     probe, which is what a supervisor, a health check or `uictl ping`
     wants, and it neither reads state nor touches the device. OP_HELLO
     is exempt for the obvious reason. Everything else — every opcode
     that has ever moved the pointer or will ever press a key — goes
     through the handshake, because that is where the class M4's policy
     reads gets derived. Without this, a client skips HELLO and operates
     at whatever the un-negotiated default is, forever. */
  /* Rate limit (M4 step 10), charged only for requests that reach the
     device. PING and HELLO are free: a liveness probe and a handshake
     are how a client finds out it is being limited, and making them
     cost budget would mean a throttled client cannot ask why. That is
     the same reasoning that exempts PING from the handshake.

     Cost: one unit per device request, except a sequence, which costs
     one per *press* — a 16-key combo is sixteen keystrokes and pretending
     otherwise would make the sequence opcode a way around the limit.

     Charged BEFORE validation deliberately: a client hammering the
     daemon with malformed frames is still hammering it, and a limiter
     that only counts well-formed requests does not limit the case you
     most want limited. */
  /* OP_KEY_UP is NOT in this set, and that is a safety decision rather
     than a generosity. A client that has spent its budget holding keys
     down must still be able to put them back up; charging the release
     means the way to get a stuck key is to be slightly too fast. Same
     shape as the PING/HELLO exemption — never make the escape hatch
     depend on the resource that ran out. OP_KEY_DOWN *is* charged: it is
     a device write like any other, and it is the half a client can be
     told to slow down without consequence. */
  if (!resumed &&
      (c->hdr.opcode == OP_MOVE_ABS || c->hdr.opcode == OP_KEY_TAP ||
       c->hdr.opcode == OP_KEY_DOWN || c->hdr.opcode == OP_KEY_SEQUENCE ||
       c->hdr.opcode == OP_MOVE_REL || c->hdr.opcode == OP_SCROLL ||
       c->hdr.opcode == OP_BATCH ||
       /* A button DOWN is charged; a button UP is not, for the same
          reason OP_KEY_UP is not: a client that has run out of budget
          must still be able to let go. Checked on the payload, which is
          why this reads the buffer rather than only the opcode. */
       (c->hdr.opcode == OP_BUTTON &&
        c->hdr.payload_len == sizeof(struct uictl_payload_button) &&
        ((const struct uictl_payload_button *)(const void *)c->buf)->down))) {
    unsigned cost = 1;
    if (c->hdr.opcode == OP_KEY_SEQUENCE &&
        c->hdr.payload_len >= sizeof(struct uictl_payload_key_seq)) {
      struct uictl_payload_key_seq peek;
      memcpy(&peek, c->buf, sizeof(peek));
      if (peek.count > 0 && peek.count <= UICTL_SEQ_MAX &&
          c->hdr.payload_len == uictl_seq_payload_len(peek.count)) {
        unsigned presses = 0;
        for (uint16_t i = 0; i < peek.count; i++) {
          struct uictl_seq_item it;
          memcpy(&it, c->buf + sizeof(peek) + (size_t)i * sizeof(it),
                 sizeof(it));
          if (it.value == 1)
            presses++;
        }
        if (presses)
          cost = presses;
      }
    }
    int global_trip = 0;
    if (!rate_allow(c->cred.pid, c->cl, cost, &global_trip)) {
      /* Naming which limit tripped matters: "your class is 5/s" and
         "the daemon as a whole is saturated" call for different
         responses, and only one of them is about this client. */
      if (global_trip)
        snprintf(args, sizeof(args),
                 "rate limited (daemon-wide %u/s, cost=%u)",
                 (unsigned)RATE_GLOBAL_PER_SEC, cost);
      else
        snprintf(args, sizeof(args), "rate limited (class=%s, %u/s, cost=%u)",
                 class_name(c->cl), rate_classes[c->cl].per_sec, cost);
      audit_log(audit_fd, c->cred.pid, c->cred.uid, c->hdr.source_tag,
                c->hdr.opcode, c->hdr.seq, ERR_RATE_LIMITED, args);
      conn_reply(c, ERR_RATE_LIMITED);
      return;
    }
  }

  if (!c->hello_seen && c->hdr.opcode != OP_HELLO &&
      c->hdr.opcode != OP_PING) {
    audit_log(audit_fd, c->cred.pid, c->cred.uid, c->hdr.source_tag,
              c->hdr.opcode, c->hdr.seq, ERR_HANDSHAKE_REQUIRED, "no hello");
    /* Per-frame, not fatal: the frame was fully consumed, so the next
       boundary is known and the client can simply say HELLO and retry
       on this same connection. */
    conn_reply(c, ERR_HANDSHAKE_REQUIRED);
    return;
  }

  /* The confirmation gate (M5). Sits after the handshake — the role is
     derived from the name a HELLO established — and after the rate
     limit, so a flooding client is refused before a human is bothered.
     It sits BEFORE the opcode switch, so there is exactly one place a
     confirmable request can slip past, and `op_touches_device` is a
     switch with no default so a new opcode cannot quietly skip it.

     Note what is being gated: the client's *role*, not its source_tag.
     The plan's original sketch keyed this on `source_tag & SRC_LLM`,
     which the client writes itself — the LLM agent would simply not set
     the bit. That is G2, and proto.h names a confirmation prompt as one
     of the things that must never read that field. */
  if (!resumed && op_touches_device(c->hdr.opcode) && !op_is_release(c) &&
      (c->roles & ROLE_CONFIRM)) {
    uint16_t parked = confirm_park(epfd, c);
    if (parked == OK) {
      /* No reply, no audit line yet: nothing has been decided. The
         request is recorded when it resolves, with the outcome. */
      return;
    }
    snprintf(args, sizeof(args), "confirmation not started");
    audit_log(audit_fd, c->cred.pid, c->cred.uid, c->hdr.source_tag,
              c->hdr.opcode, c->hdr.seq, parked, args);
    conn_reply(c, parked);
    return;
  }

  switch (c->hdr.opcode) {
  case OP_PING:
    result = (c->hdr.payload_len == 0) ? OK : ERR_PAYLOAD_INVALID;
    break;
  case OP_MOVE_ABS: {
    if (c->hdr.payload_len != sizeof(struct uictl_payload_move_abs)) {
      result = ERR_PAYLOAD_INVALID;
      break;
    }
    struct uictl_payload_move_abs mv;
    decode_move_abs(c->buf, &mv);
    /* audit records intent: the value asked for, before clamping */
    snprintf(args, sizeof(args), "x=%d y=%d", mv.x, mv.y);
    if (mv.x < 0)
      mv.x = 0;
    if (mv.x > ABS_RANGE_MAX)
      mv.x = ABS_RANGE_MAX;
    if (mv.y < 0)
      mv.y = 0;
    if (mv.y > ABS_RANGE_MAX)
      mv.y = ABS_RANGE_MAX;
    result = (uinput_move_abs(devs->pointer, mv.x, mv.y) < 0) ? ERR_INTERNAL : OK;
    break;
  }
  case OP_HELLO: {
    /* >=, not ==, for the same reason the client accepts a longer
       response: HELLO is the bootstrap frame, so a v2 client's longer
       HELLO must still be readable by a v1 daemon — otherwise it gets
       ERR_PAYLOAD_INVALID and never learns that the real disagreement
       was about versions. The prefix is fixed forever; the tail is
       whatever a newer version appended and is ignored here. */
    if (c->hdr.payload_len < sizeof(struct uictl_payload_hello)) {
      result = ERR_PAYLOAD_INVALID;
      break;
    }
    /* One HELLO per connection, and it is terminal, not retryable. A
       second one would let a client rename itself *after* the daemon has
       attached a class to the first name — which is exactly the
       per-frame self-assertion (G2) this frame exists to replace. The
       connection is the scope of the handshake; a client that wants a
       different identity opens a different connection. */
    if (c->hello_seen) {
      result = ERR_DENIED_BY_POLICY;
      snprintf(args, sizeof(args), "duplicate hello name=%s", c->client_name);
      break;
    }

    struct uictl_payload_hello hello;
    decode_hello(c->buf, &hello);

    if (!uictl_client_name_valid(hello.client_name)) {
      /* Deliberately does NOT echo the offending name — it just failed
         the check that makes it safe to put in a newline-delimited log. */
      result = ERR_PAYLOAD_INVALID;
      snprintf(args, sizeof(args), "bad client name");
      break;
    }
    if (hello.proto_min > hello.proto_max) {
      result = ERR_PAYLOAD_INVALID;
      snprintf(args, sizeof(args), "inverted proto range %u-%u",
               hello.proto_min, hello.proto_max);
      break;
    }
    /* The frame is self-describing, so it must not contradict itself:
       a client claiming to speak 2-3 while stamping this very header
       version 1 has a bug, and guessing which half to believe is how a
       negotiation ends up with two disagreeing parties who both think
       they succeeded. */
    if (c->hdr.version < hello.proto_min || c->hdr.version > hello.proto_max) {
      result = ERR_PAYLOAD_INVALID;
      snprintf(args, sizeof(args), "header v%u outside declared %u-%u",
               c->hdr.version, hello.proto_min, hello.proto_max);
      break;
    }

    /* The intersection (M3.6 task 4). Highest mutually supported wins:
       both sides claim to speak everything in their range, so the newest
       common version is the one with the most features and no downside.

       ERR_VERSION here is a *per-frame* error, not the fatal kind the
       header check raises. The difference is whether the next frame
       boundary is knowable: a bad header version means payload_len is
       untrustworthy and the stream is lost, whereas here the payload was
       already read and validated, so the connection survives. It stays
       usable on purpose — hello_seen is only set on success, so a client
       may retry HELLO with a different range on the same connection. */
    uint16_t lo = hello.proto_min > UICTL_PROTO_MIN ? hello.proto_min
                                                    : (uint16_t)UICTL_PROTO_MIN;
    uint16_t hi = hello.proto_max < UICTL_PROTO_MAX ? hello.proto_max
                                                    : (uint16_t)UICTL_PROTO_MAX;
    if (lo > hi) {
      result = ERR_VERSION;
      snprintf(args, sizeof(args), "no overlap: client %u-%u daemon %u-%u",
               hello.proto_min, hello.proto_max, UICTL_PROTO_MIN,
               UICTL_PROTO_MAX);
      break;
    }

    /* M9: a registry entry may bind its name to one binary. Checked
       BEFORE anything is assigned to the connection, so a peer that
       fails the binding gets no class, no roles and no negotiated
       version out of the attempt -- a partial application here would be
       the "identity that starts permissive and gets narrowed later"
       that conn_alloc's comment warns about, arriving through a
       different door.

       Fails closed on an unknown exe. If /proc could not be read, or
       the binary was replaced since it started, the daemon cannot show
       that this peer is the bound program, and "cannot show" is the
       only answer a check like this may give. */
    {
      const struct client_reg *bind = reg_for_name(hello.client_name);
      if (bind && bind->has_exe) {
        if (c->exe[0] == '\0') {
          result = ERR_DENIED_BY_POLICY;
          snprintf(args, sizeof(args),
                   "name=%s is bound to a binary and this peer's exe is "
                   "unknown",
                   hello.client_name);
          break;
        }
        if (strcmp(c->exe, bind->exe) != 0) {
          /* NEITHER path goes in the audit line, for two different
             reasons. The peer's is attacker-chosen text heading for a
             newline-delimited log -- the same reasoning that stops a
             rejected client name being echoed (WIRE.md §3.5). The
             registry's is safe but long, and a path plus this record's
             fixed prefix does not fit in an audit line, so including it
             would mean truncating it mid-path: the one part of the
             record somebody is reading it for.

             The line says which name failed and why. The expected path
             goes to stderr, which is not newline-delimited machine
             output and is where an operator diagnosing their own
             registry is already looking. */
          result = ERR_DENIED_BY_POLICY;
          snprintf(args, sizeof(args),
                   "name=%s is bound to a different binary",
                   hello.client_name);
          fprintf(stderr,
                  "uictld: refused HELLO name=%s from pid %d: the registry "
                  "binds that name to\n         %s\n",
                  hello.client_name, (int)c->cred.pid, bind->exe);
          break;
        }
      }
    }

    c->proto_min = hello.proto_min;
    c->proto_max = hello.proto_max;
    c->proto_selected = hi;
    memcpy(c->client_name, hello.client_name, sizeof(c->client_name));
    c->cl = class_for_name(c->client_name);
    c->roles = roles_for_name(c->client_name);
    c->hello_seen = 1;

    caps = daemon_capabilities(c->proto_selected);
    /* §8.6. Filled here rather than in daemon_capabilities() because it
       is the only field in the response that depends on *which* client
       is asking — everything else is a property of the daemon and the
       device, identical on every connection. */
    {
      const struct client_reg *reg = reg_for_name(c->client_name);
      if (reg) {
        caps.reconnect_mode = reg->reconnect_mode;
        caps.reconnect_max_tries = reg->reconnect_max_tries;
        caps.reconnect_base_ms = reg->reconnect_base_ms;
      }
      /* else: left at RECONNECT_UNSPEC/0/0 from the initialiser, which
         is what an older daemon's absent tail also means. */
    }
    resp_data = &caps;
    resp_len = sizeof(caps);

    /* Both halves: the range the client asked for is its *intent*, the
       selected version and derived class are the daemon's *decision*.
       Security rule 5 wants the first; a policy audit needs the second. */
    snprintf(args, sizeof(args), "name=%s proto=%u asked=%u-%u class=%s",
             c->client_name, c->proto_selected, c->proto_min, c->proto_max,
             class_name(c->cl));
    result = OK;
    break;
  }
  case OP_KEY_TAP: {
    /* The full path, in the order the milestone built it: size check
       (step 5), range check (step 5), deny-list (step 6), allowlist
       (step 8), inject (step 7). Nothing was ever reachable before the check above it
       existed — that ordering is why no build in this milestone's
       history could turn a socket into an arbitrary keystroke.

       Exact size, not >=: a command frame is only sent after the version
       is negotiated and pinned, so there is no version skew to absorb
       and a wrong length means a broken client. */
    if (c->hdr.payload_len != sizeof(struct uictl_payload_key)) {
      result = ERR_PAYLOAD_INVALID;
      break;
    }
    struct uictl_payload_key key;
    decode_key(c->buf, &key);

    /* Range, not policy. The device registered 1..KEY_MAX and the kernel
       would reject anything else; *which* of those keys a client may ask
       for is step 6's deny-list, a separate question with a separate
       answer and a different result code (ERR_DENIED_BY_POLICY). Keeping
       them apart is what stops "invalid" and "forbidden" from blurring
       into one unreadable audit trail. */
    if (key.keycode == 0 || key.keycode > UINPUT_KEY_CODE_MAX) {
      snprintf(args, sizeof(args), "code=%u out of range", key.keycode);
      result = ERR_PAYLOAD_INVALID;
      break;
    }

    /* Policy, checked while the handler is still a stub (M4 step 6).
       This is the ordering the whole milestone is built around: the
       deny-list exists before any build can turn a socket into a
       keystroke, so there is no window — not even one commit wide — in
       which arbitrary keys are reachable.

       ERR_DENIED_BY_POLICY, not ERR_PAYLOAD_INVALID: the request was
       well-formed and the answer is "you may not". A client can tell
       "fix your encoder" from "that key is off limits", and the audit
       log records which of the two happened. */
    const char *why = NULL;
    if (uinput_keycode_denied(key.keycode, &why)) {
      snprintf(args, sizeof(args), "code=%u denied (%s)", key.keycode, why);
      result = ERR_KEY_DENYLISTED;
      break;
    }

    /* Default-deny (M4 step 8). Checked after the deny-list so that a
       destructive key reports the specific reason it is forbidden
       rather than the generic "not allowed" — the audit line should say
       *why*, and "power" is more use than "absent from a config file".
       Both answer ERR_DENIED_BY_POLICY: to the client they are the same
       kind of no. */
    if (!key_allowed(key.keycode)) {
      snprintf(args, sizeof(args), "code=%u not in allowlist", key.keycode);
      result = ERR_KEY_NOT_ALLOWED;
      break;
    }

    /* M4 step 7: the injection, and note where it sits — *after* the
       size check, the range check, the deny-list and the allowlist, and
       nowhere else.
       There is exactly one call site, so "which keys can reach the
       device" is answerable by reading the lines above it.

       Audit BEFORE the write is not what happens here (the shared
       audit_log call is below, after the switch) and that is deliberate:
       the record then carries the real result, including ERR_INTERNAL if
       the device write failed. An audit line saying a key was injected
       when the write failed would be worse than a late one. */
    snprintf(args, sizeof(args), "code=%u", key.keycode);
    result = (uinput_key_tap(devs->keyboard, key.keycode) < 0) ? ERR_INTERNAL : OK;
    break;
  }
  case OP_KEY_DOWN: {
    /* Same gate as KEY_TAP — size, range, deny-list, allowlist — and
       then the part that is new in M4.5: arbitration. The order is not
       arbitrary. Policy first, so a destructive key is refused for being
       destructive rather than for being busy; ownership last, because it
       is the only check whose answer depends on other clients and can
       change between two identical requests. */
    if (c->hdr.payload_len != sizeof(struct uictl_payload_key)) {
      result = ERR_PAYLOAD_INVALID;
      break;
    }
    struct uictl_payload_key key;
    decode_key(c->buf, &key);

    if (key.keycode == 0 || key.keycode > UINPUT_KEY_CODE_MAX) {
      snprintf(args, sizeof(args), "code=%u out of range", key.keycode);
      result = ERR_PAYLOAD_INVALID;
      break;
    }
    const char *why = NULL;
    if (uinput_keycode_denied(key.keycode, &why)) {
      snprintf(args, sizeof(args), "code=%u denied (%s)", key.keycode, why);
      result = ERR_KEY_DENYLISTED;
      break;
    }
    if (!key_allowed(key.keycode)) {
      snprintf(args, sizeof(args), "code=%u not in allowlist", key.keycode);
      result = ERR_KEY_NOT_ALLOWED;
      break;
    }

    /* Arbitration, three questions in the order that gives the most
       specific answer first. */
    if (conn_holds(c, key.keycode)) {
      /* Not idempotent-on-purpose. Silently acking would leave the
         client believing it holds one key while owing one UP, and the
         accounting error surfaces later as a key that will not press. A
         real keyboard's repeat is EV_KEY value 2, a different thing that
         this protocol does not model. */
      snprintf(args, sizeof(args), "code=%u already held by this connection",
               key.keycode);
      result = ERR_KEY_ALREADY_HELD;
      break;
    }
    struct conn *owner = conn_holder_of(key.keycode, c);
    if (owner) {
      /* The audit line names the other peer; the client is told only
         that someone else holds it. Which pid is a fact about a
         different process of the same user, and open question 4 leans
         against handing peer identities to clients — the operator gets
         it via the audit log and SIGUSR1 instead. */
      snprintf(args, sizeof(args), "code=%u held by pid=%d (%s)", key.keycode,
               (int)owner->cred.pid,
               owner->hello_seen ? owner->client_name : "-");
      result = ERR_KEY_HELD_BY_OTHER;
      break;
    }
    if (c->held_count >= MAX_HELD_PER_CONN) {
      snprintf(args, sizeof(args), "code=%u refused, already holding %d",
               key.keycode, c->held_count);
      result = ERR_TOO_MANY_HELD;
      break;
    }

    /* Press, then record — never the other way round. If the write
       fails there is nothing held, and a bitset that says otherwise
       would make the connection's release-on-close emit an UP for a key
       that was never down. The reverse ordering is also what makes the
       failure safe: a recorded hold with no press is invisible until it
       produces a spurious release. */
    struct uinput_key_event down = {.code = key.keycode, .value = 1};
    if (uinput_key_seq(devs->keyboard, &down, 1) < 0) {
      snprintf(args, sizeof(args), "code=%u write failed", key.keycode);
      result = ERR_INTERNAL;
      break;
    }
    conn_hold_add(c, key.keycode);
    snprintf(args, sizeof(args), "code=%u held (%d total)", key.keycode,
             c->held_count);
    result = OK;
    break;
  }
  case OP_BUTTON: {
    /* Buttons are held state, exactly like keys, and reuse M4.5's
       machinery unchanged: the same per-connection bitset, the same
       arbitration, the same release on disconnect and the same dead-man
       timer. That reuse is only correct because BTN_* codes live in the
       kernel's keycode space, which is why the held bitset was sized
       0..KEY_MAX rather than 0..(number of keys).

       What is NOT reused is the allowlist. ~/.config/uictl/policy is a
       list of *keycodes* a user opted into, and requiring `272` in it
       before a client may click would be a default-deny with no upside:
       the pointer is not a destructive surface the way KEY_POWER is, a
       click is visible and reversible, and a user who wanted to forbid
       clicking would have to be told to write a number they have no way
       to look up. The deny-list still applies — it just happens to
       contain no buttons. */
    if (c->hdr.payload_len != sizeof(struct uictl_payload_button)) {
      result = ERR_PAYLOAD_INVALID;
      break;
    }
    struct uictl_payload_button b;
    memcpy(&b, c->buf, sizeof(b));
    if (b.reserved != 0 || b.down > 1) {
      result = ERR_PAYLOAD_INVALID;
      break;
    }
    if (!uinput_is_button(b.code)) {
      snprintf(args, sizeof(args), "code=%u is not a button", b.code);
      result = ERR_PAYLOAD_INVALID;
      break;
    }
    const char *bwhy = NULL;
    if (uinput_keycode_denied(b.code, &bwhy)) {
      snprintf(args, sizeof(args), "code=%u denied (%s)", b.code, bwhy);
      result = ERR_KEY_DENYLISTED;
      break;
    }

    if (b.down) {
      if (conn_holds(c, b.code)) {
        snprintf(args, sizeof(args), "code=%u already held", b.code);
        result = ERR_KEY_ALREADY_HELD;
        break;
      }
      struct conn *bowner = conn_holder_of(b.code, c);
      if (bowner) {
        /* This is G9's pointer-contention case arriving for real: two
           clients dragging with the same button is the scenario where
           "whoever releases first releases it for both" produces a drag
           that never ends. */
        snprintf(args, sizeof(args), "code=%u held by pid=%d", b.code,
                 (int)bowner->cred.pid);
        result = ERR_KEY_HELD_BY_OTHER;
        break;
      }
      if (c->held_count >= MAX_HELD_PER_CONN) {
        result = ERR_TOO_MANY_HELD;
        break;
      }
      if (uinput_button(devs->pointer, b.code, 1) < 0) {
        result = ERR_INTERNAL;
        break;
      }
      conn_hold_add(c, b.code);
      snprintf(args, sizeof(args), "code=%u down", b.code);
    } else {
      if (!conn_holds(c, b.code)) {
        /* Same forgiving window as OP_KEY_UP — WIRE.md §8.3.1. A drag
           interrupted by a daemon restart is the motivating case: the
           button went up when the old connection died, and the client's
           "finish the drag" release lands here on the new one. */
        if (!c->held_ever) {
          snprintf(args, sizeof(args), "code=%u not held, forgiven (§8.3.1)",
                   b.code);
          result = OK;
          break;
        }
        snprintf(args, sizeof(args), "code=%u not held", b.code);
        result = ERR_KEY_NOT_HELD;
        break;
      }
      conn_hold_drop(c, b.code);
      if (uinput_button(devs->pointer, b.code, 0) < 0) {
        result = ERR_INTERNAL;
        break;
      }
      snprintf(args, sizeof(args), "code=%u up", b.code);
    }
    result = OK;
    break;
  }
  case OP_MOVE_REL: {
    if (c->hdr.payload_len != sizeof(struct uictl_payload_move_rel)) {
      result = ERR_PAYLOAD_INVALID;
      break;
    }
    struct uictl_payload_move_rel mv;
    memcpy(&mv, c->buf, sizeof(mv));
    /* Bounded, unlike MOVE_ABS which is clamped. A relative delta has no
       natural ceiling to clamp to, and silently shrinking a nudge from
       100000 to 32767 would leave a client wondering why its pointer
       moved a different distance than it asked for. Out of range is an
       error; in range is exact. */
    if (mv.dx < -ABS_RANGE_MAX || mv.dx > ABS_RANGE_MAX ||
        mv.dy < -ABS_RANGE_MAX || mv.dy > ABS_RANGE_MAX) {
      snprintf(args, sizeof(args), "dx=%d dy=%d out of range", mv.dx, mv.dy);
      result = ERR_PAYLOAD_INVALID;
      break;
    }
    if (mv.dx == 0 && mv.dy == 0) {
      result = ERR_PAYLOAD_INVALID;
      break;
    }
    snprintf(args, sizeof(args), "dx=%d dy=%d", mv.dx, mv.dy);
    result = (uinput_move_rel(devs->pointer, mv.dx, mv.dy) < 0) ? ERR_INTERNAL
                                                                : OK;
    break;
  }
  case OP_SCROLL: {
    if (c->hdr.payload_len != sizeof(struct uictl_payload_scroll)) {
      result = ERR_PAYLOAD_INVALID;
      break;
    }
    struct uictl_payload_scroll sc;
    memcpy(&sc, c->buf, sizeof(sc));
    /* Notches, not pixels. A bound well below the int32 range because
       the hi-res value is 120x the notch count and must not overflow —
       a client asking for 20 million notches is broken, not scrolling. */
    const int32_t max_notches = 1000;
    if (sc.notches_v < -max_notches || sc.notches_v > max_notches ||
        sc.notches_h < -max_notches || sc.notches_h > max_notches) {
      snprintf(args, sizeof(args), "v=%d h=%d out of range", sc.notches_v,
               sc.notches_h);
      result = ERR_PAYLOAD_INVALID;
      break;
    }
    if (sc.notches_v == 0 && sc.notches_h == 0) {
      result = ERR_PAYLOAD_INVALID;
      break;
    }
    snprintf(args, sizeof(args), "v=%d h=%d", sc.notches_v, sc.notches_h);
    result = (uinput_scroll(devs->pointer, sc.notches_v, sc.notches_h) < 0)
                 ? ERR_INTERNAL
                 : OK;
    break;
  }
  case OP_BATCH: {
    /* All-or-nothing, in two passes, for the reason OP_KEY_SEQUENCE is:
       a per-item check-then-write loop leaves a rejected item's
       predecessors already delivered, and when one of those was a press
       that is the stuck-key scenario arriving through the back door.
       Pass 1 validates every item; pass 2 writes. Nothing between them
       can fail on policy grounds.

       The batch is atomic PER DEVICE (see proto.h). Pointer items go out
       as one frame with one SYN_REPORT, keyboard items as another. A
       modifier+click therefore lands as two reports — which is what it
       is on real hardware too, where the modifier comes from a keyboard
       and the click from a mouse. */
    if (c->hdr.payload_len < sizeof(struct uictl_payload_batch)) {
      result = ERR_PAYLOAD_INVALID;
      break;
    }
    struct uictl_payload_batch bh;
    memcpy(&bh, c->buf, sizeof(bh));
    if (bh.reserved != 0 || bh.count == 0 || bh.count > UICTL_BATCH_MAX ||
        c->hdr.payload_len != uictl_batch_payload_len(bh.count)) {
      snprintf(args, sizeof(args), "bad batch header count=%u len=%u", bh.count,
               c->hdr.payload_len);
      result = ERR_PAYLOAD_INVALID;
      break;
    }

    struct uictl_batch_item items[UICTL_BATCH_MAX];
    memcpy(items, c->buf + sizeof(bh),
           (size_t)bh.count * sizeof(struct uictl_batch_item));

    /* PASS 1 — structure, range and policy for every item.
       `would_hold` tracks presses this batch has already accounted for,
       so a batch containing the same button twice is rejected rather
       than double-counted against the held set. */
    uint16_t batch_result = OK;
    int pointer_items = 0, keyboard_items = 0;
    unsigned char would_hold[HELD_BITS_BYTES];
    memcpy(would_hold, c->held_bits, sizeof(would_hold));
    int would_count = c->held_count;

    for (uint16_t i = 0; i < bh.count && batch_result == OK; i++) {
      const struct uictl_batch_item *it = &items[i];
      if (it->reserved != 0) {
        snprintf(args, sizeof(args), "item %u reserved not zero", i);
        batch_result = ERR_PAYLOAD_INVALID;
        break;
      }
      switch (it->opcode) {
      case OP_MOVE_ABS:
      case OP_MOVE_REL:
      case OP_SCROLL:
        pointer_items++;
        if (it->opcode == OP_MOVE_REL &&
            (it->a < -ABS_RANGE_MAX || it->a > ABS_RANGE_MAX ||
             it->b < -ABS_RANGE_MAX || it->b > ABS_RANGE_MAX)) {
          snprintf(args, sizeof(args), "item %u delta out of range", i);
          batch_result = ERR_PAYLOAD_INVALID;
        } else if (it->opcode == OP_SCROLL &&
                   (it->a < -1000 || it->a > 1000 || it->b < -1000 ||
                    it->b > 1000)) {
          snprintf(args, sizeof(args), "item %u scroll out of range", i);
          batch_result = ERR_PAYLOAD_INVALID;
        }
        break;
      case OP_BUTTON: {
        pointer_items++;
        uint16_t code = (uint16_t)it->a;
        if (it->a < 0 || !uinput_is_button(code) || it->b < 0 || it->b > 1) {
          snprintf(args, sizeof(args), "item %u bad button", i);
          batch_result = ERR_PAYLOAD_INVALID;
          break;
        }
        int held_here = (would_hold[code / 8] & (1u << (code % 8))) != 0;
        if (it->b == 1) {
          if (held_here || conn_holder_of(code, c)) {
            snprintf(args, sizeof(args), "item %u code=%u already held", i,
                     code);
            batch_result = held_here ? ERR_KEY_ALREADY_HELD
                                     : ERR_KEY_HELD_BY_OTHER;
            break;
          }
          if (would_count >= MAX_HELD_PER_CONN) {
            batch_result = ERR_TOO_MANY_HELD;
            break;
          }
          would_hold[code / 8] |= (unsigned char)(1u << (code % 8));
          would_count++;
        } else {
          if (!held_here) {
            snprintf(args, sizeof(args), "item %u code=%u not held", i, code);
            batch_result = ERR_KEY_NOT_HELD;
            break;
          }
          would_hold[code / 8] &= (unsigned char)~(1u << (code % 8));
          would_count--;
        }
        break;
      }
      case OP_KEY_DOWN:
      case OP_KEY_UP: {
        keyboard_items++;
        uint16_t code = (uint16_t)it->a;
        if (it->a < 1 || it->a > UINPUT_KEY_CODE_MAX) {
          snprintf(args, sizeof(args), "item %u code out of range", i);
          batch_result = ERR_PAYLOAD_INVALID;
          break;
        }
        const char *iwhy = NULL;
        if (uinput_keycode_denied(code, &iwhy)) {
          snprintf(args, sizeof(args), "item %u code=%u denied (%s)", i, code,
                   iwhy);
          batch_result = ERR_KEY_DENYLISTED;
          break;
        }
        if (!key_allowed(code)) {
          snprintf(args, sizeof(args), "item %u code=%u not in allowlist", i,
                   code);
          batch_result = ERR_KEY_NOT_ALLOWED;
          break;
        }
        int held_here = (would_hold[code / 8] & (1u << (code % 8))) != 0;
        if (it->opcode == OP_KEY_DOWN) {
          if (held_here || conn_holder_of(code, c)) {
            batch_result =
                held_here ? ERR_KEY_ALREADY_HELD : ERR_KEY_HELD_BY_OTHER;
            snprintf(args, sizeof(args), "item %u code=%u already held", i,
                     code);
            break;
          }
          if (would_count >= MAX_HELD_PER_CONN) {
            batch_result = ERR_TOO_MANY_HELD;
            break;
          }
          would_hold[code / 8] |= (unsigned char)(1u << (code % 8));
          would_count++;
        } else {
          if (!held_here) {
            snprintf(args, sizeof(args), "item %u code=%u not held", i, code);
            batch_result = ERR_KEY_NOT_HELD;
            break;
          }
          would_hold[code / 8] &= (unsigned char)~(1u << (code % 8));
          would_count--;
        }
        break;
      }
      default:
        snprintf(args, sizeof(args), "item %u opcode %u not batchable", i,
                 it->opcode);
        batch_result = ERR_PAYLOAD_INVALID;
        break;
      }
    }
    if (batch_result != OK) {
      result = batch_result;
      break;
    }

    /* PASS 2 — write. Keyboard items first, as one frame, then pointer
       items. Order between the two devices is the modifier-before-click
       one, which is the only cross-device ordering that matters. */
    if (keyboard_items) {
      struct uinput_key_event kevs[UICTL_BATCH_MAX];
      size_t kn = 0;
      for (uint16_t i = 0; i < bh.count; i++)
        if (items[i].opcode == OP_KEY_DOWN || items[i].opcode == OP_KEY_UP) {
          kevs[kn].code = (uint16_t)items[i].a;
          kevs[kn].value = items[i].opcode == OP_KEY_DOWN ? 1 : 0;
          kn++;
        }
      if (uinput_key_seq(devs->keyboard, kevs, kn) < 0) {
        result = ERR_INTERNAL;
        break;
      }
    }
    int wrote_fail = 0;
    for (uint16_t i = 0; i < bh.count && !wrote_fail; i++) {
      const struct uictl_batch_item *it = &items[i];
      switch (it->opcode) {
      case OP_MOVE_ABS: {
        int32_t x = it->a < 0 ? 0 : (it->a > ABS_RANGE_MAX ? ABS_RANGE_MAX
                                                           : it->a);
        int32_t y = it->b < 0 ? 0 : (it->b > ABS_RANGE_MAX ? ABS_RANGE_MAX
                                                           : it->b);
        wrote_fail = uinput_move_abs(devs->pointer, x, y) < 0;
        break;
      }
      case OP_MOVE_REL:
        if (it->a || it->b)
          wrote_fail = uinput_move_rel(devs->pointer, it->a, it->b) < 0;
        break;
      case OP_SCROLL:
        if (it->a || it->b)
          wrote_fail = uinput_scroll(devs->pointer, it->a, it->b) < 0;
        break;
      case OP_BUTTON:
        wrote_fail =
            uinput_button(devs->pointer, (uint16_t)it->a, it->b == 1) < 0;
        break;
      default:
        break; /* keyboard items already went out above */
      }
    }
    if (wrote_fail) {
      result = ERR_INTERNAL;
      break;
    }

    /* The held set is updated only after every write succeeded, and from
       the shadow copy pass 1 built — so it can never claim a hold the
       device did not take. */
    for (uint16_t i = 0; i < bh.count; i++) {
      const struct uictl_batch_item *it = &items[i];
      if (it->opcode == OP_BUTTON || it->opcode == OP_KEY_DOWN ||
          it->opcode == OP_KEY_UP) {
        uint16_t code = (uint16_t)it->a;
        int down = (it->opcode == OP_KEY_DOWN) ||
                   (it->opcode == OP_BUTTON && it->b == 1);
        if (down)
          conn_hold_add(c, code);
        else
          conn_hold_drop(c, code);
      }
    }
    snprintf(args, sizeof(args), "batch n=%u (%d pointer, %d keyboard)",
             bh.count, pointer_items, keyboard_items);
    result = OK;
    break;
  }
  case OP_CONFIRM_SUBSCRIBE: {
    /* Config-gated: a client may only become the confirmer if the local
       registry gave its name the `confirmer` role. Without that check
       any client could subscribe and then approve its own requests,
       which is not a gate but a formality.

       Worth stating plainly, because it bounds what M5 is: names are
       self-asserted at HELLO, so a hostile local process can claim the
       confirmer's name and approve itself. Nothing name-based can stop
       that — the socket authenticates a uid, not a binary, which is the
       entire reason this broker exists. Confirmation is a speed bump
       between a *cooperative* flagged client and the user's keyboard,
       not a boundary against a hostile one. The deny-list, the
       allowlist and the rate limit are what bound a hostile client. */
    if (c->hdr.payload_len != 0) {
      result = ERR_PAYLOAD_INVALID;
      break;
    }
    if (!(c->roles & ROLE_CONFIRMER)) {
      snprintf(args, sizeof(args), "name=%s lacks the confirmer role",
               c->client_name);
      result = ERR_NOT_CONFIRMER;
      break;
    }
    struct conn *existing = confirmer_conn();
    if (existing && existing != c) {
      /* First subscriber wins. The alternative — newest wins — lets any
         client that can claim the name silently displace a live
         confirmer, and the displaced one has no way to know. */
      snprintf(args, sizeof(args), "a confirmer is already subscribed");
      result = ERR_NOT_CONFIRMER;
      break;
    }
    c->is_confirmer = 1;
    snprintf(args, sizeof(args), "confirmer subscribed name=%s",
             c->client_name);
    fprintf(stderr, "uictld: confirmer subscribed: name=%s pid=%d\n",
            c->client_name, (int)c->cred.pid);
    result = OK;
    break;
  }
  case OP_CONFIRM_DECIDE: {
    if (c->hdr.payload_len != sizeof(struct uictl_payload_confirm_decide)) {
      result = ERR_PAYLOAD_INVALID;
      break;
    }
    if (!c->is_confirmer) {
      snprintf(args, sizeof(args), "not the confirmer");
      result = ERR_NOT_CONFIRMER;
      break;
    }
    struct uictl_payload_confirm_decide dec;
    memcpy(&dec, c->buf, sizeof(dec));
    if (dec.reserved[0] || dec.reserved[1] || dec.reserved[2]) {
      result = ERR_PAYLOAD_INVALID;
      break;
    }
    if (!pending_confirm.active || dec.token != pending_confirm.token) {
      /* A stale token is the normal case, not an error condition worth
         alarming about: the request timed out, or its client went away,
         while the human was deciding. Answering OK would tell the
         confirmer its decision was applied. */
      snprintf(args, sizeof(args), "stale token %u", dec.token);
      result = ERR_PAYLOAD_INVALID;
      break;
    }
    /* Deferred: the decision is applied after this reply is staged, in
       conn_readable. Applying it here would re-enter conn_handle_frame
       for a *different* connection while this one is mid-dispatch, and
       that connection's reply would be staged into the wrong buffer.
       The flag is consumed exactly once. */
    c->confirm_verdict = dec.allow == 1 ? 1 : -1;
    snprintf(args, sizeof(args), "%s token=%u",
             dec.allow == 1 ? "allowed" : "denied", dec.token);
    result = OK;
    break;
  }
  case OP_KEY_UP: {
    /* The release path is deliberately the thinnest gate in the daemon:
       size, range, "do you hold it", write. No deny-list, no allowlist,
       no rate limit (see the exemption where the bucket is charged).

       That is not an oversight, it is the invariant. Every one of those
       checks can say no, and a no here means a key stays down. Policy
       already had its say on the DOWN — nothing can be held that was not
       allowed — so re-asking on the way up can only ever produce a stuck
       key, never prevent one. */
    if (c->hdr.payload_len != sizeof(struct uictl_payload_key)) {
      result = ERR_PAYLOAD_INVALID;
      break;
    }
    struct uictl_payload_key key;
    decode_key(c->buf, &key);

    if (key.keycode == 0 || key.keycode > UINPUT_KEY_CODE_MAX) {
      snprintf(args, sizeof(args), "code=%u out of range", key.keycode);
      result = ERR_PAYLOAD_INVALID;
      break;
    }
    if (!conn_holds(c, key.keycode)) {
      /* Includes the case where the dead-man timer already released it.
         Reported, not silently OK'd: a client that is releasing keys it
         does not hold has lost track of its own state, and that is worth
         knowing even though the outcome it wanted (key is up) is true.

         Unless nothing has ever been held on this connection — WIRE.md
         §8.3.1. Then this is the reconnect case, the key is up because
         the daemon released it when the old connection died, and there
         is no client bug to report. OK, and deliberately no write: the
         key is already up and a redundant value-0 event would be a
         device effect produced by a request the spec calls a no-op. */
      if (!c->held_ever) {
        snprintf(args, sizeof(args), "code=%u not held, forgiven (§8.3.1)",
                 key.keycode);
        result = OK;
        break;
      }
      snprintf(args, sizeof(args), "code=%u not held by this connection",
               key.keycode);
      result = ERR_KEY_NOT_HELD;
      break;
    }

    /* Clear the bookkeeping first here — the mirror image of DOWN, and
       for the same reason. If the write fails the key may well be stuck
       at the device, but keeping the bit set would only add a second,
       identical failed write on disconnect. The ERR_INTERNAL and
       uinput's own stderr are the report; the bit is not a retry queue. */
    struct uinput_key_event up = {.code = key.keycode, .value = 0};
    conn_hold_drop(c, key.keycode);
    if (uinput_key_seq(devs->keyboard, &up, 1) < 0) {
      snprintf(args, sizeof(args), "code=%u write failed", key.keycode);
      result = ERR_INTERNAL;
      break;
    }
    snprintf(args, sizeof(args), "code=%u released (%d still held)",
             key.keycode, c->held_count);
    result = OK;
    break;
  }
  case OP_KEY_SEQUENCE: {
    /* Same gate order as KEY_TAP, applied to every item before ANY of
       them is written: size, range, deny-list, allowlist, balance — then
       one atomic frame. Validating the whole sequence first is the
       point. A per-item "check then write" loop would leave a rejected
       modifier's press already delivered, which is the stuck-key
       scenario arriving through the back door. */
    if (c->hdr.payload_len < sizeof(struct uictl_payload_key_seq)) {
      result = ERR_PAYLOAD_INVALID;
      break;
    }
    struct uictl_payload_key_seq hdr;
    memcpy(&hdr, c->buf, sizeof(hdr));
    if (hdr.reserved != 0 || hdr.count == 0 || hdr.count > UICTL_SEQ_MAX ||
        c->hdr.payload_len != uictl_seq_payload_len(hdr.count)) {
      snprintf(args, sizeof(args), "bad sequence header count=%u len=%u",
               hdr.count, c->hdr.payload_len);
      result = ERR_PAYLOAD_INVALID;
      break;
    }

    struct uinput_key_event evs[UICTL_SEQ_MAX];
    /* Which keycodes this request currently holds down, in order. Small
       and linear on purpose: 16 items maximum, and a bitmap would lose
       the ordering that makes the release check readable. */
    uint16_t held[UICTL_SEQ_MAX];
    int held_n = 0;
    uint16_t seq_result = OK;
    args[0] = '\0';

    /* PASS 1 — structure and balance, before any policy question.
       Order matters for the message the user gets: an unbalanced request
       that also names an unlisted key should report the malformed
       sequence, not the policy miss. Otherwise they edit their policy
       file, retry, and meet the real error only on the second attempt. */
    for (uint16_t i = 0; i < hdr.count && seq_result == OK; i++) {
      struct uictl_seq_item item;
      memcpy(&item, c->buf + sizeof(hdr) + (size_t)i * sizeof(item),
             sizeof(item));

      if (item.reserved != 0 || item.value > 1) {
        snprintf(args, sizeof(args), "item %u malformed", i);
        seq_result = ERR_PAYLOAD_INVALID;
        break;
      }
      if (item.keycode == 0 || item.keycode > UINPUT_KEY_CODE_MAX) {
        snprintf(args, sizeof(args), "item %u code=%u out of range", i,
                 item.keycode);
        seq_result = ERR_PAYLOAD_INVALID;
        break;
      }

      /* Balance, tracked as we go. A press of something already held or
         a release of something not held is a client bug, and letting it
         through would make "balanced at the end" arithmetic rather than
         a real statement about the key's state. */
      int at = -1;
      for (int j = 0; j < held_n; j++)
        if (held[j] == item.keycode)
          at = j;
      if (item.value == 1) {
        if (at >= 0) {
          snprintf(args, sizeof(args), "item %u presses held code=%u", i,
                   item.keycode);
          seq_result = ERR_PAYLOAD_INVALID;
          break;
        }
        held[held_n++] = item.keycode;
      } else {
        if (at < 0) {
          snprintf(args, sizeof(args), "item %u releases unheld code=%u", i,
                   item.keycode);
          seq_result = ERR_PAYLOAD_INVALID;
          break;
        }
        held[at] = held[--held_n];
      }

      evs[i].code = item.keycode;
      evs[i].value = item.value;
    }

    if (seq_result == OK && held_n != 0) {
      /* The rule that lets this ship while OP_KEY_DOWN/UP wait for M4.5:
         a request may not leave anything held. Nothing the daemon accepts
         can strand a key if the client dies one microsecond later,
         because by the time we answer, everything is already released. */
      snprintf(args, sizeof(args),
               "unbalanced: %d key(s) still held (first code=%u)", held_n,
               held[0]);
      seq_result = ERR_PAYLOAD_INVALID;
    }

    /* PASS 2 — policy, on a sequence already known to be well-formed.
       Every item is checked before any is written: a per-item
       check-then-write loop would leave a rejected modifier's press
       already delivered, which is the stuck key arriving by the back
       door. */
    for (uint16_t i = 0; i < hdr.count && seq_result == OK; i++) {
      const char *seq_why = NULL;
      if (uinput_keycode_denied(evs[i].code, &seq_why)) {
        snprintf(args, sizeof(args), "code=%u denied (%s)", evs[i].code,
                 seq_why);
        seq_result = ERR_KEY_DENYLISTED;
      } else if (!key_allowed(evs[i].code)) {
        snprintf(args, sizeof(args), "code=%u not in allowlist", evs[i].code);
        seq_result = ERR_KEY_NOT_ALLOWED;
      }
    }

    if (seq_result != OK) {
      result = seq_result;
      break;
    }

    int n = snprintf(args, sizeof(args), "seq n=%u:", hdr.count);
    for (uint16_t i = 0; i < hdr.count && n > 0 && (size_t)n < sizeof(args);
         i++)
      n += snprintf(args + n, sizeof(args) - (size_t)n, " %u%s", evs[i].code,
                    evs[i].value ? "v" : "^");
    result = (uinput_key_seq(devs->keyboard, evs, hdr.count) < 0) ? ERR_INTERNAL : OK;
    break;
  }
  default:
    result = ERR_OPCODE_UNKNOWN;
    break;
  }

  /* Successful motion is accumulated, not logged line by line (G10).
     Everything else — including every failed motion request — takes the
     normal path. */
  if (result == OK && op_is_motion(c->hdr.opcode)) {
    int32_t a = 0, b = 0;
    if (c->hdr.opcode == OP_MOVE_ABS &&
        c->hdr.payload_len == sizeof(struct uictl_payload_move_abs)) {
      struct uictl_payload_move_abs mv;
      decode_move_abs(c->buf, &mv);
      a = mv.x;
      b = mv.y;
    } else if (c->hdr.payload_len == sizeof(struct uictl_payload_move_rel)) {
      struct uictl_payload_move_rel mv;
      memcpy(&mv, c->buf, sizeof(mv));
      a = mv.dx;
      b = mv.dy;
    }
    motion_note(audit_fd, c->cred.pid, c->cred.uid, c->hdr.source_tag,
                c->hdr.opcode, a, b);
  } else {
    audit_log(audit_fd, c->cred.pid, c->cred.uid, c->hdr.source_tag,
              c->hdr.opcode, c->hdr.seq, result, args);
  }
  /* An answer rides along only on success: an error response is a bare
     result code for every opcode, so a client never has to decide
     whether a failed request left it a half-filled struct. */
  if (result == OK)
    conn_reply_data(c, result, resp_data, resp_len);
  else
    conn_reply(c, result);
}

/* Drain what is readable on this connection, dispatching each frame as
   it completes, up to CONN_FRAMES_PER_TURN frames. Exact-size reads: we
   ask for precisely the bytes the current phase still needs, so a read
   can never overshoot into the next frame and there is no leftover tail
   to compact. Pipelined frames still work — the loop simply comes back
   around, and past the budget the *next* epoll turn comes back around.

   The budget (M3.7 task 1, G6) is what makes the scheduling unit "one
   frame" instead of "one connection's whole backlog". Returning early
   with bytes still sitting in the receive buffer IS the round-robin:
   epoll here is level-triggered, so this connection is re-reported as
   readable on the very next turn, after every other ready fd has had
   theirs. The kernel's readiness list is the queue — no scheduler, no
   priority queue, no fairness counter to keep consistent. (Third thing
   level-triggered mode gives us for free, after re-arming EPOLLIN post
   EPOLLOUT stall and never having to remember "there may be more".) */
/* Apply a decision to the parked request. Defined here because the
   allow path re-feeds the request through conn_handle_frame above.

   Every exit clears `pending_confirm` first: a resolve that returns
   early with the slot still marked active would wedge the whole
   confirmation channel until the daemon restarted, since there is only
   one. */
static void confirm_resolve(int epfd, const struct uinput_devs *devs,
                          int audit_fd, int allow,
                            uint16_t deny_result, const char *why) {
  if (!pending_confirm.active)
    return;
  struct conn *req = confirm_requester();
  pending_confirm.active = 0;
  if (!req)
    return; /* the requester is gone; there is nobody to answer */

  req->awaiting_confirm = 0;

  if (allow) {
    /* Restore the frame exactly as it was validated, then dispatch it as
       resumed — no second rate charge, no second prompt. The audit line
       is written by the handler with the real outcome, which is why the
       park wrote none. */
    req->hdr = req->parked_hdr;
    memcpy(req->buf, req->parked_payload, req->parked_hdr.payload_len);
    audit_log(audit_fd, req->cred.pid, req->cred.uid,
              req->parked_hdr.source_tag, req->parked_hdr.opcode,
              req->parked_hdr.seq, OK, "confirmed by user");
    conn_handle_frame(epfd, req, devs, audit_fd, 1);
  } else {
    audit_log(audit_fd, req->cred.pid, req->cred.uid,
              req->parked_hdr.source_tag, req->parked_hdr.opcode,
              req->parked_hdr.seq, deny_result, why);
    /* conn_reply echoes c->hdr, which the park may have moved past —
       restore the header so the client can match the reply to the
       request it is still waiting on. */
    req->hdr = req->parked_hdr;
    conn_reply(req, deny_result);
  }
  explicit_bzero(req->parked_payload, sizeof(req->parked_payload));

  int flushed = conn_flush(req);
  if (conn_after_flush(epfd, req, flushed, devs, audit_fd) == 0) {
    /* Re-arm. conn_after_flush only touches the epoll mask when a reply
       is still queued; here the mask is 0 because the connection was
       parked, and nothing else would ever set it back. */
    (void)conn_update_events(epfd, req);
  }
}

static void confirm_on_conn_closed(int epfd, struct conn *gone, const struct uinput_devs *devs,
                                   int audit_fd) {
  if (!pending_confirm.active)
    return;
  /* The requester itself is going away: drop the pending confirmation
     without answering. Checked by slot AND generation, so a slot that
     has since been reused is not mistaken for the original requester. */
  if ((int)(gone - conns) == pending_confirm.slot &&
      gone->generation == pending_confirm.gen) {
    pending_confirm.active = 0;
    return;
  }
  if (gone->is_confirmer)
    confirm_resolve(epfd, devs, audit_fd, 0, ERR_CONFIRM_UNAVAILABLE,
                    "confirmer disconnected");
}

static void conn_readable(int epfd, struct conn *c, const struct uinput_devs *devs,
                          int audit_fd) {
  unsigned dispatched = 0;

  for (;;) {
    while (c->have < c->want) {
      ssize_t r = read(c->fd, c->buf + c->have, c->want - c->have);
      if (r < 0) {
        if (errno == EINTR)
          continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK)
          return; /* socket drained; wait for the next EPOLLIN */
        perror("uictld: read client");
        conn_close(epfd, c, devs, audit_fd);
        return;
      }
      if (r == 0) { /* peer EOF */
        conn_close(epfd, c, devs, audit_fd);
        return;
      }
      if (c->have == 0 && c->phase == CONN_WANT_HEADER)
        c->frame_since = mono_secs(); /* first byte of a new frame */
      c->have += (size_t)r;
    }

    if (c->phase == CONN_WANT_HEADER) {
      decode_frame_header(c->buf, &c->hdr);

      /* Validation order is load-bearing. payload_len is attacker-
         controlled up to 4 GB and the very next read uses it as a
         length into a 4 KB buffer, so it MUST be bounded before it is
         copied into c->want. */
      uint16_t fatal = 0;
      if (!conn_version_ok(c, c->hdr.version, c->hdr.opcode))
        fatal = ERR_VERSION;
      else if (c->hdr.payload_len > UICTL_MAX_PAYLOAD)
        fatal = ERR_TOO_LARGE;

      if (fatal) {
        /* Both errors leave us unable to find the next frame boundary:
           a rejected version means payload_len is untrustworthy, and an
           over-long payload means those bytes are still queued and
           would be misparsed as the next header. So these are fatal to
           the stream, not per-frame. ERR_OPCODE_UNKNOWN and
           ERR_PAYLOAD_INVALID are not — there the payload was consumed
           and the connection continues. */
        audit_log(audit_fd, c->cred.pid, c->cred.uid, c->hdr.source_tag,
                  c->hdr.opcode, c->hdr.seq, fatal, "fatal frame");
        conn_reply(c, fatal);
        /* Close *after* the error actually reaches the peer, not before.
           Previously the reply was written best-effort and the socket
           closed immediately; if it didn't drain, the client learned
           nothing but "connection reset". */
        c->close_after_flush = 1;
        (void)conn_after_flush(epfd, c, conn_flush(c), devs, audit_fd);
        return;
      }

      c->phase = CONN_WANT_PAYLOAD;
      c->want = c->hdr.payload_len;
      c->have = 0;
      if (c->want > 0)
        continue; /* go read the payload */
      /* Zero-length payload (PING) falls through and is dispatched now.
         It must NOT go back through the read loop: read(fd, buf, 0)
         returns 0, which is indistinguishable from EOF. */
    }

    conn_handle_frame(epfd, c, devs, audit_fd, 0);

    /* Reset for the next frame on this same connection. Hoisted above
       everything that follows because the frame is fully consumed the
       moment the handler returns, on every path — including the M5 park,
       which returns without staging a reply.

       Leaving it below the park check was a real bug, and an instructive
       one: the connection resumed still in CONN_WANT_PAYLOAD with
       have == want, so the next read asked the kernel for zero bytes,
       got 0 back, and every caller reads a 0-byte read as EOF. The
       symptom was the daemon dropping a client the instant its
       confirmation was approved. Wiping c->buf here is safe because
       confirm_park copied the payload out first. */
    c->phase = CONN_WANT_HEADER;
    c->want = HDR_SIZE;
    c->have = 0;
    explicit_bzero(c->buf, sizeof(c->buf));

    /* Parked for confirmation: nothing staged, nothing to flush, and
       EPOLLIN already dropped. The decision restarts this connection. */
    if (c->awaiting_confirm) {
      c->frames_served++;
      return;
    }

    int flushed = conn_flush(c);

    /* -1 means closed, or queued and waiting on EPOLLOUT. Either way we
       stop parsing: with one out buffer, handling the next pipelined
       frame here would clobber the reply still in flight. */
    int alive = conn_after_flush(epfd, c, flushed, devs, audit_fd);

    /* A decision staged by THIS frame is applied now: after its own
       reply is on the wire, and outside conn_handle_frame, so the
       requester's reply is staged into the requester's buffer and not
       into the confirmer's. Read and cleared exactly once — a verdict
       left set would be re-applied to whatever confirmation came next. */
    if (c->confirm_verdict != 0) {
      int verdict = c->confirm_verdict;
      c->confirm_verdict = 0;
      confirm_resolve(epfd, devs, audit_fd, verdict > 0,
                      ERR_CONFIRM_DENIED, "denied by user");
    }

    if (alive < 0)
      return;

    /* Counted here, per *dispatched frame* — not per read() and not per
       loop iteration. A frame trickling in across five reads is still
       one frame's worth of work; charging it five would let a slow but
       honest client spend its budget on nothing and yield a turn for
       every fragment. Nothing else is needed on the way out: EPOLLIN is
       still armed (conn_after_flush only drops it while a reply is
       pending), so the leftover bytes come back to us next turn. */
    c->frames_served++;
    if (++dispatched >= CONN_FRAMES_PER_TURN)
      return;
  }
}

/* A frame is in progress iff we are holding parse state for bytes that
   have not all arrived. Two cases: mid-header (have > 0, still in
   CONN_WANT_HEADER), or header complete and payload outstanding
   (CONN_WANT_PAYLOAD). An idle connection sitting at
   CONN_WANT_HEADER with have == 0 is NOT in progress — that is the
   normal resting state of a long-lived client between hotkeys, and
   reaping it would break the very thing M3.5 exists to support. */
static int conn_frame_in_progress(const struct conn *c) {
  return c->have > 0 || c->phase == CONN_WANT_PAYLOAD;
}

/* One timer, scanned against the whole table — not one timer per
   connection. At <= 32 slots the scan is cheaper than 32 timerfds, and
   there is no per-connection fd to leak on close. */
static void conn_reap_partial(int epfd, const struct uinput_devs *devs,
                          int audit_fd) {
  time_t now = mono_secs();

  /* G10: one line per second per motion stream, written from here so a
     client that stops moving still gets its final count recorded rather
     than leaving it in memory until the daemon exits. */
  motion_flush(audit_fd, 0);

  /* A confirmation nobody answered (M5). Denied, never allowed: a gate
     that opens when the user is away from the keyboard is not a gate.
     Same tick as the stall reaper, so the effective deadline is 30-31 s
     — coarse on purpose, like every other deadline here. */
  if (pending_confirm.active &&
      now - pending_confirm.since >= CONFIRM_TIMEOUT_SEC)
    confirm_resolve(epfd, devs, audit_fd, 0, ERR_CONFIRM_TIMEOUT,
                    "confirmation timed out");

  /* Idle exit (M6). Checked here rather than on the last disconnect
     because "idle" is a duration, not an event: a client that reconnects
     every few seconds is not idle, and a table that empties and refills
     within the window must not restart the countdown from a close.

     Three conditions, and the second two are the safety. An empty
     connection table means nothing is held, since holds belong to
     connections. No pending confirmation means nobody is looking at a
     prompt — which cannot happen with an empty table, and is checked
     anyway because a condition that is cheap and currently redundant is
     the one that survives the next change to either half.

     The flag is set rather than the loop being broken from here: the
     reaper is called from inside the event batch, and abandoning the
     remaining events would drop work that has already arrived. */
  if (g_idle_exit_sec > 0) {
    if (conn_count_live() > 0 || pending_confirm.active) {
      g_idle_since = now;
    } else if (now - g_idle_since >= g_idle_exit_sec) {
      fprintf(stderr,
              "uictld: idle for %lds with no connections — exiting; "
              "systemd will start a new instance on the next connect\n",
              (long)(now - g_idle_since));
      g_idle_expired = 1;
    }
  }

  for (int i = 0; i < MAX_CONNS; i++) {
    struct conn *c = &conns[i];
    if (c->fd < 0)
      continue;

    /* Dead-man timer (M4.5 task 4). The connection is alive and may be
       perfectly healthy — this is the one case task 2 cannot reach,
       because nothing is disconnecting. A client that is up but stuck
       between its DOWN and its UP holds a key on the user's desktop
       indefinitely, and "the client will get to it" is not a property
       the broker can assert about code it does not own.

       Released, not reaped: the connection did nothing wrong at the
       protocol level and its next request should work. It will meet
       ERR_KEY_NOT_HELD on the UP it eventually sends, which is exactly
       the signal that its held set and the daemon's have diverged.

       held_since is the connection's *oldest* hold (task 1), so the
       quantity bounded here is "this connection has been continuously
       holding something for HOLD_MAX_SEC", not the age of any one key.
       That is the more meaningful thing to bound — and it means a
       client that keeps one key down while tapping others is correctly
       seen as stuck rather than busy. Everything it holds goes up
       together: a partial release would leave it holding a set neither
       side agrees on. */
    if (c->held_count > 0 && now - c->held_since >= HOLD_MAX_SEC) {
      conn_release_held(c, devs, audit_fd, "dead-man timer");
      /* fall through: this connection may also be stalled */
    }

    /* Two independent stalls, same deadline.

       A peer that stops *sending* mid-frame leaves us holding parse
       state (task 6). A peer that stops *reading* leaves us holding an
       undeliverable reply — a hole task 7 opened, because the old
       conn_flush killed such a connection on the spot and the new one
       parks it on EPOLLOUT indefinitely. Both occupy a slot forever, so
       both are reaped. */
    const char *why = NULL;
    if (conn_frame_in_progress(c) &&
        now - c->frame_since >= CONN_PARTIAL_TIMEOUT_SEC)
      why = "partial frame timeout";
    else if (c->out_since != 0 && now - c->out_since >= CONN_PARTIAL_TIMEOUT_SEC)
      why = "response stalled";
    if (!why)
      continue;

    /* c->hdr is only decoded once the header phase completes; in
       CONN_WANT_HEADER it still holds the previous frame's values, so
       report zeros rather than auditing stale state as if it were this
       frame's. (On the stalled-write path hdr *is* this frame's — the
       reply was built from it — so it reports usefully either way.) */
    int hdr_valid = (c->phase == CONN_WANT_PAYLOAD) || (c->out_since != 0);
    uint16_t op = hdr_valid ? c->hdr.opcode : OP_INVALID;
    uint32_t src = hdr_valid ? c->hdr.source_tag : 0;
    uint32_t seq = hdr_valid ? c->hdr.seq : 0;

    audit_log(audit_fd, c->cred.pid, c->cred.uid, src, op, seq,
              ERR_DENIED_BY_POLICY, why);
    /* No reply attempt. The peer is by definition not talking, so its
       receive window may be full and a write could block the daemon —
       which is exactly the failure this whole milestone removes. */
    conn_close(epfd, c, devs, audit_fd);
  }
}

/* SIGUSR1 handler body (M3.7 task 4 / G10): what the operator gets
   instead of grepping an append-only log to answer "who is connected and
   who is being refused". Deliberately stderr and not a new opcode:
   open question 4 leans against exposing peer identities *to clients*
   (an information leak between peers of the same user), and that
   objection does not apply to the operator running the daemon.

   Everything here is metadata — pids, phases, counters. No payload
   bytes, no coordinates, nothing that would become keystrokes at M4.
   That is security rule 5's "intent, not content" applied to a channel
   the rule was not written for; keep it that way when adding fields.

   Called straight from the event loop, not from a signal handler, so
   fprintf is safe. That is the whole reason signalfd exists: an
   async-signal handler could not do any of this. */
static void conn_dump_table(void) {
  time_t now = mono_secs();
  int used = 0;
  for (int i = 0; i < MAX_CONNS; i++)
    if (conns[i].fd >= 0)
      used++;

  fprintf(stderr, "uictld: %d/%d slots used (max %d per pid)\n", used,
          MAX_CONNS, MAX_CONNS_PER_PID);
  /* The confirmation channel is daemon-wide state, not per connection,
     so it gets its own line. "no confirmer" is the answer to the most
     likely question an operator has when a flagged client stops
     working. */
  {
    const struct conn *cf = confirmer_conn();
    if (cf)
      fprintf(stderr, "uictld: confirmer: name=%s pid=%d\n", cf->client_name,
              (int)cf->cred.pid);
    else
      fprintf(stderr, "uictld: confirmer: none subscribed\n");
    if (pending_confirm.active)
      fprintf(stderr, "uictld: pending confirmation: token=%u op=%s age=%llds\n",
              pending_confirm.token, opname(pending_confirm.opcode),
              (long long)(now - pending_confirm.since));
  }
  for (int i = 0; i < MAX_CONNS; i++) {
    const struct conn *c = &conns[i];
    if (c->fd < 0)
      continue;

    /* Same distinction the reaper makes: "idle" is a resting long-lived
       client, "hdr"/"payload" mean bytes are outstanding and the reap
       clock is running. Printing them apart is the point — it is what
       tells an operator whether a quiet connection is healthy or stuck. */
    const char *phase = !conn_frame_in_progress(c) ? "idle"
                        : c->phase == CONN_WANT_PAYLOAD
                            ? "payload"
                            : "hdr";
    /* "-" for a peer that has not said HELLO. Safe to print unquoted:
       uictl_client_name_valid() is what let it be stored at all. */
    /* Budget is per pid, so two connections from one process show the
       same number — which is the point: they share it. */
    unsigned tokens = 0;
    for (int b = 0; b < RATE_BUCKETS; b++)
      if (rate_buckets[b].used && rate_buckets[b].pid == c->cred.pid)
        tokens = rate_buckets[b].milli / RATE_UNIT;

    /* held=N(age) is the column an operator reaches for when something
       is stuck down: it names the connection to kill and says how long
       it has been that way. Reads held=0 everywhere until task 3. */
    fprintf(stderr,
            "  slot=%2d gen=%u fd=%d pid=%d uid=%u name=%s class=%s "
            "tokens=%u/%u phase=%s(%zu/%zu) reply=%zu/%zu age=%llds "
            "frames=%llu held=%d(%llds)\n",
            i, c->generation, c->fd, (int)c->cred.pid, (unsigned)c->cred.uid,
            c->hello_seen ? c->client_name : "-", class_name(c->cl), tokens,
            rate_classes[c->cl].burst, phase,
            c->have, c->want,
            c->out_sent, c->out_len, (long long)(now - c->accepted_at),
            (unsigned long long)c->frames_served, c->held_count,
            c->held_since ? (long long)(now - c->held_since) : 0LL);
    /* M9, and on its own line because it is a path. This is the answer
       to "which program is that, really" -- the name on the line above
       is what the client said about itself, and this is what the kernel
       said about it at accept. When they disagree, this is the one to
       believe. "?" means /proc could not be read, or the binary has been
       replaced since it started. */
    fprintf(stderr, "          exe=%s\n", c->exe[0] ? c->exe : "?");
  }
  fflush(stderr);
}

/* ---- socket activation (M6) -----------------------------------------
   systemd's protocol, implemented by hand rather than by linking
   libsystemd: LISTEN_PID names the process the fds were passed to,
   LISTEN_FDS counts them, and they begin at fd 3.

   Why not the library. It is ~60 lines against a shared-object
   dependency in the most security-sensitive binary in the stack, for a
   protocol that is three environment variables and has not changed
   since 2010. The M7 AppArmor profile also stays smaller with one fewer
   object to allow, and plan.md's "no license-incompatible deps" is
   easier to keep true when there are none. */
#define SD_LISTEN_FDS_START 3

/* Set when systemd handed us the listening socket. The daemon then does
   NOT own the socket file. */
static int g_socket_inherited;

/* Remove the socket file — unless systemd created it.

   Under socket activation the .socket unit owns that path and outlives
   this process. Unlinking it on shutdown would leave the unit listening
   on an inode nothing can reach: every later connect() gets
   ECONNREFUSED, and no restart of the *service* fixes it, because the
   stale listener belongs to the socket unit. That is a failure the user
   has to diagnose with `systemctl --user status`, which is exactly the
   class of restart bug WIRE.md §8 exists to prevent. */
static void socket_path_cleanup(const char *path) {
  if (g_socket_inherited)
    return;
  unlink(path);
}

/* Is the socket file systemd created safe to serve on?

   The obvious check does not work, and the reason is worth stating:
   fstat() on a bound AF_UNIX socket fd reports the *sockfs* inode, not
   the filesystem node, and that inode's mode is 0777 no matter what the
   path's mode is. Verified by measurement rather than assumed. So the
   real check is getsockname() to learn the path, then stat() on it.

   This matters because the mode is not ours to set here: systemd creates
   the node, and its SocketMode default is **0666**. A unit that forgets
   `SocketMode=0600` produces a world-writable input broker — the single
   worst outcome this project exists to prevent — and it would do so
   silently, since everything works. Refusing to start is the only
   honest response. */
static int inherited_socket_path_ok(int fd, char *out, size_t outlen) {
  struct sockaddr_un sa;
  socklen_t len = sizeof(sa);
  memset(&sa, 0, sizeof(sa));
  if (getsockname(fd, (struct sockaddr *)&sa, &len) < 0) {
    perror("uictld: getsockname on the inherited socket");
    return -1;
  }
  if (len <= (socklen_t)offsetof(struct sockaddr_un, sun_path) ||
      sa.sun_path[0] == '\0') {
    /* Unnamed, or the abstract namespace. Abstract sockets have no
       filesystem entry and therefore no permissions at all: anyone on
       the system could connect. plan.md rules them out for exactly this
       reason, and a ListenStream=@uictld in a unit file would otherwise
       reintroduce it without touching a line of C. */
    fprintf(stderr, "uictld: the inherited socket is not a filesystem "
                    "path\n  fix:  ListenStream= must be a path. an "
                    "abstract socket (@name) has no\n        permissions "
                    "— any user on the system could connect.\n");
    return -1;
  }
  sa.sun_path[sizeof(sa.sun_path) - 1] = '\0';

  struct stat st;
  if (stat(sa.sun_path, &st) < 0) {
    perror("uictld: stat the inherited socket path");
    return -1;
  }
  if (!S_ISSOCK(st.st_mode)) {
    fprintf(stderr, "uictld: %s is not a socket\n", sa.sun_path);
    return -1;
  }
  if (st.st_uid != getuid()) {
    fprintf(stderr, "uictld: %s is owned by uid %u, not %u\n", sa.sun_path,
            (unsigned)st.st_uid, (unsigned)getuid());
    return -1;
  }
  if (st.st_mode & 0077) {
    fprintf(stderr,
            "uictld: %s has mode %04o — group or world bits are set\n"
            "  why:  systemd's SocketMode default is 0666, which would let "
            "any user\n        on this machine inject input\n"
            "  fix:  add `SocketMode=0600` to the [Socket] section of "
            "uictld.socket,\n        then `systemctl --user daemon-reload "
            "&& systemctl --user restart uictld.socket`.\n",
            sa.sun_path, (unsigned)(st.st_mode & 07777));
    return -1;
  }

  int n = snprintf(out, outlen, "%s", sa.sun_path);
  if (n < 0 || (size_t)n >= outlen) {
    fprintf(stderr, "uictld: inherited socket path too long\n");
    return -1;
  }
  return 0;
}

/* ---- readiness notification (M6, Type=notify) ------------------------
   sd_notify by hand, for the same reasons as the fd protocol above: one
   datagram to the socket named by $NOTIFY_SOCKET.

   Why Type=notify rather than Type=simple. With `simple`, systemd
   considers the unit started the moment fork() returns, so anything
   ordered After=uictld.service races the daemon's actual readiness --
   and "ready" here means the uinput devices are registered and the
   accept loop is running, which is tens of milliseconds and a possible
   EACCES away from process start. With `notify`, `systemctl --user
   start` blocks until the daemon says it can serve, and a start-up
   failure is reported as a failure instead of a unit that is
   "active" and useless.

   Absent NOTIFY_SOCKET this is a no-op, which is the normal case when
   someone runs ./uictld in a terminal. Failure to notify is NOT fatal:
   the daemon works fine unsupervised, and refusing to run because the
   supervisor's socket is missing would make the manual case depend on
   systemd. */
static void notify_systemd(const char *msg) {
  const char *sock = getenv("NOTIFY_SOCKET");
  if (!sock || !*sock)
    return;

  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  size_t len = strlen(sock);
  if (len >= sizeof(addr.sun_path)) {
    fprintf(stderr, "uictld: NOTIFY_SOCKET path too long\n");
    return;
  }
  memcpy(addr.sun_path, sock, len);
  /* systemd's notify socket is usually in the abstract namespace, where
     it is spelled with a leading '@' in the variable and a leading NUL
     on the wire. Abstract is fine HERE and nowhere else in this project:
     we are the client, the socket is systemd's, and the rule against
     abstract sockets is about what we would expose, not what we
     connect to. */
  if (addr.sun_path[0] == '@')
    addr.sun_path[0] = '\0';

  int fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    perror("uictld: socket for NOTIFY_SOCKET");
    return;
  }
  socklen_t alen = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + len);
  if (sendto(fd, msg, strlen(msg), MSG_NOSIGNAL, (struct sockaddr *)&addr,
             alen) < 0)
    perror("uictld: notify systemd");
  close(fd);
}

/* Returns the inherited listening fd, -1 if we were not socket-activated,
   or -2 if we were and something about it is wrong (fatal — falling back
   to binding our own socket would race the one systemd is holding). */
static int listen_fd_from_systemd(char *pathbuf, size_t pathlen) {
  const char *pid_s = getenv("LISTEN_PID");
  const char *fds_s = getenv("LISTEN_FDS");
  if (!pid_s || !fds_s)
    return -1;

  errno = 0;
  char *end;
  long claimed_pid = strtol(pid_s, &end, 10);
  if (errno != 0 || *end != '\0' || claimed_pid <= 0)
    return -1;
  /* LISTEN_PID exists precisely so that an inherited environment does
     not convince a grandchild that fd 3 is its listening socket. We
     never fork, but honouring it costs one comparison and makes the
     variables meaningless to anything we did not start. */
  if ((pid_t)claimed_pid != getpid())
    return -1;

  errno = 0;
  long count = strtol(fds_s, &end, 10);
  if (errno != 0 || *end != '\0')
    return -1;
  if (count != 1) {
    fprintf(stderr,
            "uictld: systemd passed %ld file descriptors, expected exactly "
            "1\n  fix:  uictld.socket must declare a single "
            "ListenStream=.\n",
            count);
    return -2;
  }

  int fd = SD_LISTEN_FDS_START;

  /* Do not trust the environment about what fd 3 IS. These three
     getsockopts turn "the unit file is wrong" into a clear refusal
     instead of an accept() loop on something that is not a listening
     unix socket. */
  int val = 0;
  socklen_t vlen = sizeof(val);
  if (getsockopt(fd, SOL_SOCKET, SO_ACCEPTCONN, &val, &vlen) < 0 || !val) {
    fprintf(stderr, "uictld: fd 3 is not a listening socket\n");
    return -2;
  }
  vlen = sizeof(val);
  if (getsockopt(fd, SOL_SOCKET, SO_DOMAIN, &val, &vlen) < 0 ||
      val != AF_UNIX) {
    fprintf(stderr, "uictld: fd 3 is not AF_UNIX\n"
                    "  why:  this daemon has no network surface, by "
                    "design.\n");
    return -2;
  }
  vlen = sizeof(val);
  if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &val, &vlen) < 0 ||
      val != SOCK_STREAM) {
    fprintf(stderr, "uictld: fd 3 is not SOCK_STREAM\n");
    return -2;
  }

  if (inherited_socket_path_ok(fd, pathbuf, pathlen) < 0)
    return -2;

  /* systemd passes the fd blocking and without CLOEXEC; the accept loop
     needs the first and the rest of the daemon assumes the second. */
  int fl = fcntl(fd, F_GETFL, 0);
  if (fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0 ||
      fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) {
    perror("uictld: fcntl on the inherited socket");
    return -2;
  }

  /* Clear the variables so they mean nothing to anything downstream.
     Hygiene rather than necessity — the daemon never execs — but a stale
     LISTEN_FDS in an environment is the kind of thing that confuses the
     next program someone runs from a debugger. */
  unsetenv("LISTEN_PID");
  unsetenv("LISTEN_FDS");
  unsetenv("LISTEN_FDNAMES");
  return fd;
}

int main(void) {

  /* First thing, before any fd exists: a pure-logic check with nothing
     to unwind on failure. Same posture as uinput_denylist_selftest() —
     a daemon whose held-state bookkeeping is wrong must not start, since
     the failure it produces is a key stuck down on the user's desktop. */
  if (conn_held_selftest() != 0) {
    fprintf(stderr, "uictld: held-state selftest failed, refusing to start\n");
    return 1;
  }

  const char *xdg = getenv("XDG_RUNTIME_DIR");
  if (!xdg) {
    fprintf(stderr, "uictld: XDG_RUNTIME_DIR is not set. failed to start\n");
    return 1;
  }

  char path[108];
  int n = snprintf(path, sizeof(path), "%s/uictld.sock", xdg);
  if (n < 0 || (size_t)n >= sizeof(path)) {
    fprintf(stderr, "uictld: socket path too long\n");
    return 1;
  }

  umask(0077);

  /* Socket activation first (M6). If systemd is holding the listening
     socket we must NOT create one: binding our own would either fail on
     a path that already exists or, worse, replace the inode the socket
     unit is listening on, leaving every queued connection unreachable.
     There is deliberately no fallback from -2 for the same reason —
     "activated but misconfigured" is not a state to improvise in. */
  int sfd = listen_fd_from_systemd(path, sizeof(path));
  if (sfd == -2)
    return 1;
  g_socket_inherited = (sfd >= 0);

  struct sockaddr_un addr = {.sun_family = AF_UNIX};
  if (!g_socket_inherited) {
    /* SOCK_NONBLOCK on the LISTENING socket. accept4()'s flag argument
       applies to the socket it returns, not to the one it is called on —
       without this, the accept-until-EAGAIN loop blocks forever on its
       second iteration and the daemon never reaches epoll_wait again. */
    sfd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (sfd < 0) {
      perror("uictld: socket");
      return 1;
    }
    strcpy(addr.sun_path, path);
  }

  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGINT);
  sigaddset(&mask, SIGTERM);
  /* SIGUSR1 is the operator's "who is connected?" (M3.7 task 4). It has
     to be in this set for two reasons, and the second one is the sharp
     one: signalfd only ever reports signals that are BLOCKED, and the
     default disposition of SIGUSR1 is *terminate the process*. Add it to
     the signalfd mask but forget it here and `kill -USR1 $(pidof uictld)`
     kills the daemon instead of printing a table. */
  sigaddset(&mask, SIGUSR1);
  if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) {
    perror("uictld: sigprocmask");
    close(sfd);
    return 1;
  }

  struct sigaction ign = {.sa_handler = SIG_IGN};
  sigemptyset(&ign.sa_mask);

  if (sigaction(SIGPIPE, &ign, NULL) < 0) {
    perror("uictld: sigaction SIGPIPE");
    close(sfd);
    return 1;
  }

  char state_dir[256];
  if (prepare_state_dir(state_dir, sizeof(state_dir)) < 0) {
    close(sfd);
    return 1;
  }

  char lock_path[256];
  int lp = snprintf(lock_path, sizeof(lock_path), "%s/uictld.lock", state_dir);
  if (lp < 0 || (size_t)lp >= sizeof(lock_path)) {
    fprintf(stderr, "uictld: loack path too long\n");
    close(sfd);
    return 1;
  }
  int lockfd = open(lock_path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
  if (lockfd < 0) {
    perror("uictld: open lockfile");
    close(sfd);
    return 1;
  }
  if (flock(lockfd, LOCK_EX | LOCK_NB) < 0) {
    if (errno == EWOULDBLOCK) {
      fprintf(stderr, "uictld: another daemon already running\n");
    } else {
      perror("uictld: flock");
    }
    close(lockfd);
    close(sfd);
    return 1;
  }

  int audit_fd = open_audit_log(state_dir);
  if (audit_fd < 0) {
    close(lockfd);
    close(sfd);
    return 1;
  }

  /* All of this is systemd's job under activation: it created the node,
     bound it and called listen() before we were started. The unlink is
     safe here only because the flock above has already established that
     no other daemon is live. */
  if (!g_socket_inherited) {
    if (unlink(path) < 0 && errno != ENOENT) {
      perror("uictld: unlink");
      close(audit_fd);
      close(lockfd);
      close(sfd);
      return 1;
    }

    if (bind(sfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
      perror("uictld: bind");
      close(audit_fd);
      close(sfd);
      return 1;
    }

    if (listen(sfd, 16) < 0) {
      perror("uictld: listen");
      close(audit_fd);
      close(lockfd);
      close(sfd);
      unlink(path);
      return 1;
    }
  }

  uint32_t hal_caps = 0;
  struct uinput_devs devices = {-1, -1};
  const struct uinput_devs *devs = &devices;
  if (uinput_open(&devices, &hal_caps) < 0) {
    close(audit_fd);
    close(lockfd);
    close(sfd);
    socket_path_cleanup(path);
    return 1;
  }

  g_device_caps = wire_caps_from_uinput(hal_caps);
  /* A device with no advertised ability is a bug in uinput_open(), not a
     degraded mode to run in: every RPC that reaches the device would
     fail one at a time, at request time, on somebody else's machine.
     Refuse to start instead. */
  if (g_device_caps == 0) {
    fprintf(stderr, "uictld: device came up with no capabilities\n");
    uinput_close(&devices);
    close(audit_fd);
    close(lockfd);
    close(sfd);
    socket_path_cleanup(path);
    return 1;
  }
  /* Two devices since M5.5, and the fds are named so an operator can
     match them to what /proc/bus/input/devices shows. */
  fprintf(stderr,
          "uictld: pointer fd=%d, keyboard fd=%d, caps 0x%x (%s%s%s%s)\n",
          devices.pointer, devices.keyboard, g_device_caps,
          (g_device_caps & CAP_POINTER_ABS) ? "pointer-abs " : "",
          (g_device_caps & CAP_KEYBOARD) ? "keyboard " : "",
          (g_device_caps & CAP_POINTER_REL) ? "pointer-rel " : "",
          (g_device_caps & CAP_BUTTONS) ? "buttons" : "");

  int sigfd = signalfd(-1, &mask, SFD_CLOEXEC);
  if (sigfd < 0) {
    perror("uictld: signalfd");
    uinput_close(&devices);
    close(audit_fd);
    close(lockfd);
    close(sfd);
    socket_path_cleanup(path);
    return 1;
  }

  int epfd = epoll_create1(EPOLL_CLOEXEC);
  if (epfd < 0) {
    perror("uictld: epoll_create1");
    uinput_close(&devices);
    close(sigfd);
    close(audit_fd);
    close(lockfd);
    close(sfd);
    socket_path_cleanup(path);
    return 1;
  }
  /* CLOCK_MONOTONIC, not CLOCK_REALTIME: an NTP step or a settimeofday
     must not make the reaper fire early or stall for hours. TFD_NONBLOCK
     so the mandatory read() below can never park the loop. */
  int tfd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
  if (tfd < 0) {
    perror("uictld: timerfd_create");
    uinput_close(&devices);
    close(epfd);
    close(sigfd);
    close(audit_fd);
    close(lockfd);
    close(sfd);
    socket_path_cleanup(path);
    return 1;
  }
  /* it_value arms the first expiry, it_interval makes it periodic. Leave
     it_interval zero and the timer fires exactly once — the classic
     one-shot bug that looks like "the reaper worked, then stopped". */
  struct itimerspec its = {.it_value = {.tv_sec = REAPER_TICK_SEC},
                           .it_interval = {.tv_sec = REAPER_TICK_SEC}};
  if (timerfd_settime(tfd, 0, &its, NULL) < 0) {
    perror("uictld: timerfd_settime");
    close(tfd);
    uinput_close(&devices);
    close(epfd);
    close(sigfd);
    close(audit_fd);
    close(lockfd);
    close(sfd);
    socket_path_cleanup(path);
    return 1;
  }

  /* Static sources carry generation 0 in their key, which is what makes
     them distinguishable from connection keys at dispatch. */
  struct epoll_event ev = {.events = EPOLLIN, .data.u64 = EVKEY_STATIC(sfd)};
  epoll_ctl(epfd, EPOLL_CTL_ADD, sfd, &ev);
  ev.data.u64 = EVKEY_STATIC(sigfd);
  epoll_ctl(epfd, EPOLL_CTL_ADD, sigfd, &ev);
  ev.data.u64 = EVKEY_STATIC(tfd);
  epoll_ctl(epfd, EPOLL_CTL_ADD, tfd, &ev);

  conn_table_init(); /* fd = -1 in every slot; 0 would alias stdin */
  /* Before the first accept, so no connection can be classified against
     a half-loaded registry. */
  load_client_registry();
  load_key_policy();

  printf("uictld: listening on %s\n", path);
  fflush(stdout);

  /* WIRE.md §8.8 requires the socket-activated case to be visible
     specifically, not just "started". The two are operationally
     different: an activated daemon appeared because somebody connected,
     which means a client is already waiting on this pid, and it did not
     create the socket file it is serving — so `rm` on that path is a
     mistake here in a way it is not otherwise. Naming it also tells an
     operator which half to restart when something is wrong: the service,
     or the socket unit that owns the listener. */
  if (g_socket_inherited)
    fprintf(stderr,
            "uictld: socket-activated — systemd owns %s and this process "
            "does not remove it\n",
            path);

  /* Idle exit, decided here because it depends on how we got our socket.
     Refused rather than silently ignored when it cannot work: a unit
     that sets this without socket activation is asking for a daemon that
     disappears and does not come back, and the difference between "your
     setting was wrong" and "the daemon keeps vanishing" is a debugging
     afternoon. */
  {
    const char *idle = getenv("UICTL_IDLE_EXIT_SEC");
    if (idle && *idle) {
      errno = 0;
      char *end;
      long v = strtol(idle, &end, 10);
      if (errno != 0 || *end != '\0' || v < 0) {
        fprintf(stderr, "uictld: UICTL_IDLE_EXIT_SEC=%s is not a number of "
                        "seconds — ignoring it\n",
                idle);
      } else if (v == 0) {
        /* An explicit 0 is a legitimate way to say "off" in a unit file
           that always sets the variable. Not a warning. */
      } else if (!g_socket_inherited) {
        fprintf(stderr,
                "uictld: UICTL_IDLE_EXIT_SEC is set but this daemon was not "
                "socket-activated — ignoring it\n"
                "  why:  nothing would start the daemon again, so exiting "
                "would take the\n        socket with it and every later "
                "client would get ECONNREFUSED\n"
                "  fix:  enable uictld.socket, or unset the variable.\n");
      } else if (v < IDLE_EXIT_MIN_SEC) {
        fprintf(stderr,
                "uictld: UICTL_IDLE_EXIT_SEC=%ld is below the %d second "
                "floor — using %d\n"
                "  why:  activation starts this daemon BECAUSE a client "
                "connected. a timer\n        shorter than that connection "
                "takes to arrive is a restart loop.\n",
                v, IDLE_EXIT_MIN_SEC, IDLE_EXIT_MIN_SEC);
        g_idle_exit_sec = IDLE_EXIT_MIN_SEC;
      } else {
        g_idle_exit_sec = v;
      }
      if (g_idle_exit_sec > 0)
        fprintf(stderr,
                "uictld: will exit after %lds with no connections; the "
                "next connect() starts a new instance\n",
                g_idle_exit_sec);
    }
  }

  /* Ready means a client may connect and expect service: the devices are
     registered, the epoll set is armed and the accept loop is about to
     run. Sent here and not one line earlier — everything above can still
     fail, and telling the supervisor "ready" before that would turn a
     start-up failure into a unit that is active and broken. */
  notify_systemd("READY=1\n");

  /* WIRE.md §8.8. On stderr, not stdout, because that is what the
     journal captures under Type=notify and because a restart is
     diagnostic output rather than a result.

     The pid is the point. A client's held state died with its
     connection when this line was printed (§8.3), and the client has no
     way to know that happened — §8.6's advice is the only thing that
     even hints at it. When someone reports "my modifier got stuck" or
     "my drag ended by itself", this line and its timestamp are what
     turn that into "the daemon restarted at 14:02" instead of a hunt
     through the compositor. */
  fprintf(stderr,
          "uictld: started (pid %d) — any client connected to a previous "
          "instance has lost its held state and must re-HELLO\n",
          (int)getpid());

  struct epoll_event events[8];
  int stop = 0;

  /* The countdown starts now, not at the first disconnect. An activated
     daemon that is started and then never spoken to is the case this has
     to cover — otherwise a client that connects, is refused at admission
     and goes away leaves the daemon resident for the rest of the
     session. */
  g_idle_since = mono_secs();

  while (!stop && !g_idle_expired) {
    int nfd = epoll_wait(epfd, events, 8, -1);
    if (nfd < 0) {
      if (errno == EINTR)
        continue;
      perror("uictld: epoll_wait");
      break;
    }

    for (int i = 0; i < nfd; i++) {
      uint64_t key = events[i].data.u64;
      int is_static = (EVKEY_GEN(key) == 0);
      int skey = is_static ? (int)EVKEY_LOW(key) : -1;

      if (is_static && skey == sigfd) {
        struct signalfd_siginfo si;
        if (read(sigfd, &si, sizeof(si)) != (ssize_t)sizeof(si)) {
          /* Can't tell what arrived. Shutting down is the safe reading:
             the alternative is ignoring a SIGTERM. */
          perror("uictld: read signalfd");
          stop = 1;
          break;
        }

        /* Not every signal is a shutdown — this branch used to assume
           so. One siginfo is consumed per event; if several signals are
           pending the fd stays readable (level-triggered) and we come
           back for the rest, so `continue` here loses nothing. */
        if (si.ssi_signo == SIGUSR1) {
          conn_dump_table();
          continue;
        }

        fprintf(stderr, "uictld: signal %u, shutting down\n", si.ssi_signo);
        stop = 1;
        break;
      } else if (is_static && skey == tfd) {
        /* MANDATORY. epoll here is level-triggered, so the fd stays
           readable until the expiration count is consumed; skip this
           read and the loop spins at 100% CPU forever. The value is the
           number of expiries since the last read (>1 if we were busy) —
           we do not care how many, only that a tick happened. */
        uint64_t expirations;
        if (read(tfd, &expirations, sizeof(expirations)) !=
            (ssize_t)sizeof(expirations)) {
          if (errno != EAGAIN && errno != EWOULDBLOCK)
            perror("uictld: read timerfd");
          continue;
        }
        conn_reap_partial(epfd, devs, audit_fd);
      } else if (is_static && skey == sfd) {
        /* Accept until EAGAIN: one EPOLLIN on the listening socket can
           stand for several queued connections, and level-triggered
           epoll would otherwise just fire again. */
        for (;;) {
          int cfd = accept4(sfd, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
          if (cfd < 0) {
            if (errno == EINTR)
              continue;
            if (errno != EAGAIN && errno != EWOULDBLOCK)
              perror("uictld: accept4");
            break;
          }

          struct ucred cred;
          socklen_t cred_len = sizeof(cred);
          if (getsockopt(cfd, SOL_SOCKET, SO_PEERCRED, &cred, &cred_len) < 0) {
            perror("uictld: getsockopt SO_PEERCRED");
            close(cfd);
            continue;
          }
          if (cred.uid != getuid()) {
            audit_log(audit_fd, cred.pid, cred.uid, 0, OP_INVALID, 0,
                      ERR_DENIED_BY_POLICY, "peer uid mismatch");
            deny_and_close(cfd, ERR_DENIED_BY_POLICY);
            continue;
          }

          /* §8.7's backstop runs FIRST, before either cap, for two
             reasons. It has to count attempts the caps would refuse
             anyway: a client hammering a full table is the same storm as
             one hammering an empty table, and if a cap answered first
             the storm would never be recorded and could retry at full
             speed forever. And it is the cheapest of the three checks,
             so a storming peer costs one table scan rather than two. */
          if (!attempt_admit(cred.pid)) {
            audit_log(audit_fd, cred.pid, cred.uid, 0, OP_INVALID, 0, ERR_BUSY,
                      "connection-attempt storm");
            deny_and_close(cfd, ERR_BUSY);
            continue;
          }

          /* Per-pid cap before the table cap, so a peer that is already
             at its own limit is told so specifically. Both are ERR_BUSY:
             from the client's side both mean "no slot for you right now,
             try again", which is exactly what ERR_BUSY promises and what
             ERR_DENIED_BY_POLICY (terminal) must not be used for.

             The M3.5 reaper cannot substitute for this check and that is
             deliberate, not an oversight: decision 2 defines an idle
             connection with no frame in progress as well-behaved, so 32
             idle connections from one pid are, by the daemon's own
             rules, 32 innocent connections. This is the only thing that
             stops them from being all of them. */
          if (conn_count_pid(cred.pid) >= MAX_CONNS_PER_PID) {
            audit_log(audit_fd, cred.pid, cred.uid, 0, OP_INVALID, 0,
                      ERR_BUSY, "per-pid conn cap");
            deny_and_close(cfd, ERR_BUSY);
            continue;
          }

          struct conn *c = conn_alloc(cfd, &cred);
          if (!c) {
            /* M3.5 task 3: hard global cap. We still accept() and
               close() rather than leaving it queued — an unaccepted
               connection keeps the listening socket readable forever. */
            audit_log(audit_fd, cred.pid, cred.uid, 0, OP_INVALID, 0, ERR_BUSY,
                      "conn table full");
            deny_and_close(cfd, ERR_BUSY);
            continue;
          }

          /* M9: read the peer's binary now, while the process that
             connected is still the process that connected. Failure is
             not an error -- an unknown exe simply cannot satisfy a
             registry binding -- so nothing is refused here. */
          if (peer_exe(cred.pid, c->exe, sizeof(c->exe)) < 0)
            c->exe[0] = '\0';

          struct epoll_event cev = {.events = EPOLLIN,
                                    .data.u64 = conn_evkey(c)};
          if (epoll_ctl(epfd, EPOLL_CTL_ADD, cfd, &cev) < 0) {
            perror("uictld: epoll_ctl ADD client");
            conn_close(epfd, c, devs, audit_fd);
            continue;
          }
        }
      } else {
        struct conn *c = conn_from_evkey(key);
        if (!c)
          continue; /* connection closed earlier in this same batch */
        if (events[i].events & (EPOLLHUP | EPOLLERR)) {
          conn_close(epfd, c, devs, audit_fd);
          continue;
        }
        /* Only ever one of the two is registered at a time (see
           conn_update_events), but check both and re-test c->fd:
           conn_writable can close the connection out from under us. */
        if (events[i].events & EPOLLOUT)
          conn_writable(epfd, c, devs, audit_fd);
        if (c->fd >= 0 && (events[i].events & EPOLLIN))
          conn_readable(epfd, c, devs, audit_fd);
      }
    }
  }

  fprintf(stderr, "uictld: shutting down\n");

  /* Anything still accumulating goes to the log before the fd closes.
     Dropping it would mean the last second of a client's activity is
     missing exactly when the daemon went down, which is when someone is
     most likely to read the log. */
  motion_flush(audit_fd, 1);

  /* Close live connections before tearing down the device, so a client
     blocked in read() sees EOF rather than a silently vanished daemon. */
  for (int i = 0; i < MAX_CONNS; i++)
    if (conns[i].fd >= 0)
      conn_close(epfd, &conns[i], devs, audit_fd);

  /* Before the teardown, not after: STOPPING=1 tells systemd the exit is
     deliberate, so a shutdown that then takes a moment to release held
     keys reads as a clean stop rather than a daemon that stopped
     answering. */
  notify_systemd("STOPPING=1\n");

  uinput_close(&devices);
  close(tfd);
  close(sigfd);
  close(epfd);
  close(sfd);
  socket_path_cleanup(path);
  close(audit_fd);
  close(lockfd);
  return 0;
}
