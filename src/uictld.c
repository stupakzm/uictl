#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <sys/un.h>
#include <signal.h>

static volatile sig_atomic_t stop = 0;

static void on_signal(int signo) {
  (void)signo;
  stop = 1;
}

int main(void) {

  const char *xdg = getenv("XDG_RUNTIME_DIR");
  if (!xdg) {
    fprintf(stderr, "uictld: XDG_RUNTIME_DIR is not set, failed to start\n");
    return 1;
  }

  char path[108];
  int n = snprintf(path, sizeof(path), "%s/uictld.sock", xdg);
  if (n < 0 || (size_t)n >= sizeof(path)) {
    fprintf(stderr, "uictld: socket path too long\n");
    return 1;
  }

  umask(0077);
  int sfd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (sfd < 0) {
    perror("uictld: socket");
    return 1;
  }

  struct sockaddr_un addr = { .sun_family = AF_UNIX };
  strcpy(addr.sun_path, path);

  if (unlink(path) < 0 && errno != ENOENT) {
    perror("uictld: unlink");
    close(sfd);
    return 1;
  }

  struct sigaction sa = { .sa_handler = on_signal};
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;

  if (sigaction(SIGINT, &sa, NULL) < 0) {
    perror("uictld: sigaction SIGINT");
    close(sfd);
    return 1;
  }
  if (sigaction(SIGTERM, &sa, NULL) < 0) {
    perror("uictld: sigaction SIGTERM");
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
  
  if (bind(sfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    perror("uictld: bind");
    close(sfd);
    unlink(path);
    return 1;
  }

  if (listen(sfd, 16) < 0) {
    perror("uictld: listen");
    close(sfd);
    unlink(path);
    return 1;
  }

  printf("uictld: listening on %s\n", path);
  fflush(stdout);

  while (!stop) {
    int cfd = accept4(sfd, NULL, NULL, SOCK_CLOEXEC);
    if (cfd < 0) {
      if (errno == EINTR)
        continue;
      perror("uictld: accept4");
      continue;
    }

    char buf[16];
    ssize_t r = read(cfd, buf, sizeof(buf));
    if (r < 0) {
      perror("uictld: read");
      close(cfd);
      continue;
    }
    if (r == 0) {
      close(cfd);
      continue;
    }

    if (r == 5 && memcmp(buf, "PING\n", 5) == 0) {
      if (write(cfd, "PONG\n", 5) < 0) {
        perror("uictld: write");
      }
    }
    
    close(cfd);
  }

  fprintf(stderr, "uictld: shutting down\n");
  
  close(sfd);
  unlink(path);
  return 0;
}
