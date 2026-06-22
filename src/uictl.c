#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
  if (argc != 2 || strcmp(argv[1], "ping") != 0) {
    fprintf(stderr, "usage: %s ping\n", argv[0]);
    return 1;
  }

  const char *xdg = getenv("XDG_RUNTIME_DIR");
  if (!xdg) {
    fprintf(stderr, "uictl: XDG_RUNTIME_DIR is not set\n");
    return 1;
  }

  char path[108];
  int n = snprintf(path, sizeof(path), "%s/uictld.sock", xdg);
  if(n < 0 || (size_t)n >= sizeof(path)) {
    fprintf(stderr, "uictl: socket path too long\n");
    return 1;
  }

  int sfd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (sfd < 0) {
    perror("uictl: socket");
    return 1;
  }

  struct sockaddr_un addr = { .sun_family = AF_UNIX };
  strcpy(addr.sun_path, path);

  if (connect(sfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    perror("uictl: connect");
    close(sfd);
    return 1;
  }

  if (write(sfd, "PING\n", 5) < 0) {
    perror("uictl: write");
    close(sfd);
    return 1;
  }

  char buf[16];
  ssize_t r = read(sfd, buf, sizeof(buf));
  if (r < 0) {
    perror("uictl: read");
    close(sfd);
    return 1;
  }
  if (r == 0) {
    fprintf(stderr, "uictl: daemon closed without responding\n");
    close(sfd);
    return 1;
  }

  if (write(STDOUT_FILENO, buf, (size_t)r) < 0) {
    perror("uictl: write stdout");
  }

  close(sfd);
  return 0;
}
