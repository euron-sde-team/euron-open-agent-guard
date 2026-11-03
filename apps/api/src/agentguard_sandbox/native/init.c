/*
 * agentguard-sandbox-init: the first process inside every sandbox.
 *
 *   agentguard-sandbox-init --work <dir> [--proxy <unix-socket> <port>] -- <program> [args...]
 *
 * 1. Copies the read-only input (/sandbox/in: the code and the request's files) into the
 *    work directory on the sandbox's private, size-limited tmpfs, so the program may change
 *    its own files.
 * 2. In proxy mode, binds 127.0.0.1:<port> and forks a forwarder that relays every
 *    connection to the unix socket the service mounted into the sandbox. Binding before
 *    the fork means the port is ready before the program starts.
 * 3. Replaces itself with the program, which keeps PID 1 of the sandbox: when it exits,
 *    the kernel ends every other process in the sandbox, the forwarder included.
 *
 * It is a small static binary rather than a script so that it adds no process and almost
 * no memory to what the run measures (Linux carries peak memory across exec).
 *
 * The forwarder is a convenience, not a security boundary: the program may kill it or use
 * the unix socket directly. The relay on the other end, outside the sandbox, is the part
 * that connects only to the egress proxy and adds the credential, which never enters here.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#define INPUT "/sandbox/in"
#define LAUNCH_ERROR 125
#define BUF 65536
#define MAX_PAIRS 24

static void die(const char *what) {
    fprintf(stderr, "agentguard-sandbox-init: %s: %s\n", what, strerror(errno));
    _exit(LAUNCH_ERROR);
}

static int copy_file(const char *from, const char *to) {
    int in = open(from, O_RDONLY | O_CLOEXEC);
    if (in < 0) return -1;
    int out = open(to, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (out < 0) {
        close(in);
        return -1;
    }
    char buf[BUF];
    ssize_t n;
    while ((n = read(in, buf, sizeof buf)) > 0) {
        char *p = buf;
        while (n > 0) {
            ssize_t w = write(out, p, (size_t)n);
            if (w < 0) {
                if (errno == EINTR) continue;
                close(in);
                close(out);
                return -1;
            }
            p += w;
            n -= w;
        }
    }
    close(in);
    return close(out) == 0 && n == 0 ? 0 : -1;
}

/* Recursive copy of directories and regular files; anything else is skipped. */
static int copy_tree(const char *from, const char *to) {
    if (mkdir(to, 0755) < 0 && errno != EEXIST) return -1;
    DIR *dir = opendir(from);
    if (dir == NULL) return -1;
    struct dirent *e;
    int rc = 0;
    while (rc == 0 && (e = readdir(dir)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
        char src[4096], dst[4096];
        if (snprintf(src, sizeof src, "%s/%s", from, e->d_name) >= (int)sizeof src ||
            snprintf(dst, sizeof dst, "%s/%s", to, e->d_name) >= (int)sizeof dst) {
            errno = ENAMETOOLONG;
            rc = -1;
            break;
        }
        struct stat st;
        if (lstat(src, &st) < 0) {
            rc = -1;
        } else if (S_ISDIR(st.st_mode)) {
            rc = copy_tree(src, dst);
        } else if (S_ISREG(st.st_mode)) {
            rc = copy_file(src, dst);
        }
    }
    closedir(dir);
    return rc;
}

/* One direction of a relayed connection: bytes read from `from`, waiting for `to`. */
struct half {
    int from, to;
    char buf[BUF];
    size_t len, off;
    int eof;
};

struct pair {
    int used;
    struct half up, down;
};

static struct pair pairs[MAX_PAIRS];

static void close_pair(struct pair *p) {
    close(p->up.from);
    close(p->up.to);
    p->used = 0;
}

/* Move bytes for one direction; returns 0 while the direction is still alive. */
static int pump(struct half *h, short from_events, short to_events) {
    if (h->len == 0 && !h->eof && (from_events & (POLLIN | POLLHUP | POLLERR))) {
        ssize_t n = read(h->from, h->buf, sizeof h->buf);
        if (n > 0) {
            h->len = (size_t)n;
            h->off = 0;
        } else if (n == 0 || (errno != EAGAIN && errno != EINTR)) {
            h->eof = 1;
            shutdown(h->to, SHUT_WR);
        }
    }
    if (h->len > 0 && (to_events & POLLOUT)) {
        ssize_t w = write(h->to, h->buf + h->off, h->len);
        if (w > 0) {
            h->off += (size_t)w;
            h->len -= (size_t)w;
        } else if (w < 0 && errno != EAGAIN && errno != EINTR) {
            return -1;
        }
    }
    return 0;
}

static void forward(int listener, const char *unix_path) {
    signal(SIGPIPE, SIG_IGN);
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof addr);
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, unix_path, sizeof addr.sun_path - 1);
    for (;;) {
        struct pollfd fds[1 + MAX_PAIRS * 2];
        int map[1 + MAX_PAIRS * 2];
        int n = 0;
        fds[n].fd = listener;
        fds[n].events = POLLIN;
        map[n++] = -1;
        for (int i = 0; i < MAX_PAIRS; i++) {
            if (!pairs[i].used) continue;
            struct pair *p = &pairs[i];
            /* fds: the client (up.from) and the unix socket (down.from). */
            fds[n].fd = p->up.from;
            fds[n].events = (short)((p->up.len == 0 && !p->up.eof ? POLLIN : 0) |
                                    (p->down.len > 0 ? POLLOUT : 0));
            map[n++] = i;
            fds[n].fd = p->down.from;
            fds[n].events = (short)((p->down.len == 0 && !p->down.eof ? POLLIN : 0) |
                                    (p->up.len > 0 ? POLLOUT : 0));
            map[n++] = i;
        }
        if (poll(fds, (nfds_t)n, -1) < 0) {
            if (errno == EINTR) continue;
            _exit(0);
        }
        if (fds[0].revents & POLLIN) {
            int client = accept4(listener, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
            int slot = -1;
            for (int i = 0; i < MAX_PAIRS && client >= 0; i++) {
                if (!pairs[i].used) {
                    slot = i;
                    break;
                }
            }
            int upstream = -1;
            if (slot >= 0) {
                upstream = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
                if (upstream >= 0 &&
                    connect(upstream, (struct sockaddr *)&addr, sizeof addr) == 0) {
                    fcntl(upstream, F_SETFL, O_NONBLOCK);
                    struct pair *p = &pairs[slot];
                    memset(p, 0, sizeof *p);
                    p->used = 1;
                    p->up.from = client;
                    p->up.to = upstream;
                    p->down.from = upstream;
                    p->down.to = client;
                    client = upstream = -1;
                }
            }
            if (client >= 0) close(client);
            if (upstream >= 0) close(upstream);
        }
        for (int k = 1; k < n; k += 2) {
            struct pair *p = &pairs[map[k]];
            if (!p->used) continue;
            short client_ev = fds[k].revents, unix_ev = fds[k + 1].revents;
            if (pump(&p->up, client_ev, unix_ev) < 0 || pump(&p->down, unix_ev, client_ev) < 0 ||
                (p->up.eof && p->down.eof && p->up.len == 0 && p->down.len == 0)) {
                close_pair(p);
            }
        }
    }
}

static void start_forwarder(const char *unix_path, int port) {
    int listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listener < 0) die("socket");
    int one = 1;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(listener, (struct sockaddr *)&addr, sizeof addr) < 0) die("bind 127.0.0.1");
    if (listen(listener, 64) < 0) die("listen");
    pid_t pid = fork();
    if (pid < 0) die("fork");
    if (pid == 0) {
        int null = open("/dev/null", O_RDWR);
        if (null >= 0) {
            dup2(null, 0);
            dup2(null, 1);
            dup2(null, 2);
            if (null > 2) close(null);
        }
        forward(listener, unix_path);
        _exit(0);
    }
    close(listener);
}

int main(int argc, char **argv) {
    const char *work = NULL, *unix_path = NULL;
    int port = 0, i = 1;
    for (; i < argc && strcmp(argv[i], "--") != 0; i++) {
        if (strcmp(argv[i], "--work") == 0 && i + 1 < argc) {
            work = argv[++i];
        } else if (strcmp(argv[i], "--proxy") == 0 && i + 2 < argc) {
            unix_path = argv[++i];
            port = atoi(argv[++i]);
        } else {
            fprintf(stderr, "agentguard-sandbox-init: unknown argument %s\n", argv[i]);
            return LAUNCH_ERROR;
        }
    }
    if (work == NULL || i + 1 >= argc) {
        fprintf(stderr, "agentguard-sandbox-init: --work <dir> -- <program> is required\n");
        return LAUNCH_ERROR;
    }
    char **program = &argv[i + 1];
    if (copy_tree(INPUT, work) < 0) die("copy input");
    if (chdir(work) < 0) die("chdir");
    if (unix_path != NULL) {
        if (port <= 0 || port > 65535) {
            fprintf(stderr, "agentguard-sandbox-init: invalid port\n");
            return LAUNCH_ERROR;
        }
        start_forwarder(unix_path, port);
    }
    execv(program[0], program);
    die("execv");
    return LAUNCH_ERROR;
}
