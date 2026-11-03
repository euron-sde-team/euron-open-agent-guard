/*
 * agentguard-sandbox-measure: run one command and record its exact resource usage.
 *
 *   agentguard-sandbox-measure <usage-file> <absolute-path> [args...]
 *
 * Why it exists: Linux carries a process's peak resident memory across fork and exec, so
 * a program started by the sandbox service (a Python process of tens of megabytes) would
 * report at least the service's own peak as its memory. This helper is tiny; the command
 * it forks (nsjail) starts from the helper's footprint, and wait4 on it returns the CPU
 * time and peak memory of nsjail and every process of the sandbox, nothing of the service.
 *
 * It also raises its oom_score_adj to 1000 first (allowed without privilege, inherited),
 * so under memory pressure the kernel kills the sandboxed program, not the service, and it
 * forwards SIGTERM, SIGINT and SIGHUP to the command (nsjail then ends the sandbox).
 *
 * The usage file receives one line: "<wait status> <user us> <system us> <maxrss kb>".
 * The helper exits with the command's exit code, or dies by the same signal.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile pid_t child = -1;

static void forward(int sig) {
    if (child > 0) kill(child, sig);
}

int main(int argc, char **argv) {
    if (argc < 3 || argv[2][0] != '/') {
        fprintf(stderr, "usage: %s <usage-file> <absolute-path> [args...]\n", argv[0]);
        return 2;
    }
    /* No core files from the helper or anything it starts. */
    struct rlimit no_core = {0, 0};
    setrlimit(RLIMIT_CORE, &no_core);
    int adj = open("/proc/self/oom_score_adj", O_WRONLY | O_CLOEXEC);
    if (adj >= 0) {
        (void)!write(adj, "1000", 4);
        close(adj);
    }
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = forward;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return 125;
    }
    if (pid == 0) {
        /* Handlers reset to default on exec; nothing else of the helper is inherited. */
        execv(argv[2], &argv[2]);
        perror("execv");
        _exit(125);
    }
    child = pid;

    int status = 0;
    struct rusage ru;
    memset(&ru, 0, sizeof ru);
    while (wait4(pid, &status, 0, &ru) < 0) {
        if (errno != EINTR) {
            perror("wait4");
            return 125;
        }
    }
    FILE *out = fopen(argv[1], "we");
    if (out != NULL) {
        long long user = (long long)ru.ru_utime.tv_sec * 1000000LL + ru.ru_utime.tv_usec;
        long long sys = (long long)ru.ru_stime.tv_sec * 1000000LL + ru.ru_stime.tv_usec;
        fprintf(out, "%d %lld %lld %ld\n", status, user, sys, ru.ru_maxrss);
        fclose(out);
    }
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) {
        int sig = WTERMSIG(status);
        signal(sig, SIG_DFL);
        sigset_t set;
        sigemptyset(&set);
        sigaddset(&set, sig);
        sigprocmask(SIG_UNBLOCK, &set, NULL);
        raise(sig);
        return 128 + sig;
    }
    return 125;
}
