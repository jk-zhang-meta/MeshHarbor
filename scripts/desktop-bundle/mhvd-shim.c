// SPDX-License-Identifier: MPL-2.0
// FR-120 P4 — the embedded desktop's exec / dlopen shim.
//
// Every program of the embedded desktop runs on the bundle's OWN glibc,
// through the bundle's dynamic loader:
//
//     <root>/usr/lib/<triplet>/ld-linux-*.so.* --library-path <libs>
//         --preload <this shim> --argv0 <name> <root>/usr/bin/<name> ...
//
// so it works on any host glibc. This shim, preloaded into each of them,
// keeps the two worlds apart:
//
//  1. An exec of a HOST program (the person's shell from the terminal, an
//     application from the menu) gets the host's environment back: every
//     variable the desktop set is restored to the value it had before
//     (MHVD_ORIG_<NAME>) or removed, the bundle's bin directory leaves PATH,
//     and the MHVD_* bookkeeping goes. Nothing of the bundle leaks into it.
//  2. An exec of a path the desktop's programs were COMPILED with
//     (/usr/lib/<triplet>/xfce4/xfconf/xfconfd, /usr/bin/dbus-daemon, ...)
//     that the bundle carries runs the bundle's copy, through its loader.
//  3. dlopen(), bindtextdomain(), read-only opens and existence checks
//     (open/fopen/stat/access/statx/opendir) of such paths go to the
//     bundle's copy too: panel plugins, translations, and data read from a
//     compiled-in directory (xfwm4's /usr/share/xfwm4/defaults).
//  4. The calls glibc implements WITHOUT going through execve's PLT entry —
//     execl/execle/execlp (dbus-launch starts dbus-daemon with execl), and
//     system/popen, whose /bin/sh is spawned inside libc — are implemented
//     here on top of 1 and 2. In a shell command (system, popen, any
//     `sh -c`), a compiled-in /usr program the bundle carries that stands in
//     a command position runs the bundle's copy (xfce4-session's
//     `/usr/bin/iceauth source ...`).
//
// Configuration comes from the environment the launcher set:
//   MHVD_ROOT    the bundle's usr tree parent (<vd>/root)
//   MHVD_LD      the bundle's dynamic loader
//   MHVD_LIBS    its --library-path
//   MHVD_SHIM    this file
//   MHVD_BIN     the bundle's wrapper directory (stripped from host PATHs)
//   MHVD_VARS    ':'-separated names the desktop set (restored for the host)
#define _GNU_SOURCE
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

typedef int (*execve_fn)(const char *, char *const[], char *const[]);
typedef int (*spawn_fn)(pid_t *, const char *, const posix_spawn_file_actions_t *,
                        const posix_spawnattr_t *, char *const[], char *const[]);
typedef void *(*dlopen_fn)(const char *, int);
typedef char *(*btd_fn)(const char *, const char *);

static const char *env_get(char *const envp[], const char *name) {
    size_t n = strlen(name);
    for (char *const *e = envp; e && *e; e++)
        if (strncmp(*e, name, n) == 0 && (*e)[n] == '=') return *e + n + 1;
    return NULL;
}

static int starts_with(const char *s, const char *p) {
    return s && p && *p && strncmp(s, p, strlen(p)) == 0;
}

/* The real libc functions, for the shim's own probes: its exported open/stat
 * below would otherwise answer them. */
#define REAL(ret, name, ...)                                              \
    static ret (*real_##name(void))(__VA_ARGS__) {                         \
        static ret (*f)(__VA_ARGS__);                                      \
        if (!f) f = (ret(*)(__VA_ARGS__))dlsym(RTLD_NEXT, #name);          \
        return f;                                                          \
    }
REAL(int, open, const char *, int, ...)
REAL(int, open64, const char *, int, ...)
REAL(int, openat, int, const char *, int, ...)
REAL(int, openat64, int, const char *, int, ...)
REAL(int, __open_2, const char *, int)
REAL(int, __open64_2, const char *, int)
REAL(int, __openat_2, int, const char *, int)
REAL(int, __openat64_2, int, const char *, int)
REAL(FILE *, fopen, const char *, const char *)
REAL(FILE *, fopen64, const char *, const char *)
REAL(int, stat, const char *, struct stat *)
REAL(int, lstat, const char *, struct stat *)
REAL(int, stat64, const char *, struct stat64 *)
REAL(int, lstat64, const char *, struct stat64 *)
REAL(int, fstatat, int, const char *, struct stat *, int)
REAL(int, fstatat64, int, const char *, struct stat64 *, int)
REAL(int, statx, int, const char *, int, unsigned int, struct statx *)
REAL(int, access, const char *, int)
REAL(int, faccessat, int, const char *, int, int)
REAL(DIR *, opendir, const char *)

static int is_file(const char *p) {
    struct stat st;
    return real_stat()(p, &st) == 0 && S_ISREG(st.st_mode);
}

static int exists(const char *p) {
    struct stat st;
    return real_lstat()(p, &st) == 0;
}

static int is_elf(const char *p) {
    int fd = real_open()(p, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    unsigned char m[4] = {0};
    ssize_t n = read(fd, m, 4);
    close(fd);
    return n == 4 && m[0] == 0x7f && m[1] == 'E' && m[2] == 'L' && m[3] == 'F';
}

/* `<MHVD_ROOT><path>` for a compiled-in absolute path (/usr/..., /etc/xdg/...). */
static int bundled_path(const char *path, char *out, size_t outsz) {
    const char *root = getenv("MHVD_ROOT");
    if (!root || !*root || !path || path[0] != '/') return 0;
    if (!starts_with(path, "/usr/") && !starts_with(path, "/etc/xdg/")) return 0;
    return snprintf(out, outsz, "%s%s", root, path) < (int)outsz;
}

/* The bundle's copy as a regular file (exec, dlopen). */
static int bundled_copy(const char *path, char *out, size_t outsz) {
    return bundled_path(path, out, outsz) && is_file(out);
}

/* What a read or an existence check of `path` should see: the bundle's
 * copy of a FILE (its programs read the data they were built with), but a
 * DIRECTORY only when the host has none — /usr/share/applications and the
 * like are listings XDG_DATA_DIRS merges with the host's. */
static const char *bundled_any(const char *path, char *out, size_t outsz) {
    if (!bundled_path(path, out, outsz) || !exists(out)) return path;
    struct stat st;
    if (real_stat()(out, &st) == 0 && S_ISDIR(st.st_mode) && exists(path)) return path;
    return out;
}

/* Is `path` inside the bundle (its wrappers or its tree)? */
static int in_bundle(const char *path) {
    const char *root = getenv("MHVD_ROOT"), *bin = getenv("MHVD_BIN");
    return starts_with(path, root) || starts_with(path, bin);
}

/* argv for running bundled ELF `file` through the bundle's loader. */
static char **loader_argv(const char *file, char *const argv[]) {
    const char *ld = getenv("MHVD_LD"), *libs = getenv("MHVD_LIBS"),
               *shim = getenv("MHVD_SHIM");
    if (!ld || !libs || !shim) return NULL;
    int argc = 0;
    while (argv && argv[argc]) argc++;
    char **a = calloc((size_t)argc + 10, sizeof(char *));
    if (!a) return NULL;
    int i = 0;
    a[i++] = (char *)ld;
    a[i++] = "--library-path";
    a[i++] = (char *)libs;
    a[i++] = "--preload";
    a[i++] = (char *)shim;
    a[i++] = "--argv0";
    a[i++] = argc ? argv[0] : (char *)file;
    a[i++] = (char *)file;
    for (int k = 1; k < argc; k++) a[i++] = argv[k];
    a[i] = NULL;
    return a;
}

/* A growable string. */
struct sb { char *s; size_t n, cap; int bad; };
static void sb_put(struct sb *b, const char *p, size_t l) {
    if (b->bad) return;
    if (b->n + l + 1 > b->cap) {
        size_t c = b->cap ? b->cap : 256;
        while (c < b->n + l + 1) c *= 2;
        char *x = realloc(b->s, c);
        if (!x) { b->bad = 1; return; }
        b->s = x;
        b->cap = c;
    }
    memcpy(b->s + b->n, p, l);
    b->n += l;
    b->s[b->n] = 0;
}
/* `p` as one shell word, single-quoted. */
static void sb_quote(struct sb *b, const char *p) {
    sb_put(b, "'", 1);
    for (; *p; p++) {
        if (*p == '\'') sb_put(b, "'\\''", 4);
        else sb_put(b, p, 1);
    }
    sb_put(b, "'", 1);
}

/* The shell words that run the bundle's copy of compiled-in program `word`
 * (`len` bytes), appended to `b`; 0 when the bundle has no such program. */
static int bundled_invocation(struct sb *b, const char *word, size_t len) {
    char path[PATH_MAX], copy[PATH_MAX];
    if (len >= sizeof path) return 0;
    memcpy(path, word, len);
    path[len] = 0;
    if (!bundled_copy(path, copy, sizeof copy)) return 0;
    const char *bin = getenv("MHVD_BIN"), *name = strrchr(path, '/') + 1;
    char w[PATH_MAX];
    if (bin && *bin && (starts_with(path, "/usr/bin/") || starts_with(path, "/usr/sbin/")) &&
        !strchr(name, '/') && snprintf(w, sizeof w, "%s/%s", bin, name) < (int)sizeof w &&
        real_access()(w, X_OK) == 0) {
        sb_quote(b, w); /* its wrapper */
        return 1;
    }
    if (!is_elf(copy)) { sb_quote(b, copy); return 1; } /* a script */
    const char *ld = getenv("MHVD_LD"), *libs = getenv("MHVD_LIBS"), *shim = getenv("MHVD_SHIM");
    if (!ld || !libs || !shim) return 0;
    sb_quote(b, ld);
    sb_put(b, " --library-path ", 16);
    sb_quote(b, libs);
    sb_put(b, " --preload ", 11);
    sb_quote(b, shim);
    sb_put(b, " --argv0 ", 9);
    sb_quote(b, path);
    sb_put(b, " ", 1);
    sb_quote(b, copy);
    return 1;
}

/* Shell command `cmd` with every compiled-in /usr program the bundle carries
 * that stands in a command position (the start, after ; & | ( or a newline,
 * after `exec`) replaced by the bundle's copy: xfce4-session's
 * `/usr/bin/iceauth source ...`, an autostart's `... || exec /usr/lib/...`.
 * NULL when nothing changes. Caller frees. */
static char *bundled_command(const char *cmd) {
    if (!cmd || !getenv("MHVD_ROOT")) return NULL;
    struct sb b = {0};
    int at_cmd = 1, changed = 0;
    const char *p = cmd;
    while (*p) {
        if (at_cmd) {
            size_t ws = strspn(p, " \t");
            sb_put(&b, p, ws);
            p += ws;
            if (strncmp(p, "exec", 4) == 0 && (p[4] == ' ' || p[4] == '\t')) {
                sb_put(&b, p, 5);
                p += 5;
                continue;
            }
            at_cmd = 0;
            if (starts_with(p, "/usr/")) {
                size_t l = strcspn(p, " \t\n;&|<>()$`'\"\\");
                if (bundled_invocation(&b, p, l)) {
                    p += l;
                    changed = 1;
                    continue;
                }
            }
            continue;
        }
        char c = *p;
        if (c == '\'' || c == '"') {
            /* A quoted string: no command position inside it. */
            const char *q = p + 1;
            while (*q && *q != c) q += (c == '"' && *q == '\\' && q[1]) ? 2 : 1;
            if (*q) q++;
            sb_put(&b, p, (size_t)(q - p));
            p = q;
            continue;
        }
        if (c == '\\' && p[1]) { sb_put(&b, p, 2); p += 2; continue; }
        sb_put(&b, p, 1);
        p++;
        if (c == ';' || c == '&' || c == '|' || c == '(' || c == '\n') at_cmd = 1;
    }
    if (!changed || b.bad) { free(b.s); return NULL; }
    return b.s;
}

/* argv of a `<shell> -c <cmd>` exec with its command rewritten by
 * bundled_command; NULL when it is not one or nothing changes. Caller frees
 * the array and its [2]. */
static char **shell_argv(const char *path, char *const argv[]) {
    if (!path || !argv || !argv[0] || !argv[1] || !argv[2]) return NULL;
    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;
    if (strcmp(base, "sh") && strcmp(base, "bash") && strcmp(base, "dash")) return NULL;
    if (strcmp(argv[1], "-c")) return NULL;
    char *c = bundled_command(argv[2]);
    if (!c) return NULL;
    int n = 0;
    while (argv[n]) n++;
    char **a = calloc((size_t)n + 1, sizeof(char *));
    if (!a) { free(c); return NULL; }
    for (int k = 0; k < n; k++) a[k] = argv[k];
    a[2] = c;
    return a;
}

/* The host's environment, rebuilt from the desktop's. Caller frees. */
static char **host_env(char *const envp[]) {
    const char *vars = env_get(envp, "MHVD_VARS");
    const char *bin = env_get(envp, "MHVD_BIN");
    if (!vars) return NULL; /* not a desktop process: leave it alone */
    size_t n = 0;
    while (envp && envp[n]) n++;
    char **out = calloc(n + 1, sizeof(char *));
    if (!out) return NULL;
    size_t o = 0;
    for (size_t i = 0; i < n; i++) {
        const char *e = envp[i];
        const char *eq = strchr(e, '=');
        if (!eq) continue;
        size_t klen = (size_t)(eq - e);
        char key[256];
        if (klen >= sizeof key) { out[o++] = (char *)e; continue; }
        memcpy(key, e, klen);
        key[klen] = 0;
        if (strncmp(key, "MHVD_", 5) == 0) continue; /* bookkeeping */
        /* A variable the desktop set: restore or drop. */
        int managed = 0;
        const char *p = vars;
        while (*p) {
            const char *c = strchr(p, ':');
            size_t l = c ? (size_t)(c - p) : strlen(p);
            if (l == klen && strncmp(p, key, l) == 0) { managed = 1; break; }
            if (!c) break;
            p = c + 1;
        }
        if (managed) continue; /* re-added below from MHVD_ORIG_ */
        if (strcmp(key, "PATH") == 0 && bin && *bin) {
            /* Strip the bundle's wrapper directory from PATH. */
            const char *v = eq + 1;
            char *np = malloc(strlen(e) + 1);
            if (!np) { out[o++] = (char *)e; continue; }
            strcpy(np, "PATH=");
            char *w = np + 5;
            int first = 1;
            while (*v) {
                const char *c = strchr(v, ':');
                size_t l = c ? (size_t)(c - v) : strlen(v);
                if (!(l == strlen(bin) && strncmp(v, bin, l) == 0)) {
                    if (!first) *w++ = ':';
                    memcpy(w, v, l);
                    w += l;
                    first = 0;
                }
                if (!c) break;
                v = c + 1;
            }
            *w = 0;
            out[o++] = np;
            continue;
        }
        out[o++] = (char *)e;
    }
    /* Restore each managed variable's original value, if it had one. */
    const char *p = vars;
    while (*p) {
        const char *c = strchr(p, ':');
        size_t l = c ? (size_t)(c - p) : strlen(p);
        char name[256], orig[300];
        if (l && l < 200) {
            memcpy(name, p, l);
            name[l] = 0;
            snprintf(orig, sizeof orig, "MHVD_ORIG_%s", name);
            const char *v = env_get(envp, orig);
            if (v) {
                size_t sz = l + strlen(v) + 2;
                char *kv = malloc(sz);
                if (kv) {
                    snprintf(kv, sz, "%s=%s", name, v);
                    out = realloc(out, (o + 2) * sizeof(char *));
                    out[o++] = kv;
                }
            }
        }
        if (!c) break;
        p = c + 1;
    }
    out[o] = NULL;
    return out;
}

static execve_fn real_execve(void) {
    static execve_fn f;
    if (!f) f = (execve_fn)dlsym(RTLD_NEXT, "execve");
    return f;
}

int execve(const char *path, char *const argv[], char *const envp[]) {
    char copy[PATH_MAX];
    if (bundled_copy(path, copy, sizeof copy)) {
        if (!is_elf(copy)) return real_execve()(copy, argv, envp); /* a script */
        char **a = loader_argv(copy, argv);
        if (a) return real_execve()(a[0], a, envp);
    }
    char **sa = shell_argv(path, argv);
    if (sa) {
        /* The shell runs the bundle's program: the desktop's environment. */
        int r = real_execve()(path, sa, envp);
        int e = errno;
        free(sa[2]);
        free(sa);
        errno = e;
        return r;
    }
    if (path && !in_bundle(path)) {
        char **he = host_env(envp);
        if (he) return real_execve()(path, argv, he);
    }
    return real_execve()(path, argv, envp);
}

int execv(const char *path, char *const argv[]) { return execve(path, argv, environ); }

/* Resolve `file` on PATH the way execvp does, then go through execve. */
static int exec_search(const char *file, char *const argv[], char *const envp[]) {
    if (!file || !*file) { errno = ENOENT; return -1; }
    if (strchr(file, '/')) return execve(file, argv, envp);
    const char *path = env_get(envp, "PATH");
    if (!path) path = "/usr/local/bin:/usr/bin:/bin";
    char buf[PATH_MAX];
    int saved = ENOENT;
    while (*path) {
        const char *c = strchr(path, ':');
        size_t l = c ? (size_t)(c - path) : strlen(path);
        if (l + strlen(file) + 2 < sizeof buf) {
            memcpy(buf, path, l);
            buf[l] = '/';
            strcpy(buf + l + 1, file);
            if (access(buf, X_OK) == 0) {
                execve(buf, argv, envp);
                saved = errno;
            }
        }
        if (!c) break;
        path = c + 1;
    }
    errno = saved;
    return -1;
}

int execvp(const char *file, char *const argv[]) { return exec_search(file, argv, environ); }
int execvpe(const char *file, char *const argv[], char *const envp[]) {
    return exec_search(file, argv, envp);
}

/* ---- execl / execle / execlp: glibc calls __execve directly. ---- */

/* Collect a NULL-terminated variadic argv; `envp_out` takes the trailing
 * environment for execle. Caller frees. */
static char **va_argv(const char *arg0, va_list ap, char *const **envp_out) {
    size_t cap = 16, n = 0;
    char **a = malloc(cap * sizeof(char *));
    if (!a) return NULL;
    a[n++] = (char *)arg0;
    while (arg0) {
        char *x = va_arg(ap, char *);
        if (n + 1 >= cap) {
            char **b = realloc(a, (cap *= 2) * sizeof(char *));
            if (!b) { free(a); return NULL; }
            a = b;
        }
        a[n++] = x;
        if (!x) break;
    }
    if (!arg0) a[n] = NULL;
    if (envp_out) *envp_out = va_arg(ap, char *const *);
    return a;
}

int execl(const char *path, const char *arg, ...) {
    va_list ap;
    va_start(ap, arg);
    char **a = va_argv(arg, ap, NULL);
    va_end(ap);
    if (!a) { errno = ENOMEM; return -1; }
    int r = execve(path, a, environ);
    int e = errno;
    free(a);
    errno = e;
    return r;
}

int execle(const char *path, const char *arg, ...) {
    va_list ap;
    va_start(ap, arg);
    char *const *envp = NULL;
    char **a = va_argv(arg, ap, &envp);
    va_end(ap);
    if (!a) { errno = ENOMEM; return -1; }
    int r = execve(path, a, envp);
    int e = errno;
    free(a);
    errno = e;
    return r;
}

int execlp(const char *file, const char *arg, ...) {
    va_list ap;
    va_start(ap, arg);
    char **a = va_argv(arg, ap, NULL);
    va_end(ap);
    if (!a) { errno = ENOMEM; return -1; }
    int r = exec_search(file, a, environ);
    int e = errno;
    free(a);
    errno = e;
    return r;
}

/* ---- system / popen: glibc spawns /bin/sh inside libc. ---- */

/* Spawn `sh -c cmd` with the environment the command's program needs: the
 * desktop's for a bundled wrapper, the host's otherwise. */
static int spawn_shell(pid_t *pid, const char *cmd, const posix_spawn_file_actions_t *fa,
                       const posix_spawnattr_t *at) {
    static spawn_fn plain;
    if (!plain) plain = (spawn_fn)dlsym(RTLD_NEXT, "posix_spawn");
    char *b = bundled_command(cmd);
    char *argv[] = {"sh", "-c", (char *)(b ? b : cmd), NULL};
    char **he = b ? NULL : host_env(environ);
    int r = plain(pid, "/bin/sh", fa, at, argv, he ? he : environ);
    free(b);
    return r;
}

int system(const char *cmd) {
    if (!cmd) return 1; /* a shell is available */
    struct sigaction ign = {0}, oint, oquit;
    sigset_t chld, omask;
    ign.sa_handler = SIG_IGN;
    sigemptyset(&ign.sa_mask);
    sigaction(SIGINT, &ign, &oint);
    sigaction(SIGQUIT, &ign, &oquit);
    sigemptyset(&chld);
    sigaddset(&chld, SIGCHLD);
    sigprocmask(SIG_BLOCK, &chld, &omask);
    /* The child gets the caller's dispositions and mask back. */
    posix_spawnattr_t at;
    posix_spawnattr_init(&at);
    sigset_t def;
    sigemptyset(&def);
    if (oint.sa_handler != SIG_IGN) sigaddset(&def, SIGINT);
    if (oquit.sa_handler != SIG_IGN) sigaddset(&def, SIGQUIT);
    posix_spawnattr_setsigdefault(&at, &def);
    posix_spawnattr_setsigmask(&at, &omask);
    posix_spawnattr_setflags(&at, POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK);
    pid_t pid;
    int status = -1;
    int r = spawn_shell(&pid, cmd, NULL, &at);
    posix_spawnattr_destroy(&at);
    if (r == 0) {
        while (waitpid(pid, &status, 0) < 0) {
            if (errno != EINTR) { status = -1; break; }
        }
    } else {
        status = 127 << 8; /* as glibc: the shell could not run */
    }
    sigaction(SIGINT, &oint, NULL);
    sigaction(SIGQUIT, &oquit, NULL);
    sigprocmask(SIG_SETMASK, &omask, NULL);
    return status;
}

/* popen()'d streams and their shells, for pclose. */
struct popen_ent { FILE *f; pid_t pid; struct popen_ent *next; };
static struct popen_ent *popen_list;
static pthread_mutex_t popen_mu = PTHREAD_MUTEX_INITIALIZER;

FILE *popen(const char *cmd, const char *mode) {
    if (!cmd || !mode || (mode[0] != 'r' && mode[0] != 'w')) { errno = EINVAL; return NULL; }
    int reading = mode[0] == 'r';
    int cloexec = strchr(mode, 'e') != NULL;
    int fds[2];
    if (pipe2(fds, O_CLOEXEC) != 0) return NULL;
    int mine = reading ? fds[0] : fds[1], theirs = reading ? fds[1] : fds[0];
    int target = reading ? STDOUT_FILENO : STDIN_FILENO;
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, theirs, target);
    /* POSIX: streams of earlier popen() calls are closed in the child. */
    pthread_mutex_lock(&popen_mu);
    for (struct popen_ent *e = popen_list; e; e = e->next) {
        int fd = fileno(e->f);
        if (fd >= 0 && fd != target) posix_spawn_file_actions_addclose(&fa, fd);
    }
    pid_t pid;
    int r = spawn_shell(&pid, cmd, &fa, NULL);
    posix_spawn_file_actions_destroy(&fa);
    close(theirs);
    if (r != 0) {
        pthread_mutex_unlock(&popen_mu);
        close(mine);
        errno = r;
        return NULL;
    }
    if (!cloexec) fcntl(mine, F_SETFD, 0);
    FILE *f = fdopen(mine, reading ? "r" : "w");
    struct popen_ent *e = f ? malloc(sizeof *e) : NULL;
    if (!e) {
        pthread_mutex_unlock(&popen_mu);
        if (f) fclose(f); else close(mine);
        waitpid(pid, NULL, 0);
        errno = ENOMEM;
        return NULL;
    }
    e->f = f;
    e->pid = pid;
    e->next = popen_list;
    popen_list = e;
    pthread_mutex_unlock(&popen_mu);
    return f;
}

int pclose(FILE *f) {
    pthread_mutex_lock(&popen_mu);
    struct popen_ent **pp = &popen_list, *e = NULL;
    for (; *pp; pp = &(*pp)->next)
        if ((*pp)->f == f) { e = *pp; *pp = e->next; break; }
    pthread_mutex_unlock(&popen_mu);
    if (!e) {
        /* Not ours (opened before this shim was loaded): glibc's own. */
        static int (*real)(FILE *);
        if (!real) real = (int (*)(FILE *))dlsym(RTLD_NEXT, "pclose");
        return real(f);
    }
    pid_t pid = e->pid;
    free(e);
    fclose(f);
    int status;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) return -1;
    }
    return status;
}

static int spawn_common(spawn_fn real, pid_t *pid, const char *path,
                        const posix_spawn_file_actions_t *fa, const posix_spawnattr_t *at,
                        char *const argv[], char *const envp[]) {
    char copy[PATH_MAX];
    if (bundled_copy(path, copy, sizeof copy) && !is_elf(copy)) {
        static spawn_fn plain0;
        if (!plain0) plain0 = (spawn_fn)dlsym(RTLD_NEXT, "posix_spawn");
        return plain0(pid, copy, fa, at, argv, envp); /* a script */
    }
    if (bundled_copy(path, copy, sizeof copy)) {
        char **a = loader_argv(copy, argv);
        if (a) {
            static spawn_fn plain;
            if (!plain) plain = (spawn_fn)dlsym(RTLD_NEXT, "posix_spawn");
            int r = plain(pid, a[0], fa, at, a, envp);
            free(a);
            return r;
        }
    }
    char **sa = shell_argv(path, argv);
    if (sa) {
        int r = real(pid, path, fa, at, sa, envp);
        free(sa[2]);
        free(sa);
        return r;
    }
    if (path && strchr(path, '/') && !in_bundle(path)) {
        char **he = host_env(envp);
        if (he) return real(pid, path, fa, at, argv, he);
    }
    return real(pid, path, fa, at, argv, envp);
}

int posix_spawn(pid_t *pid, const char *path, const posix_spawn_file_actions_t *fa,
                const posix_spawnattr_t *at, char *const argv[], char *const envp[]) {
    static spawn_fn real;
    if (!real) real = (spawn_fn)dlsym(RTLD_NEXT, "posix_spawn");
    return spawn_common(real, pid, path, fa, at, argv, envp);
}

int posix_spawnp(pid_t *pid, const char *file, const posix_spawn_file_actions_t *fa,
                 const posix_spawnattr_t *at, char *const argv[], char *const envp[]) {
    static spawn_fn realp, real;
    if (!realp) realp = (spawn_fn)dlsym(RTLD_NEXT, "posix_spawnp");
    if (!real) real = (spawn_fn)dlsym(RTLD_NEXT, "posix_spawn");
    if (file && !strchr(file, '/')) {
        /* Resolve it here, so the decision above sees the real path. */
        const char *path = env_get(envp, "PATH");
        if (!path) path = "/usr/local/bin:/usr/bin:/bin";
        char buf[PATH_MAX];
        while (*path) {
            const char *c = strchr(path, ':');
            size_t l = c ? (size_t)(c - path) : strlen(path);
            if (l + strlen(file) + 2 < sizeof buf) {
                memcpy(buf, path, l);
                buf[l] = '/';
                strcpy(buf + l + 1, file);
                if (access(buf, X_OK) == 0)
                    return spawn_common(real, pid, buf, fa, at, argv, envp);
            }
            if (!c) break;
            path = c + 1;
        }
    }
    return spawn_common(realp, pid, file, fa, at, argv, envp);
}

void *dlopen(const char *file, int flags) {
    static dlopen_fn real;
    if (!real) real = (dlopen_fn)dlsym(RTLD_NEXT, "dlopen");
    char copy[PATH_MAX];
    if (bundled_copy(file, copy, sizeof copy)) return real(copy, flags);
    return real(file, flags);
}

char *bindtextdomain(const char *domain, const char *dir) {
    static btd_fn real;
    if (!real) real = (btd_fn)dlsym(RTLD_NEXT, "bindtextdomain");
    const char *root = getenv("MHVD_ROOT");
    char buf[PATH_MAX];
    if (root && dir && starts_with(dir, "/usr/share/locale") &&
        snprintf(buf, sizeof buf, "%s%s", root, dir) < (int)sizeof buf)
        return real(domain, buf);
    return real(domain, dir);
}

/* ---- reads and existence checks of compiled-in paths ---- */

static int read_only(int flags) {
    return (flags & O_ACCMODE) == O_RDONLY && !(flags & (O_CREAT | O_TMPFILE));
}

#define MODE_ARG(flags)                                                  \
    mode_t mode = 0;                                                     \
    if ((flags) & (O_CREAT | O_TMPFILE)) {                               \
        va_list ap;                                                      \
        va_start(ap, flags);                                             \
        mode = va_arg(ap, mode_t);                                       \
        va_end(ap);                                                      \
    }

#define RO(path, flags) (read_only(flags) ? bundled_any(path, b, sizeof b) : (path))

int open(const char *path, int flags, ...) {
    MODE_ARG(flags);
    char b[PATH_MAX];
    return real_open()(RO(path, flags), flags, mode);
}
int open64(const char *path, int flags, ...) {
    MODE_ARG(flags);
    char b[PATH_MAX];
    return real_open64()(RO(path, flags), flags, mode);
}
int openat(int dirfd, const char *path, int flags, ...) {
    MODE_ARG(flags);
    char b[PATH_MAX];
    return real_openat()(dirfd, RO(path, flags), flags, mode);
}
int openat64(int dirfd, const char *path, int flags, ...) {
    MODE_ARG(flags);
    char b[PATH_MAX];
    return real_openat64()(dirfd, RO(path, flags), flags, mode);
}
/* _FORTIFY_SOURCE builds call these for opens without a mode. */
int __open_2(const char *path, int flags) {
    char b[PATH_MAX];
    return real___open_2()(RO(path, flags), flags);
}
int __open64_2(const char *path, int flags) {
    char b[PATH_MAX];
    return real___open64_2()(RO(path, flags), flags);
}
int __openat_2(int dirfd, const char *path, int flags) {
    char b[PATH_MAX];
    return real___openat_2()(dirfd, RO(path, flags), flags);
}
int __openat64_2(int dirfd, const char *path, int flags) {
    char b[PATH_MAX];
    return real___openat64_2()(dirfd, RO(path, flags), flags);
}

static int fopen_read_only(const char *mode) {
    return mode && mode[0] == 'r' && !strchr(mode, '+');
}
FILE *fopen(const char *path, const char *mode) {
    char b[PATH_MAX];
    return real_fopen()(fopen_read_only(mode) ? bundled_any(path, b, sizeof b) : path, mode);
}
FILE *fopen64(const char *path, const char *mode) {
    char b[PATH_MAX];
    return real_fopen64()(fopen_read_only(mode) ? bundled_any(path, b, sizeof b) : path, mode);
}

int stat(const char *path, struct stat *st) {
    char b[PATH_MAX];
    return real_stat()(bundled_any(path, b, sizeof b), st);
}
int lstat(const char *path, struct stat *st) {
    char b[PATH_MAX];
    return real_lstat()(bundled_any(path, b, sizeof b), st);
}
int stat64(const char *path, struct stat64 *st) {
    char b[PATH_MAX];
    return real_stat64()(bundled_any(path, b, sizeof b), st);
}
int lstat64(const char *path, struct stat64 *st) {
    char b[PATH_MAX];
    return real_lstat64()(bundled_any(path, b, sizeof b), st);
}
int fstatat(int dirfd, const char *path, struct stat *st, int flags) {
    char b[PATH_MAX];
    return real_fstatat()(dirfd, bundled_any(path, b, sizeof b), st, flags);
}
int fstatat64(int dirfd, const char *path, struct stat64 *st, int flags) {
    char b[PATH_MAX];
    return real_fstatat64()(dirfd, bundled_any(path, b, sizeof b), st, flags);
}
int statx(int dirfd, const char *path, int flags, unsigned int mask, struct statx *st) {
    char b[PATH_MAX];
    return real_statx()(dirfd, bundled_any(path, b, sizeof b), flags, mask, st);
}
int access(const char *path, int how) {
    char b[PATH_MAX];
    return real_access()(bundled_any(path, b, sizeof b), how);
}
int faccessat(int dirfd, const char *path, int how, int flags) {
    char b[PATH_MAX];
    return real_faccessat()(dirfd, bundled_any(path, b, sizeof b), how, flags);
}
DIR *opendir(const char *path) {
    char b[PATH_MAX];
    return real_opendir()(bundled_any(path, b, sizeof b));
}
