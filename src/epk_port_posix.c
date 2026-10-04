/*
 * epk_port_posix.c — reference POSIX backend of the epkg port layer.
 * Works on Linux / macOS / BSD / Cygwin. A hobby OS should provide its
 * own implementation of the same 24 functions (see PORTING.md).
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <time.h>
#include <errno.h>

#include "../include/epk_port.h"
#include "epk_libc.h"

/* ---------------- files ---------------- */
epk_file epk_open(const char *path, unsigned mode)
{
    int flags = 0, acc = mode & 3u;
    int fd;
    if (acc == EPK_O_RDONLY) flags = O_RDONLY;
    else if (acc == EPK_O_WRONLY) flags = O_WRONLY;
    else flags = O_RDWR;
    if (mode & EPK_O_CREATE) flags |= O_CREAT;
    if (mode & EPK_O_TRUNC)  flags |= O_TRUNC;
    fd = open(path, flags, 0644);
    if (fd < 0) return NULL;
    return (epk_file)(intptr_t)fd;
}

int epk_close(epk_file f)
{
    if (!f) return 0;
    return close((int)(intptr_t)f);
}

int epk_read(epk_file f, void *buf, unsigned len)
{
    ssize_t r = read((int)(intptr_t)f, buf, len);
    return r < 0 ? -1 : (int)r;
}

int epk_write(epk_file f, const void *buf, unsigned len)
{
    ssize_t r = write((int)(intptr_t)f, buf, len);
    return r < 0 ? -1 : (int)r;
}

long epk_seek(epk_file f, long offset, int whence)
{
    return lseek((int)(intptr_t)f, offset, whence);
}

int epk_unlink(const char *path) { return unlink(path); }
int epk_rmdir(const char *path) { return rmdir(path); }
int epk_is_dir(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}
int epk_rename(const char *a, const char *b) { return rename(a, b); }
int epk_mkdir(const char *path) { return mkdir(path, 0755); }
int epk_symlink(const char *target, const char *linkpath)
{
    return symlink(target, linkpath);
}

/* ---------------- dirs ---------------- */
epk_dir epk_opendir(const char *path) { return (epk_dir)opendir(path); }

int epk_readdir(epk_dir d, char *name, unsigned cap)
{
    DIR *dp = (DIR *)d;
    struct dirent *e = readdir(dp);
    if (!e) return 0;
    if (strlen(e->d_name) >= cap) return 0;
    strcpy(name, e->d_name);
    return 1;
}

void epk_closedir(epk_dir d) { if (d) closedir((DIR *)d); }

/* ---------------- memory ---------------- */
void *epk_malloc(unsigned n) { return malloc(n); }
void  epk_free(void *p) { free(p); }
void *epk_realloc(void *p, unsigned n) { return realloc(p, n); }

/* ---------------- system ---------------- */
static void vprint(const char *s)
{
    fputs(s, stderr);
    fflush(stderr);
}

void epk_print(const char *s) { vprint(s); }

void epk_exit(int code)
{
    exit(code);
}

uint32_t epk_ticks(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (uint32_t)(ts.tv_sec * 1000u + ts.tv_nsec / 1000000u);
}

uint32_t epk_time(void) { return (uint32_t)time(NULL); }

uint32_t epk_seed(void)
{
    uint32_t v = 0;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        if (read(fd, &v, sizeof(v)) != sizeof(v)) v = 0;
        close(fd);
    }
    if (!v) {
        v ^= (uint32_t)getpid() * 2654435761u;
        v ^= (uint32_t)time(NULL) * 40503u;
        v ^= (uint32_t)(uintptr_t)&fd;
    }
    return v;
}

const char *epk_getenv(const char *name) { return getenv(name); }

/* ---------------- big stack ---------------- */

#include <pthread.h>

typedef struct {
    int (*fn)(void *);
    void *arg;
    int   rc;
} bigstack_job;

static void *bigstack_trampoline(void *p)
{
    bigstack_job *j = (bigstack_job *)p;
    j->rc = j->fn(j->arg);
    return 0;
}

int epk_bigstack_run(int (*fn)(void *), void *arg)
{
    pthread_attr_t a;
    pthread_t t;
    bigstack_job j;
    int r;

    j.fn = fn; j.arg = arg; j.rc = -1;
    if (pthread_attr_init(&a) != 0) return fn(arg);
    if (pthread_attr_setstacksize(&a, EPK_STACK_MIN) != 0) {
        pthread_attr_destroy(&a);
        return fn(arg);
    }
    r = pthread_create(&t, &a, bigstack_trampoline, &j);
    pthread_attr_destroy(&a);
    if (r != 0) return fn(arg);      /* fallback: caller's stack */
    pthread_join(t, 0);
    return j.rc;
}

/* ---------------- network ---------------- */
epk_sock epk_tcp_connect(const char *host, const char *port,
                         uint32_t timeout_ms)
{
    struct addrinfo hints, *res = NULL, *ai;
    int fd = -1, err;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    err = getaddrinfo(host, port, &hints, &res);
    if (err != 0) return NULL;

    for (ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;

        /* connect timeout via non-blocking + select */
        if (timeout_ms) {
            int flags = fcntl(fd, F_GETFL, 0);
            fd_set wset;
            struct timeval tv;
            int r, opt = 0;
            socklen_t ol = sizeof(opt);

            fcntl(fd, F_SETFL, flags | O_NONBLOCK);
            r = connect(fd, ai->ai_addr, ai->ai_addrlen);
            if (r != 0 && errno == EINPROGRESS) {
                FD_ZERO(&wset);
                FD_SET(fd, &wset);
                tv.tv_sec = timeout_ms / 1000u;
                tv.tv_usec = (timeout_ms % 1000u) * 1000u;
                if (select(fd + 1, NULL, &wset, NULL, &tv) <= 0 ||
                    getsockopt(fd, SOL_SOCKET, SO_ERROR, &opt, &ol) != 0 ||
                    opt != 0) {
                    close(fd);
                    fd = -1;
                    continue;
                }
            } else if (r != 0) {
                close(fd);
                fd = -1;
                continue;
            }
            fcntl(fd, F_SETFL, flags);
        } else {
            if (connect(fd, ai->ai_addr, ai->ai_addrlen) != 0) {
                close(fd);
                fd = -1;
                continue;
            }
        }

        /* 30 s receive timeout + TCP_NODELAY */
        {
            struct timeval tv;
            int one = 1;
            tv.tv_sec = 30;
            tv.tv_usec = 0;
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        }
        break;
    }
    freeaddrinfo(res);

    return fd < 0 ? NULL : (epk_sock)(intptr_t)fd;
}

int epk_tcp_send(epk_sock s, const void *buf, int len)
{
    ssize_t r = send((int)(intptr_t)s, buf, (size_t)len, MSG_NOSIGNAL);
    return r < 0 ? -1 : (int)r;
}

int epk_tcp_recv(epk_sock s, void *buf, int len)
{
    ssize_t r = recv((int)(intptr_t)s, buf, (size_t)len, 0);
    return r < 0 ? -1 : (int)r;
}

void epk_tcp_close(epk_sock s)
{
    if (s) close((int)(intptr_t)s);
}
