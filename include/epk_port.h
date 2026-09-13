/*
 * epk_port.h — the ONLY layer a hobby OS must implement to run epkg-tools.
 *
 * epkg-tools core is freestanding C99: it never touches hardware, syscalls
 * or libc directly. Everything goes through the ~24 functions below.
 * A POSIX reference implementation (epk_port_posix.c) is included and works
 * on Linux / macOS / BSD / Cygwin out of the box.
 *
 * See PORTING.md for a step-by-step integration guide.
 */
#ifndef EPK_PORT_H
#define EPK_PORT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* Opaque handles                                                      */
/* ------------------------------------------------------------------ */
typedef void *epk_file;     /* open file, NULL on error                */
typedef void *epk_dir;      /* open directory, NULL on error           */
typedef void *epk_sock;     /* TCP socket, NULL on error               */

/* open() mode bits for epk_open() */
#define EPK_O_RDONLY  1u
#define EPK_O_WRONLY  2u
#define EPK_O_RDWR    4u
#define EPK_O_CREATE  8u   /* create if missing                        */
#define EPK_O_TRUNC  16u   /* truncate to zero on open                 */

/* whence for epk_seek() */
#define EPK_SEEK_SET 0
#define EPK_SEEK_CUR 1
#define EPK_SEEK_END 2

/* ------------------------------------------------------------------ */
/* Files & directories                                                 */
/* ------------------------------------------------------------------ */

/* Open a file. Returns NULL on failure. */
epk_file epk_open(const char *path, unsigned mode);

/* Close a file. Returns 0 on success, -1 on error. Closing NULL is OK (0). */
int epk_close(epk_file f);

/* Read up to len bytes. Returns bytes read (>0), 0 at EOF, -1 on error. */
int epk_read(epk_file f, void *buf, unsigned len);

/* Write len bytes. Returns bytes written (>0) or -1 on error.
 * Partial writes are allowed; the core loops. */
int epk_write(epk_file f, const void *buf, unsigned len);

/* Seek. Returns new offset (>=0) or -1 on error. */
long epk_seek(epk_file f, long offset, int whence);

/* Delete a file. 0 on success, -1 on error (also OK to fail if missing). */
int epk_unlink(const char *path);

/* Remove an empty directory. 0 on success, -1 on error. */
int epk_rmdir(const char *path);

/* Directory test (uses stat where available; a port may fall back to
 * "open fails => dir"). Needed only by build tools, not by epkg itself. */
int epk_is_dir(const char *path);

/* Rename/move a file (also used for atomic DB updates). 0 / -1. */
int epk_rename(const char *oldpath, const char *newpath);

/* Create one directory level. 0 on success OR if it already exists. */
int epk_mkdir(const char *path);

/* Create a symbolic link "linkpath" pointing to "target" (raw string,
 * no interpretation). 0 on success, -1 on error.
 * OPTIONAL capability: a hobby OS without symlink support may always
 * return -1; epkg then degrades gracefully according to the
 * "symlinks" policy in epkg.conf (see README.md). */
int epk_symlink(const char *target, const char *linkpath);

/* Open a directory for listing. NULL on failure. */
epk_dir epk_opendir(const char *path);

/* Get next entry name (no path, just the component).
 * Returns 1 on success, 0 when there are no more entries. */
int epk_readdir(epk_dir d, char *name, unsigned cap);

void epk_closedir(epk_dir d);

/* ------------------------------------------------------------------ */
/* Memory                                                              */
/* ------------------------------------------------------------------ */
void *epk_malloc(unsigned n);            /* NULL if out of memory       */
void  epk_free(void *p);                 /* free(NULL) is OK            */
void *epk_realloc(void *p, unsigned n);  /* like realloc(3)             */

/* ------------------------------------------------------------------ */
/* System                                                              */
/* ------------------------------------------------------------------ */

/* Write a NUL-terminated string to the log/stderr stream. No newline. */
void epk_print(const char *s);

/* Terminate the process. */
void epk_exit(int code);

/* Monotonic milliseconds (any epoch) — used for network timeouts.
 * Return 0 if not available. */
uint32_t epk_ticks(void);

/* Wall-clock UNIX time in seconds. Return 0 if clock not set. */
uint32_t epk_time(void);

/* 32 bits of entropy for TLS nonces. May be weak; TLS mixes it. */
uint32_t epk_seed(void);

/* Optional: environment lookup. A hobby OS may always return NULL. */
const char *epk_getenv(const char *name);

/* ------------------------------------------------------------------ */
/* Network (TCP only; TLS is implemented inside epkg-tools core)       */
/* ------------------------------------------------------------------ */

/* Open a TCP connection to host:port. "host" may be a DNS name or an
 * IPv4/IPv6 literal; "port" is a decimal service string ("443").
 * timeout_ms limits the connect attempt. NULL on failure. */
epk_sock epk_tcp_connect(const char *host, const char *port,
                         uint32_t timeout_ms);

/* Send len bytes. Returns bytes sent (>0) or -1 on error. */
int epk_tcp_send(epk_sock s, const void *buf, int len);

/* Receive up to len bytes. Returns bytes read (>0), 0 on clean EOF,
 * -1 on error or timeout. A recommended receive timeout of ~30 s
 * is fine (set inside the port, see epk_port_posix.c). */
int epk_tcp_recv(epk_sock s, void *buf, int len);

void epk_tcp_close(epk_sock s);

#ifdef __cplusplus
}
#endif
#endif /* EPK_PORT_H */
