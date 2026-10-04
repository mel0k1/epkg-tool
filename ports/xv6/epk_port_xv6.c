/* epk_port_xv6.c — epkg port layer for xv6-riscv.
 *
 * Maps the port contract (include/epk_port.h) onto xv6 user syscalls:
 *   - files: open/close/read/write/lseek/unlink/mkdir (+fstat for is_dir)
 *   - rename: xv6 has no rename syscall, emulate with copy+unlink
 *   - dirs: read() on an opened directory returns 16-byte dirents
 *   - symlink: unsupported, always -1 (epkg "symlinks = deny" policy)
 *   - network: netconnect/netread/netwrite/netclose/netresolve (kernel net.c)
 *   - big stack: static 256 KiB buffer + sp-switch trampoline (epk_bigstack_xv6.S)
 */
#include <stddef.h>
#include "kernel/types.h"
#include "user.h"
#include "../../include/epk_port.h"

/* ---- xv6 constants (duplicated on purpose, no kernel headers needed) ---- */
#define XV6_O_RDONLY 0x000
#define XV6_O_WRONLY 0x001
#define XV6_O_RDWR   0x002
#define XV6_O_CREATE 0x200
#define XV6_O_TRUNC  0x400

#define XV6_T_DIR 1

struct xv6_dirent {
  unsigned short inum;
  char name[14];
};

struct stat {
  int dev;
  uint ino;
  short type;
  short nlink;
  uint64 size;
};

/* ------------------------------------------------------------------ */
/* Files                                                               */
/* ------------------------------------------------------------------ */

static int
xv6_flags(unsigned m)
{
  int f;
  if (m & EPK_O_RDWR) f = XV6_O_RDWR;
  else if (m & EPK_O_WRONLY) f = XV6_O_WRONLY;
  else f = XV6_O_RDONLY;
  if (m & EPK_O_CREATE) f |= XV6_O_CREATE;
  if (m & EPK_O_TRUNC) f |= XV6_O_TRUNC;
  return f;
}

epk_file
epk_open(const char *path, unsigned mode)
{
  int fd = open(path, xv6_flags(mode));
  if (fd < 0) return 0;
  return (epk_file)(long)(fd + 1);
}

int
epk_close(epk_file f)
{
  if (!f) return 0;
  return close((int)(long)f - 1);
}

int
epk_read(epk_file f, void *buf, unsigned len)
{
  return read((int)(long)f - 1, buf, (int)len);
}

int
epk_write(epk_file f, const void *buf, unsigned len)
{
  return write((int)(long)f - 1, buf, (int)len);
}

long
epk_seek(epk_file f, long offset, int whence)
{
  return (long)lseek((int)(long)f - 1, (int)offset, whence);
}

int
epk_unlink(const char *path)
{
  return unlink(path);
}

int
epk_rmdir(const char *path)
{
  return unlink(path);          /* xv6 unlink removes empty dirs too */
}

int
epk_rename(const char *oldpath, const char *newpath)
{
  /* copy+unlink: xv6 has no rename(2) */
  epk_file in, out;
  char buf[1024];
  long n;

  in = epk_open(oldpath, EPK_O_RDONLY);
  if (!in) return -1;
  out = epk_open(newpath, EPK_O_WRONLY | EPK_O_CREATE | EPK_O_TRUNC);
  if (!out) { epk_close(in); return -1; }
  while ((n = epk_read(in, buf, sizeof(buf))) > 0)
    if (epk_write(out, buf, (unsigned)n) != n) { n = -1; break; }
  epk_close(in);
  epk_close(out);
  if (n < 0) { epk_unlink(newpath); return -1; }
  epk_unlink(oldpath);
  return 0;
}

int
epk_mkdir(const char *path)
{
  int fd;
  if (mkdir(path) == 0) return 0;
  /* already exists? */
  fd = open(path, XV6_O_RDONLY);
  if (fd >= 0) { close(fd); return 0; }
  return -1;
}

int
epk_symlink(const char *target, const char *linkpath)
{
  (void)target; (void)linkpath;
  return -1;                    /* no symlinks on xv6 */
}

int
epk_is_dir(const char *path)
{
  int fd = open(path, XV6_O_RDONLY);
  struct stat st;
  if (fd < 0) return 0;
  if (fstat(fd, &st) < 0) { close(fd); return 0; }
  close(fd);
  return st.type == XV6_T_DIR;
}

/* ------------------------------------------------------------------ */
/* Directories                                                         */
/* ------------------------------------------------------------------ */

epk_dir
epk_opendir(const char *path)
{
  int fd = open(path, XV6_O_RDONLY);
  struct stat st;
  if (fd < 0) return 0;
  if (fstat(fd, &st) < 0 || st.type != XV6_T_DIR) {
    close(fd);
    return 0;
  }
  return (epk_dir)(long)(fd + 1);
}

int
epk_readdir(epk_dir d, char *name, unsigned cap)
{
  int fd = (int)(long)d - 1;
  struct xv6_dirent de;

  if (cap < 15) return 0;
  for (;;) {
    if (read(fd, &de, sizeof(de)) != (int)sizeof(de))
      return 0;                             /* end of directory */
    if (de.inum == 0)
      continue;                             /* free slot */
    {
      int i;
      for (i = 0; i < 13 && de.name[i]; i++)
        name[i] = de.name[i];
      name[i] = 0;
    }
    return 1;
  }
}

void
epk_closedir(epk_dir d)
{
  if (d) close((int)(long)d - 1);
}

/* ------------------------------------------------------------------ */
/* Memory: small first-fit allocator over sbrk                         */
/* ------------------------------------------------------------------ */

typedef struct epk_blk {
  unsigned sz;                  /* payload size */
  struct epk_blk *next;         /* free list link (free blocks only) */
} epk_blk;

static epk_blk *epk_freelist;

void *
epk_malloc(unsigned n)
{
  if (n == 0) n = 1;
  n = (n + 15u) & ~15u;

  {
    epk_blk **pp = &epk_freelist;
    while (*pp) {
      if ((*pp)->sz >= n) {
        epk_blk *b = *pp;
        if (b->sz >= n + sizeof(epk_blk) + 16u) {
          /* split: tail stays free, head is detached and returned */
          epk_blk *rest = (epk_blk *)((char *)b + sizeof(epk_blk) + n);
          rest->sz = b->sz - n - sizeof(epk_blk);
          rest->next = b->next;
          *pp = rest;
          b->sz = n;
        } else {
          *pp = b->next;        /* detach: block consumed in place */
        }
        return (char *)b + sizeof(epk_blk);
      }
      pp = &(*pp)->next;
    }
  }

  {
    unsigned want = n + sizeof(epk_blk);
    char *p = sbrk((int)want);
    epk_blk *b;
    if (p == (char *)-1) return 0;
    b = (epk_blk *)p;
    b->sz = n;
    b->next = 0;
    return (char *)b + sizeof(epk_blk);
  }
}

void
epk_free(void *p)
{
  epk_blk *b, **pp;
  if (!p) return;
  b = (epk_blk *)((char *)p - sizeof(epk_blk));

  /* address-ordered insert, then coalesce with neighbours */
  for (pp = &epk_freelist; *pp; pp = &(*pp)->next)
    if ((char *)*pp > (char *)b) break;
  b->next = *pp;
  *pp = b;
  if ((char *)b + b->sz + sizeof(epk_blk) == (char *)b->next) {
    b->sz += b->next->sz + sizeof(epk_blk);
    b->next = b->next->next;
  }
  for (pp = &epk_freelist; *pp && *pp != b; pp = &(*pp)->next) {
    epk_blk *pr = *pp;
    if ((char *)pr + pr->sz + sizeof(epk_blk) == (char *)b) {
      pr->sz += b->sz + sizeof(epk_blk);
      pr->next = b->next;
      break;
    }
  }
}

void *
epk_realloc(void *p, unsigned n)
{
  epk_blk *b;
  void *np;
  char *d;
  const char *s;
  unsigned i;

  if (!p) return epk_malloc(n);
  if (n == 0) { epk_free(p); return 0; }
  b = (epk_blk *)((char *)p - sizeof(epk_blk));
  if (b->sz >= n) return p;
  np = epk_malloc(n);
  if (!np) return 0;
  d = (char *)np;
  s = (const char *)p;
  for (i = 0; i < b->sz; i++) d[i] = s[i];
  epk_free(p);
  return np;
}

/* ------------------------------------------------------------------ */
/* System                                                              */
/* ------------------------------------------------------------------ */

void
epk_print(const char *s)
{
  unsigned n = 0;
  while (s[n]) n++;
  write(2, s, (int)n);
}

void
epk_exit(int code)
{
  exit(code);
  for (;;) ;
}

uint32_t
epk_ticks(void)
{
  return (uint32_t)uptime() * 100u;     /* xv6 tick = 100ms */
}

uint32_t
epk_time(void)
{
  return 0;                             /* no wall clock on xv6 */
}

uint32_t
epk_seed(void)
{
  static uint32_t mix;
  mix ^= (uint32_t)uptime() * 0x9E3779B9u;
  mix ^= (uint32_t)(long)&mix;
  mix ^= mix << 13;
  mix ^= mix >> 17;
  return mix;
}

const char *
epk_getenv(const char *name)
{
  (void)name;
  return 0;
}

int
epk_bigstack_run(int (*fn)(void *), void *arg)
{
  extern int epk_bigstack_trampoline(int (*fn)(void *), void *arg,
                                     char *sp_top);
  static char epk_bigstack[EPK_STACK_MIN] __attribute__((aligned(16)));
  return epk_bigstack_trampoline(fn, arg,
                                 epk_bigstack + sizeof(epk_bigstack));
}

/* ------------------------------------------------------------------ */
/* Network                                                             */
/* ------------------------------------------------------------------ */

/* dotted-quad parser: "10.0.2.2" -> wire-order u32; returns octets parsed */
static int
sscan4(const char *s, unsigned out[4])
{
  int got = 0;
  while (*s && got < 4) {
    unsigned v = 0;
    int digits = 0;
    while (*s >= '0' && *s <= '9') {
      v = v * 10 + (unsigned)(*s - '0');
      s++; digits++;
      if (digits > 3) return got;
    }
    if (!digits) return got;
    if (v > 255) return got;
    out[got++] = v;
    if (*s == '.') s++;
    else break;
  }
  return got;
}

epk_sock
epk_tcp_connect(const char *host, const char *port, uint32_t timeout_ms)
{
  unsigned oct[4];
  uint32_t ip = 0;
  int fd, p = 0, i = 0, n;

  (void)timeout_ms;                     /* kernel uses a fixed 15s */
  while (port[i] >= '0' && port[i] <= '9')
    p = p * 10 + (port[i++] - '0');
  if (p <= 0 || port[i]) return 0;      /* fully numeric port required */

  n = sscan4(host, oct);
  if (n == 4)
    ip = ((oct[0] & 0xff) << 24) | ((oct[1] & 0xff) << 16) |
         ((oct[2] & 0xff) << 8) | (oct[3] & 0xff);
  if (!ip) {
    ip = (uint32_t)netresolve(host);
    if (!ip) return 0;
  }
  fd = netconnect((int)ip, p);
  if (fd < 0) return 0;
  return (epk_sock)(long)(fd + 1);
}

int
epk_tcp_send(epk_sock s, const void *buf, int len)
{
  return netwrite((int)(long)s - 1, buf, len);
}

int
epk_tcp_recv(epk_sock s, void *buf, int len)
{
  return netread((int)(long)s - 1, buf, len);
}

void
epk_tcp_close(epk_sock s)
{
  if (s) netclose((int)(long)s - 1);
}

/* ------------------------------------------------------------------ */
/* libc bits xv6's ulib lacks                                          */
/* ------------------------------------------------------------------ */

int
strncmp(const char *a, const char *b, size_t n)
{
  while (n && *a && *a == *b) { a++; b++; n--; }
  if (!n) return 0;
  return (unsigned char)*a - (unsigned char)*b;
}

char *
strrchr(const char *s, int c)
{
  const char *last = 0;
  for (; *s; s++)
    if (*s == (char)c) last = s;
  if ((char)c == 0) return (char *)s;
  return (char *)last;
}

char *
strstr(const char *h, const char *n)
{
  if (!*n) return (char *)h;
  for (; *h; h++) {
    const char *a = h, *b = n;
    while (*a && *b && *a == *b) { a++; b++; }
    if (!*b) return (char *)h;
  }
  return 0;
}

void *
memchr(const void *s, int c, size_t n)
{
  const unsigned char *p = (const unsigned char *)s;
  while (n--) {
    if (*p == (unsigned char)c) return (void *)p;
    p++;
  }
  return 0;
}
