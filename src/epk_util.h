/*
 * epk_util.h — small shared helpers: dynamic buffers, string utils,
 * base64, hex. Freestanding C99, builds on the port layer.
 */
#ifndef EPK_UTIL_H
#define EPK_UTIL_H

#include <stdint.h>
#include "epk_libc.h"

/* ---------------- dynamic byte buffer ---------------- */
typedef struct {
    uint8_t *p;
    unsigned len, cap;
    int      oom;               /* set on allocation failure   */
} epk_buf;

void  epk_buf_init(epk_buf *b);
int   epk_buf_reserve(epk_buf *b, unsigned need);
int   epk_buf_append(epk_buf *b, const void *data, unsigned n);
int   epk_buf_appendc(epk_buf *b, uint8_t c);
int   epk_buf_appends(epk_buf *b, const char *s);
void  epk_buf_free(epk_buf *b);
/* reset length, keep capacity */
void  epk_buf_clear(epk_buf *b);

/* ---------------- string utils ---------------- */
/* copy with guaranteed NUL (like strlcpy); returns src length */
size_t epk_strlcpy(char *dst, const char *src, size_t cap);
/* append with guaranteed NUL (like strlcat) */
size_t epk_strlcat(char *dst, const char *src, size_t cap);
/* case-insensitive compare (ASCII) */
int    epk_strcasecmp(const char *a, const char *b);
int    epk_strncasecmp(const char *a, const char *b, size_t n);
/* safe parse helpers */
int    epk_parse_uint(const char *s, unsigned long *out);
int    epk_hexval(int c);
int    epk_has_prefix(const char *s, const char *prefix);

/* ---------------- hex ---------------- */
/* write n bytes as lowercase hex into out (needs 2n+1 bytes) */
void   epk_hex(const uint8_t *data, unsigned n, char *out);
/* parse hex string into out; returns 0 on success */
int    epk_unhex(const char *hex, uint8_t *out, unsigned cap);

/* ---------------- base64 (RFC 4648, no newlines) ---------------- */
int    epk_base64_decode(const char *in, unsigned inlen,
                         uint8_t *out, unsigned cap, unsigned *outlen);
/* encode with '=' padding; out needs 4*((n+2)/3)+1 bytes.
 * Returns number of chars written (without NUL), -1 on cap overflow. */
int    epk_base64_encode(const uint8_t *in, unsigned n,
                         char *out, unsigned cap);

/* ---------------- file helper on top of the port layer ---------------- */
/* read whole file into a malloc'd buffer (caller frees). NULL on error. */
uint8_t *epk_read_file(const char *path, unsigned *outlen);
/* write whole buffer to path (mode RDWR|CREATE|TRUNC). 0 on success */
int      epk_write_file(const char *path, const void *data, unsigned n);
/* mkdir -p equivalent, built from epk_mkdir */
int      epk_mkdir_p(const char *path);

#endif /* EPK_UTIL_H */
