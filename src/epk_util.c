/* epk_util.c — implementation of the shared helpers. */
#include "epk_util.h"
#include "../include/epk_port.h"
/* ---------------------------------------------------------------- */
void epk_buf_init(epk_buf *b) { b->p = 0; b->len = b->cap = 0; b->oom = 0; }

int epk_buf_reserve(epk_buf *b, unsigned need)
{
    unsigned ncap;
    void *np;
    if (b->oom) return -1;
    if (b->len + need <= b->cap) return 0;
    ncap = b->cap ? b->cap : 256;
    while (ncap < b->len + need) ncap *= 2;
    np = epk_realloc(b->p, ncap);
    if (!np) { b->oom = 1; return -1; }
    b->p = (uint8_t *)np;
    b->cap = ncap;
    return 0;
}

int epk_buf_append(epk_buf *b, const void *data, unsigned n)
{
    if (n == 0) return 0;
    if (epk_buf_reserve(b, n) != 0) return -1;
    memcpy(b->p + b->len, data, n);
    b->len += n;
    return 0;
}

int epk_buf_appendc(epk_buf *b, uint8_t c)
{
    return epk_buf_append(b, &c, 1);
}

int epk_buf_appends(epk_buf *b, const char *s)
{
    return epk_buf_append(b, s, (unsigned)strlen(s));
}

void epk_buf_free(epk_buf *b)
{
    epk_free(b->p);
    epk_buf_init(b);
}

void epk_buf_clear(epk_buf *b)
{
    b->len = 0;
}

/* ---------------------------------------------------------------- */
size_t epk_strlcpy(char *dst, const char *src, size_t cap)
{
    size_t n = strlen(src);
    if (cap == 0) return n;
    if (n >= cap) n = cap - 1;
    memcpy(dst, src, n);
    dst[n] = 0;
    return strlen(src);
}

size_t epk_strlcat(char *dst, const char *src, size_t cap)
{
    size_t dl = strlen(dst);
    if (dl >= cap) return dl + strlen(src);
    return dl + epk_strlcpy(dst + dl, src, cap - dl);
}

static int lc(int c) { return (c >= 'A' && c <= 'Z') ? c + 32 : c; }

int epk_strcasecmp(const char *a, const char *b)
{
    while (*a && lc(*a) == lc(*b)) { a++; b++; }
    return lc((unsigned char)*a) - lc((unsigned char)*b);
}

int epk_strncasecmp(const char *a, const char *b, size_t n)
{
    while (n && *a && lc(*a) == lc(*b)) { a++; b++; n--; }
    if (n == 0) return 0;
    return lc((unsigned char)*a) - lc((unsigned char)*b);
}

int epk_parse_uint(const char *s, unsigned long *out)
{
    unsigned long v = 0;
    if (!s || !*s) return -1;
    while (*s >= '0' && *s <= '9') {
        v = v * 10 + (unsigned)(*s - '0');
        s++;
    }
    if (*s) return -1;
    *out = v;
    return 0;
}

int epk_hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int epk_has_prefix(const char *s, const char *prefix)
{
    size_t n = strlen(prefix);
    return strncmp(s, prefix, n) == 0;
}

/* ---------------------------------------------------------------- */
void epk_hex(const uint8_t *data, unsigned n, char *out)
{
    static const char d[] = "0123456789abcdef";
    unsigned i;
    for (i = 0; i < n; i++) {
        out[i * 2]     = d[data[i] >> 4];
        out[i * 2 + 1] = d[data[i] & 15];
    }
    out[n * 2] = 0;
}

int epk_unhex(const char *hex, uint8_t *out, unsigned cap)
{
    unsigned n = (unsigned)strlen(hex), i;
    if (n & 1 || n / 2 > cap) return -1;
    for (i = 0; i < n / 2; i++) {
        int hi = epk_hexval((unsigned char)hex[i * 2]);
        int lo = epk_hexval((unsigned char)hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)(hi * 16 + lo);
    }
    return (int)(n / 2);
}

/* ---------------------------------------------------------------- */
int epk_base64_decode(const char *in, unsigned inlen,
                      uint8_t *out, unsigned cap, unsigned *outlen)
{
    unsigned o = 0, i;
    int val = 0, bits = 0;
    for (i = 0; i < inlen; i++) {
        int c = (unsigned char)in[i], d;
        if (c == '\r' || c == '\n' || c == ' ' || c == '\t') continue;
        if (c == '=' ) break;
        d = 0;
        if (c >= 'A' && c <= 'Z') d = c - 'A';
        else if (c >= 'a' && c <= 'z') d = c - 'a' + 26;
        else if (c >= '0' && c <= '9') d = c - '0' + 52;
        else if (c == '+') d = 62;
        else if (c == '/') d = 63;
        else return -1;
        val = (val << 6) | d;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (o >= cap) return -1;
            out[o++] = (uint8_t)(val >> bits);
        }
    }
    *outlen = o;
    return 0;
}

/* ---------------------------------------------------------------- */
static const char b64d[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int epk_base64_encode(const uint8_t *in, unsigned n, char *out, unsigned cap)
{
    unsigned o = 0, i;
    for (i = 0; i < n; i += 3) {
        unsigned v = (unsigned)in[i] << 16;
        int pad = 0;
        if (o + 4 > cap) return -1;
        if (i + 1 < n) v |= (unsigned)in[i + 1] << 8; else pad++;
        if (i + 2 < n) v |= (unsigned)in[i + 2]; else pad++;
        out[o++] = b64d[(v >> 18) & 63];
        out[o++] = b64d[(v >> 12) & 63];
        out[o++] = pad >= 2 ? '=' : b64d[(v >> 6) & 63];
        out[o++] = pad >= 1 ? '=' : b64d[v & 63];
    }
    if (o + 1 > cap) return -1;
    out[o] = 0;
    return (int)o;
}

/* ---------------------------------------------------------------- */
uint8_t *epk_read_file(const char *path, unsigned *outlen)
{
    epk_file f;
    uint8_t *data = 0;
    unsigned cap = 4096, len = 0;
    int n;

    f = epk_open(path, EPK_O_RDONLY);
    if (!f) return 0;
    data = (uint8_t *)epk_malloc(cap);
    if (!data) { epk_close(f); return 0; }
    for (;;) {
        if (len == cap) {
            uint8_t *nd = (uint8_t *)epk_realloc(data, cap * 2);
            if (!nd) { epk_free(data); epk_close(f); return 0; }
            data = nd; cap *= 2;
        }
        n = epk_read(f, data + len, cap - len);
        if (n < 0) { epk_free(data); epk_close(f); return 0; }
        if (n == 0) break;
        len += (unsigned)n;
    }
    epk_close(f);
    /* guarantee NUL termination one past the payload (text helpers) */
    if (len + 1 > cap) {
        uint8_t *nd = (uint8_t *)epk_realloc(data, len + 1);
        if (!nd) { epk_free(data); return 0; }
        data = nd;
    }
    data[len] = 0;
    *outlen = len;
    return data;
}

int epk_write_file(const char *path, const void *data, unsigned n)
{
    epk_file f = epk_open(path, EPK_O_WRONLY | EPK_O_CREATE | EPK_O_TRUNC);
    const uint8_t *p = (const uint8_t *)data;
    if (!f) return -1;
    while (n) {
        int w = epk_write(f, p, n);
        if (w <= 0) { epk_close(f); return -1; }
        p += w; n -= (unsigned)w;
    }
    epk_close(f);
    return 0;
}

int epk_mkdir_p(const char *path)
{
    char tmp[512];
    size_t i, n = strlen(path);
    if (n >= sizeof(tmp)) return -1;
    memcpy(tmp, path, n + 1);
    for (i = 1; i <= n; i++) {
        if (tmp[i] == '/' || tmp[i] == 0) {
            char c = tmp[i];
            tmp[i] = 0;
            if (epk_mkdir(tmp) != 0) { if (c == 0) return -1; }
            tmp[i] = (char)c;
        }
    }
    return 0;
}

/* ---------------------------------------------------------------- */
/* Mini formatter: %s %c %d %i %u %x %X %p %zu %llu, %%, width+'0'   */
#include <stdarg.h>

static void put(char *b, size_t cap, size_t *n, char c)
{
    if (*n + 1 < cap) b[*n] = c;
    (*n)++;
}

static void put_pad(char *b, size_t cap, size_t *n, char c, int count)
{
    while (count-- > 0) put(b, cap, n, c);
}

static void emit_num(char *b, size_t cap, size_t *n,
                     unsigned long long v, unsigned base, int upper,
                     int width, int zeropad, int neg)
{
    char tmp[24];
    const char *d = upper ? "0123456789ABCDEF" : "0123456789abcdef";
    int i = 0, pad;

    if (v == 0) tmp[i++] = '0';
    while (v) { tmp[i++] = d[v % base]; v /= base; }
    pad = width - i - (neg ? 1 : 0);
    if (neg) put(b, cap, n, '-');
    if (pad > 0) {
        char pc = zeropad ? '0' : ' ';
        while (pad-- > 0) put(b, cap, n, pc);
    }
    while (i > 0) put(b, cap, n, tmp[--i]);
}

int epk_snprintf(char *buf, size_t cap, const char *fmt, ...)
{
    va_list ap;
    size_t n = 0;
    const char *f = fmt;

    va_start(ap, fmt);
    while (*f) {
        if (*f != '%') { put(buf, cap, &n, *f++); continue; }
        f++;
        if (*f == '%') { put(buf, cap, &n, *f++); continue; }

        {
            int width = 0, zeropad = 0, lcount = 0, zmod = 0, left = 0;
            while (*f == '0' || *f == '-' || (*f >= '1' && *f <= '9') ||
                   *f == 'l' || *f == 'z') {
                if (*f == '0' && width == 0) zeropad = 1;
                else if (*f == '-') left = 1;
                else if (*f == 'l') lcount++;
                else if (*f == 'z') zmod = 1;
                else width = width * 10 + (*f - '0');
                f++;
            }
            (void)zmod;
            switch (*f) {
            case 's': {
                const char *s = va_arg(ap, const char *);
                int len = 0;
                if (!s) s = "(null)";
                len = (int)strlen(s);
                if (!left && len < width) put_pad(buf, cap, &n, ' ', width - len);
                while (*s) put(buf, cap, &n, *s++);
                if (left && len < width) put_pad(buf, cap, &n, ' ', width - len);
                break;
            }
            case 'c':
                put(buf, cap, &n, (char)va_arg(ap, int));
                break;
            case 'd': case 'i': {
                long long v;
                if (lcount >= 2) v = va_arg(ap, long long);
                else v = va_arg(ap, int);
                if (v < 0) emit_num(buf, cap, &n, (unsigned long long)(-v),
                                    10, 0, width, zeropad, 1);
                else emit_num(buf, cap, &n, (unsigned long long)v,
                              10, 0, width, zeropad, 0);
                break;
            }
            case 'u': case 'x': case 'X': case 'p': {
                unsigned long long v;
                if (*f == 'p') v = (unsigned long long)(size_t)va_arg(ap, void *);
                else if (lcount >= 2) v = va_arg(ap, unsigned long long);
                else v = va_arg(ap, unsigned int);
                emit_num(buf, cap, &n, v,
                         (*f == 'x' || *f == 'X' || *f == 'p') ? 16 : 10,
                         *f == 'X', width, zeropad, 0);
                break;
            }
            default:
                put(buf, cap, &n, '%');
                put(buf, cap, &n, *f);
                break;
            }
            if (*f) f++;
        }
    }
    va_end(ap);
    if (cap) buf[n < cap ? n : cap - 1] = 0;
    return (int)n;
}
