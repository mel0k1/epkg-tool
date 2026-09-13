/* epk_http.c — HTTP/1.1 GET with redirects + chunked transfer decoding. */
#include "epk_http.h"
#include "epk_url.h"
#include "epk_util.h"
#include "epk_tls.h"
#include "../include/epk_port.h"

#define MAX_REDIRECTS 5
#define HDR_LIMIT     (32 * 1024)

static int http_once(const char *url, const char *ca_file,
                     long long range_from,
                     epk_http_sink sink, void *ctx,
                     epk_http_onresp onresp, epk_http_res *res,
                     int *redirect, char *loc, unsigned loccap,
                     char *err, unsigned errcap);

typedef struct {
    epk_sock sock;
    epk_tls *tls;
} xport;

static int xsend(xport *x, const void *buf, unsigned len)
{
    const uint8_t *p = (const uint8_t *)buf;
    while (len) {
        int w = x->tls ? epk_tls_write(x->tls, p, (int)len)
                       : epk_tcp_send(x->sock, p, (int)len);
        if (w <= 0) return -1;
        p += w;
        len -= (unsigned)w;
    }
    return 0;
}

/* read one line (CR-LF terminated) into buf; returns stripped length
 * (0 for the empty line that ends the header section) */
static int xline(xport *x, char *buf, unsigned cap)
{
    unsigned n = 0;
    for (;;) {
        uint8_t c;
        int r = x->tls ? epk_tls_read(x->tls, &c, 1)
                       : epk_tcp_recv(x->sock, &c, 1);
        if (r <= 0) return -1;
        if (c == '\n') {
            if (n && buf[n - 1] == '\r') n--;
            buf[n] = 0;
            return (int)n;
        }
        if (n + 1 >= cap) return -1;
        buf[n++] = (char)c;
    }
}

/* read exactly n raw bytes */
static int xread(xport *x, uint8_t *buf, unsigned n)
{
    unsigned got = 0;
    while (got < n) {
        int r = x->tls ? epk_tls_read(x->tls, buf + got, (int)(n - got))
                       : epk_tcp_recv(x->sock, buf + got, (int)(n - got));
        if (r <= 0) return -1;
        got += (unsigned)r;
    }
    return 0;
}

/* read and discard until EOF */
static void xdrain(xport *x)
{
    uint8_t scratch[512];
    while (x->tls ? epk_tls_read(x->tls, scratch, sizeof(scratch)) > 0
                  : epk_tcp_recv(x->sock, scratch, sizeof(scratch)) > 0)
        ;
}

int epk_http_get(const char *url, const char *ca_file,
                 epk_http_sink sink, void *ctx,
                 char *err, unsigned errcap)
{
    return epk_http_get_ex(url, ca_file, -1, sink, ctx, 0, 0, err, errcap);
}

int epk_http_get_ex(const char *url, const char *ca_file,
                    long long range_from,
                    epk_http_sink sink, void *ctx,
                    epk_http_onresp onresp,
                    epk_http_res *res,
                    char *err, unsigned errcap)
{
    int hops = 0, r;
    char cur[900], loc[900];

    if (res) {
        res->status = -1;
        res->body_from = 0;
        res->total = -1;
    }
    epk_strlcpy(cur, url, sizeof(cur));
    for (;;) {
        r = http_once(cur, ca_file, range_from, sink, ctx, onresp, res,
                      &hops, loc, sizeof(loc), err, errcap);
        if (r >= 300 && r < 400 && hops <= MAX_REDIRECTS && loc[0]) {
            epk_strlcpy(cur, loc, sizeof(cur));
            continue;
        }
        break;
    }
    if (r >= 200 && r < 300) return 0;
    return r;
}

static int http_once(const char *url, const char *ca_file,
                     long long range_from,
                     epk_http_sink sink, void *ctx,
                     epk_http_onresp onresp, epk_http_res *res,
                     int *redirect, char *loc, unsigned loccap,
                     char *err, unsigned errcap)
{
    epk_url u;
    xport x;
    char req[1200], line[2048];
    long status = -1;
    int chunked = 0;
    long clen = -1;
    long long cr_from = -1, cr_total = -1;
    int i;

    if (res) {
        res->status = -1;
        res->body_from = 0;
        res->total = -1;
    }

    loc[0] = 0;
    if (epk_url_parse(url, &u) != 0) {
        epk_snprintf(err, errcap, "bad URL: %s", url);
        return -1;
    }

    x.sock = epk_tcp_connect(u.host, u.port[0] ? u.port : "80", 15000);
    if (!x.sock) {
        epk_snprintf(err, errcap, "connect %s:%s failed", u.host, u.port);
        return -1;
    }
    x.tls = 0;
    if (u.tls) {
        x.tls = epk_tls_connect(x.sock, u.host, ca_file, err, errcap);
        if (!x.tls) {
            epk_tcp_close(x.sock);
            return -1;
        }
    }

    if (range_from >= 0)
        epk_snprintf(req, sizeof(req),
                     "GET %s HTTP/1.1\r\n"
                     "Host: %s\r\n"
                     "User-Agent: epkg/1.1\r\n"
                     "Accept: */*\r\n"
                     "Range: bytes=%lld-\r\n"
                     "Connection: close\r\n"
                     "\r\n",
                     u.path, u.host, range_from);
    else
        epk_snprintf(req, sizeof(req),
                     "GET %s HTTP/1.1\r\n"
                     "Host: %s\r\n"
                     "User-Agent: epkg/1.1\r\n"
                     "Accept: */*\r\n"
                     "Connection: close\r\n"
                     "\r\n",
                     u.path, u.host);
    if (xsend(&x, req, (unsigned)strlen(req)) != 0) {
        epk_snprintf(err, errcap, "send failed");
        goto fail;
    }

    /* status line */
    if (xline(&x, line, sizeof(line)) < 0) {
        epk_snprintf(err, errcap, "no response");
        goto fail;
    }
    if (strncmp(line, "HTTP/", 5) == 0) {
        /* lenient status parse: "200 OK", "301 Moved ..." etc. */
        const char *q = strchr(line, ' ');
        unsigned long v = 0;
        if (q) {
            q++;
            while (*q >= '0' && *q <= '9') v = v * 10 + (unsigned long)(*q++ - '0');
        }
        status = (long)v;
    }
    if (status < 100) {
        epk_snprintf(err, errcap, "bad status line");
        goto fail;
    }

    /* headers */
    for (i = 0; i < HDR_LIMIT; ) {
        int n = xline(&x, line, sizeof(line));
        if (n < 0) break;
        i += n;
        if (n == 0) break;
        if (epk_strncasecmp(line, "content-length:", 15) == 0) {
            const char *v = line + 15;
            unsigned long n = 0;
            while (*v == ' ' || *v == '\t') v++;
            while (*v >= '0' && *v <= '9') n = n * 10 + (unsigned long)(*v++ - '0');
            clen = (long)n;
        } else if (epk_strncasecmp(line, "transfer-encoding:", 18) == 0) {
            if (strstr(line, "chunked")) chunked = 1;
        } else if (epk_strncasecmp(line, "location:", 9) == 0) {
            const char *p = line + 9;
            while (*p == ' ' || *p == '\t') p++;
            epk_strlcpy(loc, p, loccap);
        } else if (epk_strncasecmp(line, "content-range:", 14) == 0) {
            /* "bytes FROM-TO/TOTAL" or "* / TOTAL" — lenient parse */
            const char *p = line + 14;
            long long cur = 0;
            int have = 0, intotal = 0;
            for (; *p; p++) {
                if (*p >= '0' && *p <= '9') {
                    cur = cur * 10 + (*p - '0');
                    have = 1;
                } else {
                    if (have) {
                        if (intotal) cr_total = cur;
                        else if (cr_from < 0) cr_from = cur;
                        have = 0;
                        cur = 0;
                    }
                    if (*p == '/') intotal = 1;
                }
            }
            if (have && intotal) cr_total = cur;
        }
    }

    if (status >= 300 && status < 400) {
        /* body of redirect is skipped by caller via new request */
        (*redirect)++;
        xdrain(&x);
        goto done_nolocate;
    }

    /* fill the result + let the caller reconfigure the sink before body */
    if (res) {
        res->status = status;
        res->body_from = (status == 206 && cr_from >= 0) ? cr_from : 0;
        res->total = (status == 206) ? cr_total
                   : (clen >= 0 ? clen + res->body_from : -1);
        if (res->total < 0) res->total = -1;
    }
    if (onresp) {
        long long bf = res ? res->body_from : 0;
        long long tt = res ? res->total : -1;
        if (onresp(ctx, status, bf, tt) != 0) {
            epk_snprintf(err, errcap, "aborted by callback");
            goto fail;
        }
    }

    if (chunked) {
        for (;;) {
            unsigned long csz = 0;
            int n = xline(&x, line, sizeof(line));
            if (n < 0) break;
            /* chunk size may be followed by ;ext */
            {
                char *sc = strchr(line, ';');
                if (sc) *sc = 0;
                if (epk_parse_uint(line, &csz) != 0) break;
            }
            if (csz == 0) {
                /* trailer lines until empty */
                for (;;) {
                    int t = xline(&x, line, sizeof(line));
                    if (t <= 0) break;
                }
                break;
            }
            {
                static uint8_t buf[8192];
                unsigned long left = csz;
                while (left) {
                    unsigned take = left > sizeof(buf) ? sizeof(buf) : (unsigned)left;
                    if (xread(&x, buf, take) != 0) {
                        epk_snprintf(err, errcap, "chunked body truncated");
                        goto fail;
                    }
                    if (!sink(ctx, buf, take)) {
                        epk_snprintf(err, errcap, "write failed");
                        goto fail;
                    }
                    left -= take;
                }
                /* trailing CRLF */
                if (xread(&x, (uint8_t *)line, 2) != 0) {
                    epk_snprintf(err, errcap, "chunked framing error");
                    goto fail;
                }
            }
        }
    } else if (clen >= 0) {
        static uint8_t buf[16384];
        long left = clen;
        while (left > 0) {
            unsigned take = left > (long)sizeof(buf) ? sizeof(buf) : (unsigned)left;
            if (xread(&x, buf, take) != 0) {
                epk_snprintf(err, errcap, "body truncated");
                goto fail;
            }
            if (!sink(ctx, buf, take)) {
                epk_snprintf(err, errcap, "write failed");
                goto fail;
            }
            left -= (long)take;
        }
    } else {
        /* read until connection close */
        static uint8_t buf[16384];
        for (;;) {
            int r = x.tls ? epk_tls_read(x.tls, buf, sizeof(buf))
                          : epk_tcp_recv(x.sock, buf, sizeof(buf));
            if (r < 0) {
                epk_snprintf(err, errcap, "recv failed");
                goto fail;
            }
            if (r == 0) break;
            if (!sink(ctx, buf, (unsigned)r)) {
                epk_snprintf(err, errcap, "write failed");
                goto fail;
            }
        }
    }

done_nolocate:
    if (x.tls) epk_tls_close(x.tls);
    epk_tcp_close(x.sock);
    return (int)status;

fail:
    if (x.tls) epk_tls_close(x.tls);
    epk_tcp_close(x.sock);
    return -1;
}
