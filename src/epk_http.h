/* epk_http.h — HTTP/1.1 GET client over the port layer (+ TLS via epk_tls). */
#ifndef EPK_HTTP_H
#define EPK_HTTP_H

#include <stdint.h>

/* return: 1 = chunk accepted, 0 = abort */
typedef int (*epk_http_sink)(void *ctx, const uint8_t *data, unsigned len);

/* Perform GET on an absolute http:// or https:// URL, streaming the body
 * to sink. Follows up to 5 redirects.
 * ca_file: PEM bundle for https validation (may be NULL: TLS still
 * validates hostname against known anchors? see epk_tls; NULL means
 * "no chain verification, hostname-only warnings").
 * Returns:
 *   0        success (2xx, body delivered)
 *   1..599   final HTTP status (non-2xx)
 *   -1       transport/protocol error (details in err) */
int epk_http_get(const char *url, const char *ca_file,
                 epk_http_sink sink, void *ctx,
                 char *err, unsigned errcap);

/* ---------------- extended API (download resume) ---------------- */

typedef struct {
    long      status;      /* final HTTP status (-1 on transport error) */
    long long body_from;  /* offset the delivered body starts at       */
    long long total;      /* total object size if known, else -1       */
} epk_http_res;

/* Called once the FINAL response headers are parsed, before the body.
 * The sink/ctx pair may reconfigure itself here (e.g. truncate vs append
 * depending on status / body_from). Return 0 to deliver the body,
 * nonzero to abort (epk_http_get_ex then reports a transport error). */
typedef int (*epk_http_onresp)(void *ctx, long status,
                               long long body_from, long long total);

/* GET with optional byte range ("Range: bytes=FROM-").
 * range_from < 0 sends no Range header (plain GET).
 * onresp may be NULL; res may be NULL.
 * Return codes: see epk_http_get. */
int epk_http_get_ex(const char *url, const char *ca_file,
                    long long range_from,
                    epk_http_sink sink, void *ctx,
                    epk_http_onresp onresp,
                    epk_http_res *res,
                    char *err, unsigned errcap);

#endif
