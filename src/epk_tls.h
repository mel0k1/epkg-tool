/* epk_tls.h — TLS (via vendored BearSSL) over an epk_sock TCP connection. */
#ifndef EPK_TLS_H
#define EPK_TLS_H

#include <stdint.h>
#include "../include/epk_port.h"

typedef struct epk_tls epk_tls;

/* Start a TLS session on an established TCP connection.
 * host     — SNI name and certificate hostname to verify.
 * ca_path  — PEM bundle with trust anchors; if NULL, the chain is not
 *            verified against roots (hostname check still runs on the
 *            leaf certificate; a warning is expected behaviour for
 *            hobby systems without a CA store).
 * err      — human-readable error buffer (may be NULL).
 * Returns NULL on failure. */
epk_tls *epk_tls_connect(epk_sock sock, const char *host,
                         const char *ca_path,
                         char *err, unsigned errcap);

/* Read: >0 bytes, 0 on clean TLS close, -1 on error. */
int  epk_tls_read(epk_tls *t, void *buf, unsigned len);

/* Write: >0 bytes written or -1 on error. */
int  epk_tls_write(epk_tls *t, const void *buf, unsigned len);

void epk_tls_close(epk_tls *t);

#endif
