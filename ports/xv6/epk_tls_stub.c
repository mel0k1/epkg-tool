/* epk_tls_stub.c — TLS disabled build for xv6 (keeps epk_http linkable).
 * The xv6 mirror is served over plain http:// inside QEMU slirp. */
#include "epk_tls.h"
#include "epk_util.h"

epk_tls *
epk_tls_connect(epk_sock sock, const char *host, const char *ca_path,
                char *err, unsigned errcap)
{
  (void)sock; (void)host; (void)ca_path;
  if (err && errcap)
    epk_snprintf(err, errcap, "TLS not built into this epkg binary");
  return 0;
}

int
epk_tls_read(epk_tls *t, void *buf, unsigned len)
{
  (void)t; (void)buf; (void)len;
  return -1;
}

int
epk_tls_write(epk_tls *t, const void *buf, unsigned len)
{
  (void)t; (void)buf; (void)len;
  return -1;
}

void
epk_tls_close(epk_tls *t)
{
  (void)t;
}
