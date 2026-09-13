/* epk_url.c — tiny URL parser (absolute http/https URLs only). */
#include "epk_url.h"
#include "epk_util.h"

int epk_url_parse(const char *url, epk_url *u)
{
    const char *p = url;
    const char *h, *hend, *path;
    size_t n;

    memset(u, 0, sizeof(*u));
    strcpy(u->port, "");

    if (epk_has_prefix(p, "https://")) {
        epk_strlcpy(u->scheme, "https", sizeof(u->scheme));
        u->tls = 1;
        epk_strlcpy(u->port, "443", sizeof(u->port));
        p += 8;
    } else if (epk_has_prefix(p, "http://")) {
        epk_strlcpy(u->scheme, "http", sizeof(u->scheme));
        u->tls = 0;
        epk_strlcpy(u->port, "80", sizeof(u->port));
        p += 7;
    } else {
        return -1;
    }

    h = p;
    while (*p && *p != '/' && *p != ':') p++;
    hend = p;
    if (*p == ':') {
        p++;
        n = 0;
        while (*p >= '0' && *p <= '9' && n < sizeof(u->port) - 1)
            u->port[n++] = *p++;
        u->port[n] = 0;
        if (!n) return -1;
    }
    if (hend == h || hend - h >= (long)sizeof(u->host)) return -1;
    memcpy(u->host, h, (size_t)(hend - h));
    u->host[hend - h] = 0;

    path = p;
    if (!*path) path = "/";
    epk_strlcpy(u->path, path, sizeof(u->path));
    return 0;
}
