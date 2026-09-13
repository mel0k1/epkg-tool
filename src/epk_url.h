/* epk_url.h — URL parsing (scheme://host[:port]/path). */
#ifndef EPK_URL_H
#define EPK_URL_H

#include <stdint.h>

typedef struct {
    char scheme[16];
    char host[256];
    char port[8];
    char path[768];
    int  tls;               /* 1 for https */
} epk_url;

/* Parse "https://host:port/path". Returns 0 on success. */
int epk_url_parse(const char *url, epk_url *u);

#endif
