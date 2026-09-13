/* TLS smoke test: HTTPS GET against a real server. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "epk_http.h"
#include "epk_util.h"
#include "../include/epk_port.h"

typedef struct {
    FILE *f;
    unsigned n;
} sink_t;

static int sink_write(void *ctx, const uint8_t *d, unsigned n)
{
    sink_t *s = (sink_t *)ctx;
    fwrite(d, 1, n, s->f);
    s->n += n;
    return 1;
}

int main(int argc, char **argv)
{
    const char *url = argc > 1 ? argv[1]
        : "https://raw.githubusercontent.com/git/git/master/README.md";
    const char *ca  = argc > 2 ? argv[2] : "ca/roots.pem";
    char err[256];
    sink_t s;
    int r;

    s.f = fopen("/tmp/tls_out.bin", "wb");
    s.n = 0;
    r = epk_http_get(url, ca, sink_write, &s, err, sizeof(err));
    fclose(s.f);
    printf("status=%d bytes=%u err=%s\n", r, s.n, err);
    if (r == 0) {
        FILE *f = fopen("/tmp/tls_out.bin", "rb");
        char head[200] = {0};
        fread(head, 1, sizeof(head) - 1, f);
        fclose(f);
        printf("head: %.80s\n", head);
        return 0;
    }
    return 1;
}
