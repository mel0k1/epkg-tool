/* epk_index.c — repository index access. */
#include "epk_index.h"
#include "epk_util.h"
#include "../include/epk_port.h"

static void idx_add(epk_index *ix, const ej_value *o)
{
    epk_idx_entry *e;
    const char *s;
    ej_value *deps;

    if (ix->n == ix->cap) {
        unsigned ncap = ix->cap ? ix->cap * 2 : 32;
        void *np = epk_realloc(ix->pkgs, ncap * sizeof(epk_idx_entry));
        if (!np) return;                          /* oom: skip entry */
        ix->pkgs = (epk_idx_entry *)np;
        ix->cap = ncap;
    }
    e = &ix->pkgs[ix->n];
    memset(e, 0, sizeof(*e));

    s = ej_get_str(o, "pkgname");
    if (s) epk_strlcpy(e->pkgname, s, sizeof(e->pkgname));
    if (!e->pkgname[0]) return;                   /* required */
    s = ej_get_str(o, "pkgver");
    if (s) epk_strlcpy(e->pkgver, s, sizeof(e->pkgver));
    s = ej_get_str(o, "pkgdesc");
    if (s) epk_strlcpy(e->pkgdesc, s, sizeof(e->pkgdesc));
    s = ej_get_str(o, "filename");
    if (s) epk_strlcpy(e->filename, s, sizeof(e->filename));
    s = ej_get_str(o, "sha256");
    if (s) epk_strlcpy(e->sha256, s, sizeof(e->sha256));
    s = ej_get_str(o, "url");
    if (s) epk_strlcpy(e->url, s, sizeof(e->url));
    e->size = ej_get_int(o, "size");

    deps = ej_get(o, "deps");
    if (deps && deps->t == EJ_ARR) {
        unsigned k, n = ej_arr_len(deps);
        for (k = 0; k < n; k++) {
            ej_value *d = ej_arr_at(deps, k);
            if (d && d->t == EJ_STR) {
                if (e->deps[0]) epk_strlcat(e->deps, ",", sizeof(e->deps));
                epk_strlcat(e->deps, d->v.str.s, sizeof(e->deps));
            }
        }
    } else if ((s = ej_get_str(o, "deps")) != 0) {
        epk_strlcpy(e->deps, s, sizeof(e->deps));
    }

    ix->n++;
}

int epk_index_parse(epk_index *ix, char *buf, unsigned len)
{
    ej_value *pkgs;
    unsigned i, n;

    memset(ix, 0, sizeof(*ix));
    (void)len;                       /* buf must be NUL-terminated */
    if (epk_json_parse(&ix->json, buf) != 0) return -1;
    pkgs = ej_get(ix->json.root, "packages");
    if (!pkgs || pkgs->t != EJ_ARR) {
        epk_json_free(&ix->json);
        return -1;
    }
    n = ej_arr_len(pkgs);
    for (i = 0; i < n; i++)
        idx_add(ix, ej_arr_at(pkgs, i));
    ix->loaded = 1;
    return 0;
}

void epk_index_free(epk_index *ix)
{
    epk_json_free(&ix->json);
    epk_free(ix->pkgs);
    memset(ix, 0, sizeof(*ix));
}

const epk_idx_entry *epk_index_get(const epk_index *ix, const char *name)
{
    unsigned i;
    for (i = 0; i < ix->n; i++)
        if (strcmp(ix->pkgs[i].pkgname, name) == 0)
            return &ix->pkgs[i];
    return 0;
}

static int ci_substring(const char *hay, const char *needle)
{
    size_t nl = strlen(needle);
    if (!nl) return 1;
    for (; *hay; hay++)
        if (epk_strncasecmp(hay, needle, nl) == 0) return 1;
    return 0;
}

unsigned epk_index_search(const epk_index *ix, const char *term,
                          const epk_idx_entry **out, unsigned max)
{
    unsigned i, cnt = 0;
    for (i = 0; i < ix->n && cnt < max; i++) {
        if (ci_substring(ix->pkgs[i].pkgname, term) ||
            ci_substring(ix->pkgs[i].pkgdesc, term)) {
            out[cnt++] = &ix->pkgs[i];
        }
    }
    return cnt;
}
