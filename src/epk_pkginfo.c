/* epk_pkginfo.c — PKGINFO parser (non-destructive). */
#include "epk_pkginfo.h"

static int field_is(const char *ks, size_t kn, const char *name)
{
    return strlen(name) == kn && memcmp(ks, name, kn) == 0;
}

static void field_set(epk_pkginfo *pi, const char *ks, size_t kn,
                      const char *vs, size_t vn,
                      int *have_name, int *have_ver)
{
    char vbuf[256];
    if (vn >= sizeof(vbuf)) vn = sizeof(vbuf) - 1;
    memcpy(vbuf, vs, vn);
    vbuf[vn] = 0;

    if (field_is(ks, kn, "pkgname")) {
        epk_strlcpy(pi->pkgname, vbuf, sizeof(pi->pkgname));
        *have_name = 1;
    } else if (field_is(ks, kn, "pkgver")) {
        epk_strlcpy(pi->pkgver, vbuf, sizeof(pi->pkgver));
        *have_ver = 1;
    } else if (field_is(ks, kn, "pkgdesc")) {
        epk_strlcpy(pi->pkgdesc, vbuf, sizeof(pi->pkgdesc));
    } else if (field_is(ks, kn, "arch")) {
        epk_strlcpy(pi->arch, vbuf, sizeof(pi->arch));
    } else if (field_is(ks, kn, "sha256")) {
        epk_strlcpy(pi->sha256, vbuf, sizeof(pi->sha256));
    } else if (field_is(ks, kn, "deps") || field_is(ks, kn, "depends")) {
        epk_strlcpy(pi->deps, vbuf, sizeof(pi->deps));
    }
    /* unknown keys ignored (forward compatible) */
}

int epk_pkginfo_parse(epk_pkginfo *pi, char *buf, unsigned len)
{
    char *p = buf;
    int have_name = 0, have_ver = 0;

    memset(pi, 0, sizeof(*pi));
    epk_strlcpy(pi->arch, "any", sizeof(pi->arch));
    (void)len;                       /* buf must be NUL-terminated */

    while (*p) {
        char *eol = strchr(p, '\n');
        char *next;
        char *eq;
        const char *ks, *ke, *vs, *ve;
        size_t kn, vn;
        char kbuf[32];

        if (!eol) eol = p + strlen(p);
        next = (*eol == '\n') ? eol + 1 : eol;

        /* find '=' within the line */
        for (eq = p; eq < eol && *eq != '='; eq++) {}
        if (eq >= eol) { p = next; continue; }

        ks = p;   ke = eq;
        vs = eq + 1; ve = eol;
        while (ks < ke && (ke[-1] == ' ' || ke[-1] == '\t' || ke[-1] == '\r'))
            ke--;
        while (ks < ke && (*ks == ' ' || *ks == '\t')) ks++;
        while (vs < ve && (*vs == ' ' || *vs == '\t')) vs++;
        while (ve > vs && (ve[-1] == ' ' || ve[-1] == '\t' || ve[-1] == '\r'))
            ve--;

        kn = (size_t)(ke - ks);
        vn = (size_t)(ve - vs);
        if (kn == 0 || kn >= sizeof(kbuf)) { p = next; continue; }
        memcpy(kbuf, ks, kn);
        kbuf[kn] = 0;

        field_set(pi, kbuf, kn, vs, vn, &have_name, &have_ver);
        p = next;
    }
    return (have_name && have_ver) ? 0 : -1;
}
