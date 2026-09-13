/* epk_pkginfo.h — PKGINFO metadata parsing (key = value lines). */
#ifndef EPK_PKGINFO_H
#define EPK_PKGINFO_H

#include "epk_util.h"

typedef struct {
    char pkgname[64];
    char pkgver[64];
    char pkgdesc[256];
    char arch[32];
    char sha256[65];     /* manifest hash of files/ (see FORMAT.md)  */
    char deps[256];      /* comma-separated names (informational)    */
} epk_pkginfo;

/* Parse a PKGINFO buffer (modified in place). 0 on success.
 * Requires at least pkgname and pkgver. */
int epk_pkginfo_parse(epk_pkginfo *pi, char *buf, unsigned len);

#endif
