/* epk_index.h — repository index (index.json) access. */
#ifndef EPK_INDEX_H
#define EPK_INDEX_H

#include "epk_json.h"

#define EPK_IDX_MAXPKGS 512

typedef struct {
    char pkgname[64];
    char pkgver[64];
    char pkgdesc[256];
    char filename[128];
    char sha256[65];
    char url[512];       /* optional absolute override */
    char deps[256];
    long long size;
} epk_idx_entry;

typedef struct {
    epk_json json;               /* parsed document (owns memory)  */
    epk_idx_entry *pkgs;         /* malloc'd array                 */
    unsigned n, cap;
    int loaded;
} epk_index;

/* Parse an index.json buffer (consumes it). 0 on success. */
int  epk_index_parse(epk_index *ix, char *buf, unsigned len);
void epk_index_free(epk_index *ix);

/* Look up exact package name; NULL if absent. */
const epk_idx_entry *epk_index_get(const epk_index *ix, const char *name);

/* Case-insensitive substring search over name + description.
 * Results appended to out (up to max). Returns count. */
unsigned epk_index_search(const epk_index *ix, const char *term,
                          const epk_idx_entry **out, unsigned max);

#endif
