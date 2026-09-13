/* epk_db.c — installed-packages database.
 *
 * Layout under <db>:
 *   installed/<pkgname>       metadata: pkgver \n pkgdesc \n deps
 *   files/<pkgname>.list      one installed path per line
 */
#include "epk_db.h"
#include "../include/epk_port.h"

static void db_paths(const char *db, const char *name,
                     char *meta, unsigned mcap,
                     char *list, unsigned lcap)
{
    char t[300];
    epk_snprintf(t, sizeof(t), "%s/installed/%s", db, name);
    epk_strlcpy(meta, t, mcap);
    epk_snprintf(t, sizeof(t), "%s/files/%s.list", db, name);
    epk_strlcpy(list, t, lcap);
}

int epk_db_installed(const char *db, const char *name, epk_db_rec *rec)
{
    char meta[512], list[512];
    uint8_t *data;
    unsigned len;
    char *text, *l1, *l2, *l3;

    db_paths(db, name, meta, sizeof(meta), list, sizeof(list));
    data = epk_read_file(meta, &len);
    if (!data) return 0;
    if (len && data[len-1] != 0) { data[len-1] = 0; }
    text = (char *)data;
    l1 = text;
    l2 = l1 ? strchr(l1, '\n') : 0;
    if (l2) { *l2++ = 0; } else { l2 = l1 + strlen(l1); }
    l3 = strchr(l2, '\n');
    if (l3) { *l3++ = 0; } else { l3 = l2 + strlen(l2); }

    if (rec) {
        memset(rec, 0, sizeof(*rec));
        epk_strlcpy(rec->pkgname, name, sizeof(rec->pkgname));
        epk_strlcpy(rec->pkgver, l1, sizeof(rec->pkgver));
        epk_strlcpy(rec->pkgdesc, l2, sizeof(rec->pkgdesc));
        epk_strlcpy(rec->deps, l3, sizeof(rec->deps));
    }
    epk_free(data);
    return 1;
}

int epk_db_add(const char *db, const epk_db_rec *rec,
               const char (*files)[256], unsigned nfiles)
{
    char meta[512], list[512], tmp[600];
    epk_buf b;
    unsigned i;
    char hdr[600];

    epk_mkdir_p(db);
    {
        char sub[512];
        epk_snprintf(sub, sizeof(sub), "%s/installed", db);
        epk_mkdir_p(sub);
        epk_snprintf(sub, sizeof(sub), "%s/files", db);
        epk_mkdir_p(sub);
    }
    db_paths(db, rec->pkgname, meta, sizeof(meta), list, sizeof(list));

    epk_snprintf(hdr, sizeof(hdr), "%s\n%s\n%s\n",
                 rec->pkgver, rec->pkgdesc, rec->deps);
    if (epk_write_file(meta, hdr, (unsigned)strlen(hdr)) != 0) return -1;

    epk_buf_init(&b);
    for (i = 0; i < nfiles; i++) {
        epk_buf_appends(&b, files[i]);
        epk_buf_appendc(&b, '\n');
    }
    /* atomic-ish write: tmp + rename */
    epk_snprintf(tmp, sizeof(tmp), "%s.tmp", list);
    if (epk_write_file(tmp, b.p ? (const char *)b.p : "", b.len) != 0) {
        epk_buf_free(&b);
        return -1;
    }
    epk_buf_free(&b);
    if (epk_rename(tmp, list) != 0) return -1;
    return 0;
}

int epk_db_remove(const char *db, const char *name)
{
    char meta[512], list[512];

    db_paths(db, name, meta, sizeof(meta), list, sizeof(list));
    epk_unlink(meta);
    epk_unlink(list);
    return 0;
}

char **epk_db_files(const char *db, const char *name, unsigned *n)
{
    char meta[512], list[512];
    uint8_t *data;
    unsigned len, cap = 32, cnt = 0;
    char **out;
    char *s;

    *n = 0;
    db_paths(db, name, meta, sizeof(meta), list, sizeof(list));
    data = epk_read_file(list, &len);          /* NUL-terminated */
    if (!data) return 0;

    out = (char **)epk_malloc(cap * sizeof(char *));
    if (!out) { epk_free(data); return 0; }

    /* split on newlines (in place) and collect */
    {
        unsigned i;
        for (i = 0; i < len; i++)
            if (data[i] == '\n') data[i] = 0;
    }
    s = (char *)data;
    while (*s) {
        char *copy = (char *)epk_malloc((unsigned)strlen(s) + 1);
        if (!copy) break;
        strcpy(copy, s);
        if (cnt == cap) {
            char **no = (char **)epk_realloc(out, cap * 2 * sizeof(char *));
            if (!no) { epk_free(copy); break; }
            out = no; cap *= 2;
        }
        out[cnt++] = copy;
        s += strlen(s) + 1;
    }
    epk_free(data);
    *n = cnt;
    return out;
}

void epk_db_files_free(char **files, unsigned n)
{
    unsigned i;
    for (i = 0; i < n; i++) epk_free(files[i]);
    epk_free(files);
}

char **epk_db_list(const char *db, unsigned *n)
{
    char sub[512];
    epk_dir d;
    char **out;
    unsigned cap = 32, cnt = 0;
    char name[256];

    *n = 0;
    epk_snprintf(sub, sizeof(sub), "%s/installed", db);
    d = epk_opendir(sub);
    if (!d) return 0;
    out = (char **)epk_malloc(cap * sizeof(char *));
    if (!out) { epk_closedir(d); return 0; }
    while (epk_readdir(d, name, sizeof(name))) {
        if (name[0] == '.') continue;
        if (cnt == cap) {
            char **no = (char **)epk_realloc(out, cap * 2 * sizeof(char *));
            if (!no) break;
            out = no; cap *= 2;
        }
        out[cnt] = (char *)epk_malloc((unsigned)strlen(name) + 1);
        if (!out[cnt]) break;
        strcpy(out[cnt], name);
        cnt++;
    }
    epk_closedir(d);
    *n = cnt;
    return out;
}

/* ------------------------------------------------------------------ */
/* world file                                                          */

static void world_path(const char *db, char *out, unsigned cap)
{
    char t[300];
    epk_snprintf(t, sizeof(t), "%s/world", db);
    epk_strlcpy(out, t, cap);
}

/* shared reader: returns a malloc'd NUL-terminated buffer whose lines
 * are split in place (NUL instead of '\n'); count in *nlines, buffer
 * length in *len_out */
static char *world_read(const char *db, unsigned *nlines, unsigned *len_out)
{
    char path[512];
    uint8_t *data;
    unsigned len, i, nl = 0;

    *nlines = 0;
    *len_out = 0;
    world_path(db, path, sizeof(path));
    data = epk_read_file(path, &len);
    if (!data) return 0;
    for (i = 0; i < len; i++)
        if (data[i] == '\n' || data[i] == '\r') data[i] = 0;
    /* walk NUL-split lines, tolerating empty lines and '#' comments */
    {
        char *s = (char *)data;
        char *end = (char *)data + len;
        while (s < end) {
            if (s[0] != '#' && s[0] != 0) nl++;
            s += strlen(s) + 1;
        }
    }
    *nlines = nl;
    *len_out = len;
    return (char *)data;
}

char **epk_db_world_list(const char *db, unsigned *n)
{
    unsigned nl = 0, len = 0, cnt = 0, cap = 16;
    char *data, *s;
    char **out;

    *n = 0;
    data = world_read(db, &nl, &len);
    if (!data) return 0;
    out = (char **)epk_malloc(cap * sizeof(char *));
    if (!out) { epk_free(data); return 0; }
    s = data;
    {
        char *end = (char *)data + len;
        while (s < end) {
            if (s[0] != '#' && s[0] != 0) {
                if (cnt == cap) {
                    char **no = (char **)epk_realloc(out,
                                        cap * 2 * sizeof(char *));
                    if (!no) break;
                    out = no; cap *= 2;
                }
                out[cnt] = (char *)epk_malloc((unsigned)strlen(s) + 1);
                if (!out[cnt]) break;
                strcpy(out[cnt], s);
                cnt++;
            }
            s += strlen(s) + 1;
        }
    }
    epk_free(data);
    *n = cnt;
    return out;
}

/* rewrite world from the surviving name list (atomic tmp+rename) */
static int world_write(const char *db, char **names, unsigned n)
{
    char path[512], tmp[600];
    epk_buf b;
    unsigned i;
    int rc;

    epk_mkdir_p(db);
    epk_buf_init(&b);
    for (i = 0; i < n; i++) {
        epk_buf_appends(&b, names[i]);
        epk_buf_appendc(&b, '\n');
    }
    world_path(db, path, sizeof(path));
    epk_snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    rc = epk_write_file(tmp, b.p ? (const char *)b.p : "", b.len);
    epk_buf_free(&b);
    if (rc != 0) { epk_unlink(tmp); return -1; }
    if (epk_rename(tmp, path) != 0) { epk_unlink(tmp); return -1; }
    return 0;
}

int epk_db_world_add(const char *db, const char *const *names, unsigned n)
{
    char **cur;
    unsigned ncur, nw, i, k, total;
    char **out;
    int rc;

    cur = epk_db_world_list(db, &ncur);
    total = ncur + n;
    out = (char **)epk_malloc((total ? total : 1) * sizeof(char *));
    if (!out) { epk_db_files_free(cur, ncur); return -1; }
    nw = 0;
    for (i = 0; i < ncur; i++) out[nw++] = cur[i];
    for (k = 0; k < n; k++) {
        int dup = 0;
        for (i = 0; i < nw; i++)
            if (strcmp(out[i], names[k]) == 0) { dup = 1; break; }
        if (!dup) out[nw++] = (char *)names[k];     /* borrowed */
    }
    rc = world_write(db, out, nw);
    epk_free(out);
    epk_db_files_free(cur, ncur);
    return rc;
}

int epk_db_world_del(const char *db, const char *const *names, unsigned n)
{
    char **cur;
    unsigned ncur, i, k, keep = 0;
    char **out;
    int rc;

    cur = epk_db_world_list(db, &ncur);
    if (!cur) return 0;                       /* nothing to delete from */
    out = (char **)epk_malloc((ncur ? ncur : 1) * sizeof(char *));
    if (!out) { epk_db_files_free(cur, ncur); return -1; }
    for (i = 0; i < ncur; i++) {
        int drop = 0;
        for (k = 0; k < n; k++)
            if (strcmp(cur[i], names[k]) == 0) { drop = 1; break; }
        if (!drop) out[keep++] = cur[i];
    }
    rc = world_write(db, out, keep);
    epk_free(out);
    epk_db_files_free(cur, ncur);
    return rc;
}

int epk_db_world_has(const char *db, const char *name)
{
    char **cur;
    unsigned ncur, i;
    int found = 0;

    cur = epk_db_world_list(db, &ncur);
    for (i = 0; cur && i < ncur; i++)
        if (strcmp(cur[i], name) == 0) { found = 1; break; }
    epk_db_files_free(cur, ncur);
    return found;
}
