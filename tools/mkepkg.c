/*
 * mkepkg — build an .epkg package from a directory.
 *
 * usage: mkepkg <pkgdir> [output.epkg]
 *
 * <pkgdir>/PKGINFO must exist with at least pkgname and pkgver.
 * mkepkg computes the content manifest (sha256) over every regular
 * file (sorted paths, PKGINFO excluded) and injects/updates the
 * "sha256 = <hex>" line into the packaged PKGINFO automatically.
 *
 * The archive layout: PKGINFO first, then directories and files in
 * sorted order, tar (ustar) -> gzip -> .epkg.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include "epk_sha256.h"
#include "epk_inflate.h"
#include "epk_util.h"
#include "epk_pkginfo.h"
#include "../include/epk_port.h"

#define MAXFILES 4096

static char  *paths[MAXFILES];
static unsigned npaths;
static char  *lpaths[MAXFILES];   /* symlinks inside the package */
static unsigned nlinks;
static int     oom;

static void say(const char *s) { epk_print(s); }

/* ---------------- recursive directory walk ---------------- */

static void walk(const char *dir, const char *prefix)
{
    epk_dir d = epk_opendir(dir);
    char name[256];

    if (!d) {
        say("mkepkg: cannot open dir ");
        say(dir);
        say("\n");
        oom = 1;
        return;
    }
    while (epk_readdir(d, name, sizeof(name))) {
        char full[512], rel[512];
        struct stat st;

        if (name[0] == '.') continue;            /* skip dotfiles */
        epk_snprintf(full, sizeof(full), "%s/%s", dir, name);
        epk_snprintf(rel, sizeof(rel), "%s%s", prefix, name);

        if (lstat(full, &st) == 0 && S_ISLNK(st.st_mode)) {
            /* symlink: recorded verbatim (target read at tar time) */
            if (nlinks == MAXFILES) {
                say("mkepkg: too many symlinks\n");
                oom = 1;
                return;
            }
            lpaths[nlinks] = (char *)epk_malloc((unsigned)strlen(rel) + 1);
            if (!lpaths[nlinks]) { oom = 1; return; }
            strcpy(lpaths[nlinks], rel);
            nlinks++;
        } else if (epk_is_dir(full)) {
            char sub[512];
            epk_snprintf(sub, sizeof(sub), "%s/", rel);
            walk(full, sub);
        } else {
            if (npaths == MAXFILES) { say("mkepkg: too many files\n"); oom = 1; return; }
            paths[npaths] = (char *)epk_malloc((unsigned)strlen(rel) + 1);
            if (!paths[npaths]) { oom = 1; return; }
            strcpy(paths[npaths], rel);
            npaths++;
        }
    }
    epk_closedir(d);
}

static int cmp_str(const void *a, const void *b)
{
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

/* ---------------- tar writer ---------------- */

typedef struct {
    epk_buf b;
} tarw;

static void tarw_pad(tarw *t, unsigned len)
{
    static const uint8_t zeros[512] = {0};
    unsigned pad = (512 - (len & 511u)) & 511u;
    epk_buf_append(&t->b, zeros, pad);
}

static void put_octal(char *dst, unsigned width, unsigned long v)
{
    char tmp[24];
    int i = 0;
    unsigned pos, j;
    if (v == 0) tmp[i++] = '0';
    while (v) { tmp[i++] = (char)('0' + (int)(v & 7)); v >>= 3; }
    pos = width - (unsigned)i;
    for (j = 0; j < width; j++) dst[j] = '0';
    for (j = 0; j < (unsigned)i; j++)
        dst[pos + j] = tmp[i - 1 - j];
}

static void tarw_header(tarw *t, const char *name, unsigned long size,
                        char type, const char *linkname)
{
    uint8_t hdr[512];
    unsigned sum = 0, i;

    memset(hdr, 0, sizeof(hdr));
    if (strlen(name) >= 100) {
        say("mkepkg: path too long for ustar: ");
        say(name);
        say("\n");
        oom = 1;
        return;
    }
    memcpy(hdr, name, strlen(name));
    memcpy(hdr + 100, "0000644\0", 8);           /* mode */
    memcpy(hdr + 108, "0000000\0", 7);           /* uid */
    memcpy(hdr + 116, "0000000\0", 7);           /* gid */
    put_octal((char *)hdr + 124, 11, size);      /* size */
    memcpy(hdr + 135, "\0", 1);
    put_octal((char *)hdr + 136, 11, 0);         /* mtime */
    memcpy(hdr + 147, "\0", 1);
    memcpy(hdr + 148, "        ", 8);            /* checksum placeholder */
    hdr[156] = (uint8_t)type;
    if (linkname && linkname[0]) {
        if (strlen(linkname) >= 100) {
            say("mkepkg: symlink target too long for ustar: ");
            say(linkname);
            say("\n");
            oom = 1;
            return;
        }
        memcpy(hdr + 157, linkname, strlen(linkname));
    }
    memcpy(hdr + 257, "ustar", 5);
    memcpy(hdr + 263, "00", 2);
    /* name > 100 handled above; prefix unused for short names */

    for (i = 0; i < 512; i++) sum += hdr[i];
    /* store checksum as 6 octal digits + NUL + space */
    {
        unsigned c = sum;
        int k = 0;
        char tmp[8];
        if (c == 0) tmp[k++] = '0';
        while (c) { tmp[k++] = (char)("0"[0] + (int)(c & 7)); c >>= 3; }
        /* 6 chars octal zero-padded */
        {
            unsigned pos = 6 - (unsigned)k, j;
            for (j = 0; j < 6; j++) hdr[148 + j] = '0';
            for (j = 0; j < (unsigned)k; j++)
                hdr[148 + pos + j] = tmp[k - 1 - j];
        }
        hdr[154] = 0;
        hdr[155] = ' ';
    }
    epk_buf_append(&t->b, hdr, 512);
}

/* ---------------- main ---------------- */

int main(int argc, char **argv)
{
    const char *dir, *outpath;
    char pkginfo_disk[512];
    uint8_t *pi_data;
    unsigned pi_len;
    epk_pkginfo pi;
    epk_sha256 manifest;
    uint8_t digest[32];
    char hex[65];
    char *pi_new;
    unsigned pi_new_len;
    tarw t;
    uint8_t *gzbuf;
    unsigned gzlen, outcap;
    char outname[256];
    unsigned i;
    FILE *fp;

    if (argc < 2) {
        say("usage: mkepkg <pkgdir> [output.epkg]\n");
        return 1;
    }
    dir = argv[1];

    epk_snprintf(pkginfo_disk, sizeof(pkginfo_disk), "%s/PKGINFO", dir);
    pi_data = epk_read_file(pkginfo_disk, &pi_len);
    if (!pi_data) {
        say("mkepkg: no PKGINFO in package dir\n");
        return 1;
    }
    (void)pi_len;   /* epk_read_file NUL-terminates */
    if (epk_pkginfo_parse(&pi, (char *)pi_data, pi_len) != 0) {
        say("mkepkg: PKGINFO needs at least pkgname and pkgver\n");
        return 1;
    }
    if (!pi.pkgname[0] || !pi.pkgver[0]) {
        say("mkepkg: PKGINFO needs at least pkgname and pkgver\n");
        return 1;
    }

    /* collect + sort file paths */
    walk(dir, "");
    if (oom) return 1;
    qsort(paths, npaths, sizeof(char *), cmp_str);

    /* manifest hash over all regular files (PKGINFO excluded) */
    epk_sha256_init(&manifest);
    for (i = 0; i < npaths; i++) {
        uint8_t *d;
        unsigned dl;
        char full[512];
        uint8_t lb[4];

        epk_snprintf(full, sizeof(full), "%s/%s", dir, paths[i]);
        if (strcmp(paths[i], "PKGINFO") == 0) continue;
        d = epk_read_file(full, &dl);
        if (!d) { say("mkepkg: cannot read "); say(full); say("\n"); return 1; }
        {
            unsigned pl = (unsigned)strlen(paths[i]);
            lb[0] = (uint8_t)(pl & 0xff);
            lb[1] = (uint8_t)((pl >> 8) & 0xff);
            lb[2] = 0; lb[3] = 0;
            epk_sha256_update(&manifest, lb, 4);
            epk_sha256_update(&manifest, paths[i], pl);
        }
        lb[0] = (uint8_t)(dl & 0xff);
        lb[1] = (uint8_t)((dl >> 8) & 0xff);
        lb[2] = (uint8_t)((dl >> 16) & 0xff);
        lb[3] = (uint8_t)((dl >> 24) & 0xff);
        epk_sha256_update(&manifest, lb, 4);
        epk_sha256_update(&manifest, d, dl);
        epk_free(d);
    }
    epk_sha256_final(&manifest, digest);
    epk_hex(digest, 32, hex);

    /* rebuild PKGINFO with injected/updated sha256 line */
    {
        epk_buf nb;
        char *p = (char *)pi_data;
        int injected = 0;

        epk_buf_init(&nb);
        while (*p) {
            char *eol = strchr(p, '\n');
            char *next = eol ? eol + 1 : p + strlen(p);
            if (eol) *eol = 0;
            if (strncmp(p, "sha256", 6) == 0 &&
                (p[6] == ' ' || p[6] == '=' )) {
                char l[100];
                epk_snprintf(l, sizeof(l), "sha256 = %s\n", hex);
                epk_buf_appends(&nb, l);
                injected = 1;
            } else {
                epk_buf_appends(&nb, p);
                epk_buf_appendc(&nb, '\n');
            }
            if (eol) *eol = '\n';
            p = next;
        }
        if (!injected) {
            char l[100];
            epk_snprintf(l, sizeof(l), "sha256 = %s\n", hex);
            epk_buf_appends(&nb, l);
        }
        epk_buf_appendc(&nb, 0);
        nb.len--;                                /* do not count NUL */
        pi_new = (char *)nb.p;
        pi_new_len = nb.len;
    }

    epk_buf_init(&t.b);

    /* build tar: PKGINFO first, then directories + files sorted */
    {
        char prevdir[512] = "";
        char sizehdr[12];

        epk_snprintf(sizehdr, sizeof(sizehdr), "%011lo",
                     (unsigned long)pi_new_len);
        tarw_header(&t, "PKGINFO", (unsigned long)pi_new_len, '0', 0);
        epk_buf_append(&t.b, pi_new, pi_new_len);
        tarw_pad(&t, pi_new_len);

        for (i = 0; i < npaths; i++) {
            char full[512], ddir[512], cmp[512], *slash;
            unsigned dl2;

            if (strcmp(paths[i], "PKGINFO") == 0) continue;   /* already first */
            epk_snprintf(full, sizeof(full), "%s/%s", dir, paths[i]);

            /* emit missing parent dir entries */
            epk_strlcpy(ddir, paths[i], sizeof(ddir));
            slash = strrchr(ddir, '/');
            if (slash) {
                *slash = 0;
                if (strcmp(ddir, prevdir) != 0) {
                    char dhdr[512];
                    epk_snprintf(dhdr, sizeof(dhdr), "%s/", ddir);
                    tarw_header(&t, dhdr, 0, '5', 0);
                    epk_strlcpy(prevdir, ddir, sizeof(prevdir));
                }
                epk_snprintf(cmp, sizeof(cmp), "%s/", ddir);
            } else {
                prevdir[0] = 0;
            }

            {
                uint8_t *d = epk_read_file(full, &dl2);
                if (!d) {
                    say("mkepkg: cannot read ");
                    say(full);
                    say("\n");
                    return 1;
                }
                tarw_header(&t, paths[i], (unsigned long)dl2, '0', 0);
                epk_buf_append(&t.b, d, dl2);
                tarw_pad(&t, dl2);
                epk_free(d);
            }
            (void)cmp;
        }

        /* symlinks (sorted like files, after regular files) */
        qsort(lpaths, nlinks, sizeof(char *), cmp_str);
        for (i = 0; i < nlinks; i++) {
            char full[512];
            char target[512];
            ssize_t rl;

            epk_snprintf(full, sizeof(full), "%s/%s", dir, lpaths[i]);
            rl = readlink(full, target, sizeof(target) - 1);
            if (rl <= 0) {
                say("mkepkg: cannot readlink ");
                say(full);
                say("\n");
                return 1;
            }
            target[rl] = 0;
            tarw_header(&t, lpaths[i], 0, '2', target);
        }
    }
    {
        static const uint8_t zeros[1024] = {0};
        epk_buf_append(&t.b, zeros, 1024);       /* end-of-archive */
    }

    /* gzip the whole tar */
    outcap = t.b.len + t.b.len / 8 + 4096;
    gzbuf = (uint8_t *)epk_malloc(outcap);
    if (!gzbuf) { say("mkepkg: oom\n"); return 1; }
    gzlen = epk_gz_compress(t.b.p, t.b.len, gzbuf, outcap);
    if (!gzlen) { say("mkepkg: compression failed (output too large?)\n"); return 1; }

    /* output name */
    if (argc >= 3) {
        outpath = argv[2];
    } else {
        char nbuf[128], vbuf[64];
        epk_strlcpy(nbuf, pi.pkgname, sizeof(nbuf));
        epk_strlcpy(vbuf, pi.pkgver, sizeof(vbuf));
        epk_snprintf(outname, sizeof(outname), "%s-%s.epkg", nbuf, vbuf);
        outpath = outname;
    }
    fp = fopen(outpath, "wb");
    if (!fp) { say("mkepkg: cannot create output file\n"); return 1; }
    fwrite(gzbuf, 1, gzlen, fp);
    fclose(fp);

    {
        char msg[600];
        epk_snprintf(msg, sizeof(msg),
                     "built %s (%lu -> %lu bytes, %u files, %u links)\n",
                     outpath, (unsigned long)t.b.len, (unsigned long)gzlen,
                     npaths, nlinks);
        say(msg);
    }
    return 0;
}
