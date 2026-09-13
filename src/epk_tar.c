/* epk_tar.c — streaming USTAR reader. */
#include "epk_tar.h"
#include "epk_util.h"

void epk_tar_init(epk_tar *t)
{
    memset(t, 0, sizeof(*t));
}

static long pull_bytes(void *ctx, epk_tar_pull pull,
                       uint8_t *dst, unsigned len)
{
    long r = pull(ctx, dst, len);
    return r;
}

static int fill_block(epk_tar *t, void *ctx, epk_tar_pull pull)
{
    while (t->blkpos < 512) {
        long r = pull_bytes(ctx, pull, t->blk + t->blkpos, 512 - t->blkpos);
        if (r < 0) return -1;
        if (r == 0) return (t->blkpos == 0) ? 0 : -1;  /* truncated */
        t->blkpos += (unsigned)r;
    }
    return 1;
}

static int tar_octal(const uint8_t *p, int n, uint64_t *out)
{
    uint64_t v = 0;
    int i, started = 0;
    for (i = 0; i < n; i++) {
        uint8_t c = p[i];
        if (c == 0 || c == ' ') {
            if (started) break;
            continue;
        }
        if (c < '0' || c > '7') return -1;
        started = 1;
        v = v * 8 + (uint64_t)(c - '0');
    }
    *out = v;
    return 0;
}

static int parse_header(epk_tar *t, epk_tar_entry *e)
{
    uint64_t size, mode, mtime, stored;
    unsigned computed = 0, i;
    int allzero = 1;

    for (i = 0; i < 512; i++)
        if (t->blk[i] != 0) { allzero = 0; break; }
    if (allzero) return 0;                          /* end of archive */

    /* stored checksum is an octal NUMBER in bytes 148..155 */
    if (tar_octal(t->blk + 148, 8, &stored) != 0) return -1;
    for (i = 0; i < 512; i++)
        if (i < 148 || i >= 156) computed += t->blk[i];
    computed += 8 * ' ';                            /* checksum field as spaces */
    if (stored != computed) return -1;

    if (tar_octal(t->blk + 124, 12, &size) != 0) return -1;
    if (tar_octal(t->blk + 100, 8, &mode) != 0) mode = 0644;
    if (tar_octal(t->blk + 136, 12, &mtime) != 0) mtime = 0;

    memset(e, 0, sizeof(*e));
    e->size = size;
    e->mode = (unsigned)mode;
    e->mtime = (unsigned)mtime;
    e->type = (char)t->blk[156];
    if (e->type == 0) e->type = '0';
    memcpy(e->link, t->blk + 157, 100);
    e->link[99] = 0;

    /* name = prefix + '/' + name (ustar), else plain */
    {
        unsigned namelen = 0;
        while (namelen < 100 && t->blk[namelen]) namelen++;
        if (memcmp(t->blk + 257, "ustar", 5) == 0) {
            unsigned pfxlen = 0;
            while (pfxlen < 155 && t->blk[345 + pfxlen]) pfxlen++;
            if (pfxlen) {
                unsigned room = (unsigned)sizeof(e->name) - 1;
                unsigned ncopy = pfxlen;
                if (ncopy > room) ncopy = room;
                memcpy(e->name, t->blk + 345, ncopy);
                if (ncopy < room) {
                    e->name[ncopy] = '/';
                    ncopy++;
                    if (ncopy < room) {
                        unsigned n2 = namelen;
                        if (n2 > room - ncopy) n2 = room - ncopy;
                        memcpy(e->name + ncopy, t->blk, n2);
                        ncopy += n2;
                    }
                }
                e->name[ncopy] = 0;
            } else {
                memcpy(e->name, t->blk, namelen);
                e->name[namelen] = 0;
            }
        } else {
            memcpy(e->name, t->blk, namelen);
            e->name[namelen] = 0;
        }
    }
    return 1;
}

int epk_tar_next(epk_tar *t, epk_tar_pull pull, void *ctx, epk_tar_entry *e)
{
    int r;

    if (t->err) return -1;

    /* skip leftover payload + padding of the previous entry */
    if (t->state == 1) {
        if (epk_tar_skip(t, pull, ctx) != 0) { t->err = 1; return -1; }
    }

    for (;;) {
        r = fill_block(t, ctx, pull);
        if (r <= 0) return r;                       /* 0 = EOF, -1 = err */
        t->blkpos = 0;

        r = parse_header(t, e);
        if (r < 0) { t->err = 1; return -1; }
        if (r == 0) { t->state = 2; return 0; }

        /* GNU long name extension */
        if (e->type == 'L') {
            unsigned want = e->size > sizeof(t->longname) - 1
                            ? sizeof(t->longname) - 1 : (unsigned)e->size;
            t->remaining = e->size;
            t->entsize = e->size;
            t->state = 1;
            if (epk_tar_read(t, pull, ctx, (uint8_t *)t->longname, want) < 0 ||
                epk_tar_skip(t, pull, ctx) != 0) {
                t->err = 1;
                return -1;
            }
            t->longname[want] = 0;
            t->has_longname = 1;
            continue;                                /* next header */
        }

        if (t->has_longname) {
            epk_strlcpy(e->name, t->longname, sizeof(e->name));
            t->has_longname = 0;
        }

        t->remaining = e->size;
        t->entsize = e->size;
        t->state = 1;
        return 1;
    }
}

long epk_tar_read(epk_tar *t, epk_tar_pull pull, void *ctx,
                  uint8_t *buf, unsigned len)
{
    unsigned got = 0;

    if (t->err) return -1;
    if (t->state != 1) return -1;
    if (len > t->remaining) len = (unsigned)t->remaining;

    while (got < len) {
        long r = pull_bytes(ctx, pull, buf + got, len - got);
        if (r <= 0) { t->err = 1; return -1; }
        got += (unsigned)r;
        t->remaining -= (unsigned)r;
    }
    return (long)got;
}

int epk_tar_skip(epk_tar *t, epk_tar_pull pull, void *ctx)
{
    uint64_t left;
    uint8_t scratch[512];

    if (t->err) return -1;
    if (t->state != 1) return 0;
    left = t->remaining + ((512u - (t->entsize & 511u)) & 511u);
    while (left) {
        unsigned take = left > sizeof(scratch) ? sizeof(scratch) : (unsigned)left;
        long r = pull_bytes(ctx, pull, scratch, take);
        if (r <= 0) { t->err = 1; return -1; }
        left -= (unsigned)r;
    }
    t->remaining = 0;
    t->entsize = 0;
    t->state = 0;
    return 0;
}
