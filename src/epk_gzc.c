/*
 * epk_gzc.c — DEFLATE compressor (fixed Huffman, greedy LZ77 with hash
 * chains) + gzip wrapper. Used by mkepkg on the build host; deliberately
 * simple and dependency-free. Output is fully RFC 1950/1951/1952 valid
 * and inflates with zlib, Info-ZIP and epkg's own decoder alike.
 */
#include "epk_inflate.h"
#include "epk_crc32.h"
#include "epk_libc.h"
#include "../include/epk_port.h"

#define WSIZE      32768u
#define HSIZE      (1u << 15)
#define HMASK      (HSIZE - 1u)
#define MINMATCH   3
#define MAXMATCH   258
#define MAXCHAIN   128

typedef struct {
    const uint8_t *in; unsigned inlen;
    uint8_t *out; unsigned outcap, outlen;
    uint32_t bitbuf; int bitcnt;
    unsigned head[HSIZE];
    int      prev[WSIZE];
    unsigned pos;
    int overflow;
} dfl;

static void putbits(dfl *d, uint32_t v, int n)
{
    d->bitbuf |= v << d->bitcnt;
    d->bitcnt += n;
    while (d->bitcnt >= 8) {
        if (d->outlen < d->outcap) d->out[d->outlen++] = (uint8_t)d->bitbuf;
        else d->overflow = 1;
        d->bitbuf >>= 8;
        d->bitcnt -= 8;
    }
}

/* Huffman codes are packed MSB-first (RFC 1951 §3.1.1); extra bits and
 * other data elements are LSB-first. */
static void putbits_rev(dfl *d, uint32_t v, int n)
{
    int i;
    for (i = n - 1; i >= 0; i--)
        putbits(d, (v >> i) & 1u, 1);
}

/* fixed-huffman literal/length code */
static void put_lit(dfl *d, int sym)
{
    if (sym < 144)      putbits_rev(d, 0x30u + (uint32_t)sym, 8);
    else if (sym < 256) putbits_rev(d, 0x190u + (uint32_t)sym - 144u, 9);
    else if (sym < 280) putbits_rev(d, (uint32_t)(sym - 256), 7);
    else                putbits_rev(d, 0xC0u + (uint32_t)sym - 280u, 8);
}

static void put_dist(dfl *d, int dsym)
{
    putbits_rev(d, (uint32_t)dsym, 5);
}

static const uint16_t lbase[29] = {
    3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,
    163,195,227,258 };
static const uint16_t lext[29] = {
    0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0 };
static const uint16_t dbase[30] = {
    1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,
    2049,3073,4097,6145,8193,12289,16385,24577 };
static const uint16_t dext[30] = {
    0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13 };

static void put_match(dfl *d, unsigned len, unsigned dist)
{
    int li = 28, di = 29;
    while (li > 0 && lbase[li] > (int)len) li--;
    put_lit(d, 257 + li);
    if (lext[li]) putbits(d, len - lbase[li], lext[li]);
    while (di > 0 && dbase[di] > (int)dist) di--;
    put_dist(d, di);
    if (dext[di]) putbits(d, dist - dbase[di], dext[di]);
}

static unsigned match_len(dfl *d, unsigned cur, unsigned cand, unsigned maxlen)
{
    unsigned n = 0;
    while (n < maxlen && d->in[cand + n] == d->in[cur + n]) n++;
    return n;
}

static unsigned find_match(dfl *d, unsigned cur, unsigned *dist_out)
{
    unsigned hash, cand, chain = MAXCHAIN;
    unsigned best = 0, bestdist = 0;
    unsigned maxlen = d->inlen - cur;
    unsigned minpos;

    if (cur + MINMATCH > d->inlen || maxlen < MINMATCH) return 0;
    if (maxlen > MAXMATCH) maxlen = MAXMATCH;

    hash = ((unsigned)d->in[cur] << 10 ^ (unsigned)d->in[cur + 1] << 5 ^
            (unsigned)d->in[cur + 2]) & HMASK;
    cand = d->head[hash];
    minpos = (cur > WSIZE) ? cur - WSIZE : 0;

    while (cand >= minpos && cand < cur && chain--) {
        if (d->in[cand + best] == d->in[cur + best]) {
            unsigned l = match_len(d, cur, cand, maxlen);
            if (l > best) { best = l; bestdist = cur - cand; }
            if (best >= maxlen) break;
        }
        cand = (unsigned)d->prev[cand & (WSIZE - 1u)];
    }
    *dist_out = bestdist;
    return (best >= MINMATCH) ? best : 0;
}

static void insert_hash(dfl *d, unsigned cur)
{
    unsigned hash;
    if (cur + MINMATCH > d->inlen) return;
    hash = ((unsigned)d->in[cur] << 10 ^ (unsigned)d->in[cur + 1] << 5 ^
            (unsigned)d->in[cur + 2]) & HMASK;
    d->prev[cur & (WSIZE - 1u)] = (int)d->head[hash];
    d->head[hash] = cur;
}

static void dfl_reset(dfl *d, const uint8_t *in, unsigned inlen,
                      uint8_t *out, unsigned outcap)
{
    memset(d, 0, sizeof(*d));
    d->in = in; d->inlen = inlen;
    d->out = out; d->outcap = outcap;
}

unsigned epk_gz_compress(const uint8_t *in, unsigned inlen,
                         uint8_t *out, unsigned outcap)
{
    /* heap, not stack: ~288 KB of hash-chain state would blow up
     * small-stack environments (threads in hobby OSes) */
    dfl *dp = (dfl *)epk_malloc(sizeof(dfl));
    dfl *d_ptr = dp;
    unsigned i, gzip_hdr = 10, isize;
    uint32_t crc;
    int rc;

    if (!dp) return 0;
#define d (*d_ptr)

    if (inlen == 0) {
        /* empty gzip stream: 10-byte header, BFINAL=1 BTYPE=01, EOB
         * (3+7 bits = 2 bytes), then CRC+ISIZE (both 0) */
        if (outcap < 20) { epk_free(dp); return 0; }
        memcpy(out, "\x1F\x8B\x08\x00\x00\x00\x00\x00\x00\x03", 10);
        out[10] = 0x03;
        out[11] = 0x00;
        memset(out + 12, 0, 8);
        epk_free(dp);
        return 20;
    }

    dfl_reset(dp, in, inlen, out + gzip_hdr, outcap - gzip_hdr);

    /* block header: final + fixed huffman */
    putbits(&d, 1, 1);
    putbits(&d, 1, 2);

    i = 0;
    while (i < inlen) {
        unsigned dist = 0;
        unsigned len = find_match(dp, i, &dist);
        if (len) {
            put_match(dp, len, dist);
            /* insert every position covered by the match */
            for (; len; len--, i++) insert_hash(dp, i);
        } else {
            put_lit(dp, in[i]);
            insert_hash(dp, i);
            i++;
        }
    }
    put_lit(dp, 256);                          /* EOB */
    putbits(dp, 0, 7);                         /* flush to byte */

    if (dp->overflow) { epk_free(dp); return 0; }

    crc = epk_crc32(0, in, inlen);
    isize = inlen;

    if (dp->outlen + 8 + gzip_hdr > outcap) { epk_free(dp); return 0; }
    memcpy(out, "\x1F\x8B\x08\x00\x00\x00\x00\x00\x00\x03", 10);
    out[dp->outlen + 10]     = (uint8_t)crc;
    out[dp->outlen + 10 + 1] = (uint8_t)(crc >> 8);
    out[dp->outlen + 10 + 2] = (uint8_t)(crc >> 16);
    out[dp->outlen + 10 + 3] = (uint8_t)(crc >> 24);
    out[dp->outlen + 10 + 4] = (uint8_t)isize;
    out[dp->outlen + 10 + 5] = (uint8_t)(isize >> 8);
    out[dp->outlen + 10 + 6] = (uint8_t)(isize >> 16);
    out[dp->outlen + 10 + 7] = (uint8_t)(isize >> 24);

    rc = (int)(gzip_hdr + dp->outlen + 8);
    epk_free(dp);
    return (unsigned)rc;
}
