/*
 * epk_inflate.h — streaming DEFLATE (RFC 1951) decoder + gzip (RFC 1952)
 * decoder, and a small fixed-Huffman DEFLATE compressor used by mkepkg.
 *
 * Freestanding C99; output is pushed to a caller callback, so packages
 * of any size can be extracted with a few KB of RAM.
 *
 * Feed contract: epk_inflate_feed / epk_gz_feed consume as much of the
 * passed chunk as possible; the number of consumed input bytes is
 * returned via the feed structs (field `consumed` after the call).
 * Return: 0 = keep feeding, 1 = stream complete, -1 = corrupt input.
 */
#ifndef EPK_INFLATE_H
#define EPK_INFLATE_H

#include <stdint.h>
#include <stddef.h>

/* return: 1 = chunk accepted, 0 = error (abort) */
typedef int (*epk_inflate_sink)(void *ctx, const uint8_t *data, unsigned len);

typedef struct {
    /* input (set by feed) */
    const uint8_t *in;  unsigned inlen, inpos;

    uint32_t bitbuf; int bitcnt;

    /* stateful huffman symbol decode (resumable across feeds) */
    int d_active, d_code, d_first, d_index, d_len;

    /* output */
    epk_inflate_sink sink; void *ctx;
    uint8_t stage[512]; unsigned stagelen;

    /* LZ77 window (ring) */
    uint8_t win[32768]; unsigned winpos;

    /* current block tables */
    uint16_t counts[16];
    uint16_t symbols[288];
    uint16_t dcounts[16];
    uint16_t dsymbols[32];

    /* pending match state (resumable across feeds) */
    int      m_phase;       /* 0 fresh, 1 len-extra, 2 dist-sym, 3 dist-extra, 4 copy */
    unsigned m_len, m_lbase, m_lext;
    unsigned m_dist, m_dbase, m_dext, m_left;

    /* stored-block state */
    unsigned stored_len;

    /* dynamic header state (progress within the header) */
    int hlit, hdist, hclen, hclc, hn;
    uint8_t clclen[19];
    int  m_reppending, m_rep;   /* pending 16/17/18 repeat */

    int state, final, done, err;
} epk_inflate;

void epk_inflate_init(epk_inflate *inf, epk_inflate_sink sink, void *ctx);

int epk_inflate_feed(epk_inflate *inf, const uint8_t *data, unsigned len);

/* ---------------- gzip container ---------------- */

typedef struct {
    epk_inflate inf;
    epk_inflate_sink real_sink; void *real_ctx;

    uint8_t hbuf[512]; unsigned hpos;
    unsigned flg;

    uint8_t tbuf[8]; unsigned tpos;
    uint32_t crc, outsize;

    int state, err;
} epk_gz;

void epk_gz_init(epk_gz *gz, epk_inflate_sink sink, void *ctx);

/* epk_gz_feed consumes ALL fed bytes (header/trailer/inflate as needed).
 * Returns: 0 = keep feeding, 1 = complete, -1 = corrupt input. */
int epk_gz_feed(epk_gz *gz, const uint8_t *data, unsigned len);

/* ---------------- compressor (fixed Huffman, greedy LZ77) -------- */

/* Compress inlen bytes into a full gzip stream written to out.
 * Returns compressed size, or 0 on error / overflow of outcap. */
unsigned epk_gz_compress(const uint8_t *in, unsigned inlen,
                         uint8_t *out, unsigned outcap);

#endif /* EPK_INFLATE_H */
