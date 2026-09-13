/*
 * epk_inflate.c — streaming DEFLATE decoder + gzip decoder + fixed-Huffman
 * compressor. Algorithm style follows classic "tinf" (J. Ibsen, public
 * domain), rewritten as a resumable streaming state machine.
 */
#include "epk_inflate.h"
#include "epk_crc32.h"
#include "epk_libc.h"

/* ------------------------------------------------------------------ */
/* atomic bit reads: consume all requested bits or none                */

static int bits_need(epk_inflate *inf, int need)
{
    while (inf->bitcnt < need) {
        if (inf->inpos >= inf->inlen) return -1;
        inf->bitbuf |= (uint32_t)inf->in[inf->inpos++] << inf->bitcnt;
        inf->bitcnt += 8;
    }
    {
        int v = (int)(inf->bitbuf & ((1u << need) - 1u));
        inf->bitbuf >>= need;
        inf->bitcnt -= need;
        return v;
    }
}

/* ------------------------------------------------------------------ */
/* canonical huffman tree (counts + sorted symbols)                    */

static int build_tree(uint16_t *counts, uint16_t *symbols,
                      const uint8_t *lengths, int n)
{
    int i, sum = 0, offs[16];

    for (i = 0; i < 16; i++) counts[i] = 0;
    for (i = 0; i < n; i++) counts[lengths[i]]++;
    counts[0] = 0;
    for (i = 1; i < 16; i++) {
        sum += counts[i];
        if (sum > (1 << i)) return -1;          /* over-subscribed */
    }
    if (sum == 0) return 1;                     /* empty tree (ok for dist) */

    offs[1] = 0;
    for (i = 1; i < 15; i++) offs[i + 1] = offs[i] + counts[i];
    for (i = 0; i < n; i++)
        if (lengths[i]) symbols[offs[lengths[i]]++] = (uint16_t)i;
    return 0;
}

/* resumable symbol decode: keeps partial code state across feeds      */
static int decode_sym(epk_inflate *inf,
                      const uint16_t *counts, const uint16_t *symbols)
{
    if (!inf->d_active) {
        inf->d_code = 0; inf->d_first = 0; inf->d_index = 0; inf->d_len = 0;
        inf->d_active = 1;
    }
    for (;;) {
        int b;
        if (inf->bitcnt == 0) {
            if (inf->inpos >= inf->inlen) return -1;   /* need more input */
            inf->bitbuf |= (uint32_t)inf->in[inf->inpos++] << inf->bitcnt;
            inf->bitcnt += 8;
        }
        b = (int)(inf->bitbuf & 1u);
        inf->bitbuf >>= 1;
        inf->bitcnt--;

        inf->d_code = (inf->d_code << 1) | b;
        inf->d_len++;
        {
            int count = counts[inf->d_len];
            if (inf->d_code - inf->d_first < count) {
                int sym = symbols[inf->d_index + (inf->d_code - inf->d_first)];
                inf->d_active = 0;
                return sym;
            }
            inf->d_index += count;
            inf->d_first = (inf->d_first + count) << 1;
        }
        if (inf->d_len >= 15) { inf->d_active = 0; return -2; }
    }
}

/* ------------------------------------------------------------------ */
/* tables                                                              */

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

static const uint8_t clcidx[19] = {
    16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15 };

/* ------------------------------------------------------------------ */
/* output                                                              */

static int flush_stage(epk_inflate *inf)
{
    if (inf->stagelen) {
        if (!inf->sink(inf->ctx, inf->stage, inf->stagelen)) return -1;
        inf->stagelen = 0;
    }
    return 0;
}

static int emit_byte(epk_inflate *inf, uint8_t b)
{
    inf->win[inf->winpos & 32767u] = b;
    inf->winpos++;
    inf->stage[inf->stagelen++] = b;
    if (inf->stagelen == sizeof(inf->stage)) {
        if (!inf->sink(inf->ctx, inf->stage, inf->stagelen)) return -1;
        inf->stagelen = 0;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* fixed tables (built lazily)                                         */

static uint8_t fixed_litlen[288];
static uint8_t fixed_distl[30];
static int fixed_ready = 0;

static void build_fixed(void)
{
    int i;
    if (fixed_ready) return;
    for (i = 0; i < 144; i++) fixed_litlen[i] = 8;
    for (i = 144; i < 256; i++) fixed_litlen[i] = 9;
    for (i = 256; i < 280; i++) fixed_litlen[i] = 7;
    for (i = 280; i < 288; i++) fixed_litlen[i] = 8;
    for (i = 0; i < 30; i++) fixed_distl[i] = 5;
    fixed_ready = 1;
}

/* ------------------------------------------------------------------ */

enum {
    S_HDR = 0, S_STORED_LEN, S_STORED_NLEN, S_STORED_COPY,
    S_BODY, S_DONE, S_DYNHDR
};

static int dyn_header(epk_inflate *inf);

static int inflate_body(epk_inflate *inf)
{
    for (;;) {
        /* phase 4: finish pending match copy (needs no input) */
        if (inf->m_phase == 4) {
            if (flush_stage(inf) != 0) return -1;
            while (inf->m_left) {
                uint8_t b = inf->win[(inf->winpos - inf->m_dist) & 32767u];
                if (emit_byte(inf, b) != 0) return -1;
                inf->m_left--;
            }
            inf->m_phase = 0;
        }

        if (inf->m_phase == 0) {
            int sym = decode_sym(inf, inf->counts, inf->symbols);
            if (sym == -1) return 0;                 /* need more input */
            if (sym < 0) return -1;

            if (sym < 256) {
                if (emit_byte(inf, (uint8_t)sym) != 0) return -1;
                continue;
            }
            if (sym == 256) {
                if (flush_stage(inf) != 0) return -1;
                /* EOB ends the block; final flag ends the stream */
                inf->state = inf->final ? S_DONE : S_HDR;
                return 0;
            }
            {
                int li = sym - 257;
                if (li >= 29) return -1;
                inf->m_lbase = lbase[li];
                inf->m_lext = lext[li];
                inf->m_len = lbase[li];
                inf->m_phase = 1;
            }
        }

        if (inf->m_phase == 1) {                     /* length extra bits */
            if (inf->m_lext) {
                int e = bits_need(inf, (int)inf->m_lext);
                if (e < 0) return 0;
                inf->m_len += (unsigned)e;
            }
            inf->m_phase = 2;
        }

        if (inf->m_phase == 2) {                     /* distance symbol */
            int dsym = decode_sym(inf, inf->dcounts, inf->dsymbols);
            if (dsym == -1) return 0;
            if (dsym < 0 || dsym >= 30) return -1;
            inf->m_dbase = dbase[dsym];
            inf->m_dext = dext[dsym];
            inf->m_dist = dbase[dsym];
            inf->m_phase = 3;
        }

        if (inf->m_phase == 3) {                     /* distance extra bits */
            if (inf->m_dext) {
                int e = bits_need(inf, (int)inf->m_dext);
                if (e < 0) return 0;
                inf->m_dist += (unsigned)e;
            }
            if (inf->m_dist > inf->winpos) return -1;  /* before start */
            inf->m_left = inf->m_len;
            inf->m_phase = 4;
        }
    }
}

static int inflate_step(epk_inflate *inf)
{
    switch (inf->state) {
    case S_HDR: {
        /* read BFINAL + BTYPE atomically so a chunk break cannot
         * split the header (bits_need is all-or-nothing) */
        int v = bits_need(inf, 3);
        int final, type;
        if (v < 0) return 0;
        final = v & 1;
        type = (v >> 1) & 3;
        inf->final = final;
        if (type == 0) {
            inf->bitcnt = 0; inf->bitbuf = 0;
            inf->state = S_STORED_LEN;
            return 1;
        } else if (type == 1) {
            build_fixed();
            if (build_tree(inf->counts, inf->symbols, fixed_litlen, 288) != 0)
                return -1;
            if (build_tree(inf->dcounts, inf->dsymbols, fixed_distl, 30) != 0)
                return -1;
            inf->state = S_BODY;
            return 1;
        } else if (type == 2) {
            /* fresh dynamic block: reset per-header progress */
            inf->hlit = 0; inf->hdist = 0; inf->hclen = 0;
            inf->hclc = 0; inf->hn = 0;
            inf->m_reppending = 0;
            inf->state = S_DYNHDR;       /* resume must not re-read hdr */
            return 1;
        }
        return -1;
    }
    case S_DYNHDR: {
        int r = dyn_header(inf);
        if (r < 0) return -1;
        if (r == 0) return 0;
        inf->state = S_BODY;
        return 1;
    }
    case S_STORED_LEN: {
        int v = bits_need(inf, 16);
        if (v < 0) return 0;
        inf->stored_len = (unsigned)v;
        inf->state = S_STORED_NLEN;
        return 1;
    }
    case S_STORED_NLEN: {
        int v = bits_need(inf, 16);
        if (v < 0) return 0;
        if (((v ^ 0xFFFFu) & 0xFFFFu) != inf->stored_len) return -1;
        if (inf->stored_len) inf->state = S_STORED_COPY;
        else if (inf->final) { inf->done = 1; inf->state = S_DONE; }
        else inf->state = S_HDR;
        return 1;
    }
    case S_STORED_COPY: {
        while (inf->stored_len) {
            unsigned take;
            if (inf->inpos >= inf->inlen) return 0;
            take = inf->inlen - inf->inpos;
            if (take > inf->stored_len) take = inf->stored_len;
            if (take > 512) take = 512;
            if (flush_stage(inf) != 0) return -1;
            if (!inf->sink(inf->ctx, inf->in + inf->inpos, take)) return -1;
            {
                unsigned i;
                for (i = 0; i < take; i++)
                    inf->win[inf->winpos++ & 32767u] = inf->in[inf->inpos + i];
            }
            inf->inpos += take;
            inf->stored_len -= take;
        }
        if (inf->final) {
            inf->done = 1;
            inf->state = S_DONE;
        } else {
            inf->state = S_HDR;
        }
        return 1;
    }
    case S_BODY: {
        int r = inflate_body(inf);
        if (r < 0) return -1;
        if (inf->state == S_DONE) {
            inf->done = 1;
            return 1;
        }
        if (inf->state == S_HDR)
            return 1;                /* block ended, continue with next */
        return 0;
    }
    case S_DONE:
        inf->done = 1;
        return 1;
    }
    return -1;
}

void epk_inflate_init(epk_inflate *inf, epk_inflate_sink sink, void *ctx)
{
    memset(inf, 0, sizeof(*inf));
    inf->sink = sink;
    inf->ctx = ctx;
}

int epk_inflate_feed(epk_inflate *inf, const uint8_t *data, unsigned len)
{
    if (inf->err) return -1;
    if (inf->done) return 1;
    inf->in = data;
    inf->inlen = len;
    inf->inpos = 0;
    for (;;) {
        int r = inflate_step(inf);
        if (r < 0) { inf->err = 1; return -1; }
        if (r == 0) return 0;
        if (inf->done) return 1;
    }
}

/* ------------------------------------------------------------------ */
/* dynamic block header (resumable across feeds)                       */

static int dyn_header(epk_inflate *inf)
{
    /* litlen and dist lengths form ONE continuous sequence (RFC 1951):
     * repeats may span the boundary, so keep a single array. */
    static uint8_t lens[288 + 32];
    uint16_t clccounts[16];
    uint16_t clcsymbols[19];
    int r;

    if (inf->hlit == 0) {
        int v = bits_need(inf, 5);
        if (v < 0) return 0;
        inf->hlit = v + 257;
        if (inf->hlit > 288) return -1;
    }
    if (inf->hdist == 0) {
        int v = bits_need(inf, 5);
        if (v < 0) return 0;
        inf->hdist = v + 1;
        if (inf->hdist > 30) return -1;
    }
    if (inf->hclen == 0) {
        int v = bits_need(inf, 4);
        if (v < 0) return 0;
        inf->hclen = v + 4;
    }

    while (inf->hclc < inf->hclen) {
        int v = bits_need(inf, 3);
        if (v < 0) return 0;
        inf->clclen[clcidx[inf->hclc]] = (uint8_t)v;
        inf->hclc++;
    }
    if (build_tree(clccounts, clcsymbols, inf->clclen, 19) != 0) return -1;

    while (inf->hn < inf->hlit + inf->hdist) {
        int sym, rep, val = 0, cnt, j;

        if (!inf->m_reppending) {
            sym = decode_sym(inf, clccounts, clcsymbols);
            if (sym == -1) return 0;
            if (sym < 0) return -1;
            if (sym < 16) {
                lens[inf->hn] = (uint8_t)sym;
                inf->hn++;
                continue;
            }
            if (sym == 16 && inf->hn == 0) return -1;
            inf->m_rep = sym;
            inf->m_reppending = 1;
        }
        sym = inf->m_rep;
        cnt = bits_need(inf, (sym == 16) ? 2 : (sym == 17) ? 3 : 7);
        if (cnt < 0) return 0;                    /* atomic: retry next feed */
        inf->m_reppending = 0;
        rep = (sym == 16) ? 3 + cnt : (sym == 17) ? 3 + cnt : 11 + cnt;
        if (sym == 16) {
            if (inf->hn == 0) return -1;
            val = lens[inf->hn - 1];
        }
        if (inf->hn + rep > inf->hlit + inf->hdist) return -1;
        for (j = 0; j < rep; j++) {
            lens[inf->hn] = (uint8_t)val;
            inf->hn++;
        }
    }
    if (lens[256] == 0) return -1;

    r = build_tree(inf->counts, inf->symbols, lens, inf->hlit);
    if (r != 0) return -1;
    r = build_tree(inf->dcounts, inf->dsymbols, lens + inf->hlit, inf->hdist);
    if (r < 0) return -1;
    return 1;
}

/* ================================================================== */
/* gzip                                                                */

enum { G_HDR = 0, G_CM, G_FLG, G_FIXED, G_XLEN, G_EXTRA, G_NAME,
       G_COMMENT, G_HCRC, G_BODY, G_TRAILER, G_DONE };

static int gz_out_sink(void *ctx, const uint8_t *d, unsigned n)
{
    epk_gz *gz = (epk_gz *)ctx;
    gz->crc = epk_crc32(gz->crc, d, n);
    gz->outsize += n;
    return gz->real_sink(gz->real_ctx, d, n);
}

void epk_gz_init(epk_gz *gz, epk_inflate_sink sink, void *ctx)
{
    memset(gz, 0, sizeof(*gz));
    gz->real_sink = sink;
    gz->real_ctx = ctx;
    epk_inflate_init(&gz->inf, gz_out_sink, gz);
    gz->state = G_HDR;
}

/* take n header bytes; returns 0 if the chunk ran out first */
static int take_bytes(epk_gz *gz, const uint8_t **data, unsigned *len,
                      unsigned n)
{
    while (gz->hpos < n) {
        if (!*len) return 0;
        gz->hbuf[gz->hpos++] = *(*data)++;
        (*len)--;
    }
    return 1;
}

/* skip NUL-terminated string from the raw stream */
static int take_cstr(epk_gz *gz, const uint8_t **data, unsigned *len)
{
    for (;;) {
        uint8_t c;
        if (!*len) return 0;
        c = *(*data)++;
        (*len)--;
        if (gz->hpos < sizeof(gz->hbuf)) gz->hbuf[gz->hpos] = c;
        if (c == 0) return 1;
    }
}

int epk_gz_feed(epk_gz *gz, const uint8_t *data, unsigned len)
{
    if (gz->err) return -1;
    if (gz->state == G_DONE) return 1;

    while (len) {
        switch (gz->state) {
        case G_HDR:
            if (!take_bytes(gz, &data, &len, 2)) return 0;
            if (gz->hbuf[0] != 0x1F || gz->hbuf[1] != 0x8B) { gz->err = 1; return -1; }
            gz->hpos = 0;
            gz->state = G_CM;
            break;
        case G_CM:
            if (!take_bytes(gz, &data, &len, 1)) return 0;
            if (gz->hbuf[0] != 8) { gz->err = 1; return -1; }
            gz->hpos = 0;
            gz->state = G_FLG;
            break;
        case G_FLG:
            if (!take_bytes(gz, &data, &len, 1)) return 0;
            gz->flg = gz->hbuf[0];
            if (gz->flg & 0xE0) { gz->err = 1; return -1; }  /* reserved */
            gz->hpos = 0;
            gz->state = G_FIXED;
            break;
        case G_FIXED:
            if (!take_bytes(gz, &data, &len, 6)) return 0;   /* mtime+xfl+os */
            gz->hpos = 0;
            if (gz->flg & 0x04)      { gz->state = G_XLEN; }
            else if (gz->flg & 0x08) { gz->state = G_NAME; }
            else if (gz->flg & 0x10) { gz->state = G_COMMENT; }
            else if (gz->flg & 0x02) { gz->state = G_HCRC; }
            else                     { gz->state = G_BODY; epk_inflate_init(&gz->inf, gz_out_sink, gz); }
            break;
        case G_XLEN:
            if (!take_bytes(gz, &data, &len, 2)) return 0;
            gz->hpos = 0;
            if (gz->hbuf[0] | gz->hbuf[1]) { gz->state = G_EXTRA; }
            else if (gz->flg & 0x08) { gz->state = G_NAME; }
            else if (gz->flg & 0x10) { gz->state = G_COMMENT; }
            else if (gz->flg & 0x02) { gz->state = G_HCRC; }
            else { gz->state = G_BODY; epk_inflate_init(&gz->inf, gz_out_sink, gz); }
            break;
        case G_EXTRA:
            if (!take_bytes(gz, &data, &len, 2 + (gz->hbuf[0] | ((unsigned)gz->hbuf[1] << 8))))
                return 0;
            gz->hpos = 0;
            if (gz->flg & 0x08)      { gz->state = G_NAME; }
            else if (gz->flg & 0x10) { gz->state = G_COMMENT; }
            else if (gz->flg & 0x02) { gz->state = G_HCRC; }
            else { gz->state = G_BODY; epk_inflate_init(&gz->inf, gz_out_sink, gz); }
            break;
        case G_NAME:
            if (!take_cstr(gz, &data, &len)) return 0;
            gz->hpos = 0;
            if (gz->flg & 0x10)      { gz->state = G_COMMENT; }
            else if (gz->flg & 0x02) { gz->state = G_HCRC; }
            else { gz->state = G_BODY; epk_inflate_init(&gz->inf, gz_out_sink, gz); }
            break;
        case G_COMMENT:
            if (!take_cstr(gz, &data, &len)) return 0;
            gz->hpos = 0;
            if (gz->flg & 0x02)      { gz->state = G_HCRC; }
            else { gz->state = G_BODY; epk_inflate_init(&gz->inf, gz_out_sink, gz); }
            break;
        case G_HCRC:
            if (!take_bytes(gz, &data, &len, 2)) return 0;
            gz->hpos = 0;
            gz->state = G_BODY;
            epk_inflate_init(&gz->inf, gz_out_sink, gz);
            break;
        case G_BODY: {
            int r = epk_inflate_feed(&gz->inf, data, len);
            if (r < 0) { gz->err = 1; return -1; }
            data += gz->inf.inpos;
            len -= gz->inf.inpos;
            if (r == 1) {
                gz->tpos = 0;
                gz->state = G_TRAILER;
            } else {
                return 0;
            }
            break;
        }
        case G_TRAILER: {
            while (gz->tpos < 8 && len) {
                gz->tbuf[gz->tpos++] = *data++;
                len--;
            }
            if (gz->tpos < 8) return 0;
            {
                uint32_t crc = (uint32_t)gz->tbuf[0] |
                               ((uint32_t)gz->tbuf[1] << 8) |
                               ((uint32_t)gz->tbuf[2] << 16) |
                               ((uint32_t)gz->tbuf[3] << 24);
                uint32_t sz = (uint32_t)gz->tbuf[4] |
                              ((uint32_t)gz->tbuf[5] << 8) |
                              ((uint32_t)gz->tbuf[6] << 16) |
                              ((uint32_t)gz->tbuf[7] << 24);
                if (crc != gz->crc || sz != gz->outsize) { gz->err = 1; return -1; }
                gz->state = G_DONE;
                return 1;
            }
        }
        default:
            gz->err = 1;
            return -1;
        }
    }
    return 0;
}
