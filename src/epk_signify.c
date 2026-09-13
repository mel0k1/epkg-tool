/* epk_signify.c — signify-compatible key/sig files (see epk_signify.h). */
#include "epk_signify.h"
#include "epk_ed25519.h"
#include "epk_sha256.h"
#include "epk_util.h"
#include "../include/epk_port.h"

/* ------------------------------------------------------------------ */
/* shared blob parsing                                                 */

static int check_magic(const uint8_t *blob, unsigned blen, unsigned want)
{
    if (blen != want) return -1;
    if (blob[0] != 'E' || blob[1] != 'd') return -1;
    return 0;
}

/* find the first non-comment, non-empty line and base64-decode it */
static int decode_b64_line(const char *text, unsigned len,
                           uint8_t *out, unsigned cap, unsigned *outlen)
{
    const char *p = text, *end = text + len;
    const char *line, *lend;

    /* line 1: "untrusted comment: ..." (skipped, tolerated to be absent) */
    line = p;
    while (line < end) {
        lend = (const char *)memchr(line, '\n', (size_t)(end - line));
        if (!lend) lend = end;
        /* does the line look like base64? */
        {
            const char *q;
            int n64 = 0;
            for (q = line; q < lend; q++) {
                char c = *q;
                if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                    (c >= '0' && c <= '9') || c == '+' || c == '/' ||
                    c == '=') {
                    n64++;
                }
            }
            if (n64 >= 8 &&
                (lend - line) == n64) {         /* pure base64 line */
                return epk_base64_decode(line, (unsigned)(lend - line),
                                         out, cap, outlen);
            }
        }
        line = lend + 1;
    }
    return -1;
}

static int strip_comment(const char *text, unsigned len,
                         char *out, unsigned cap)
{
    const char *end = text + len;
    const char *lend;
    unsigned n;

    if (epk_has_prefix(text, "untrusted comment:"))
        text += strlen("untrusted comment:");
    while (*text == ' ') text++;
    lend = (const char *)memchr(text, '\n', (size_t)(end - text));
    if (!lend) lend = end;
    n = (unsigned)(lend - text);
    if (n >= cap) n = cap - 1;
    memcpy(out, text, n);
    out[n] = 0;
    return 0;
}

/* ------------------------------------------------------------------ */
/* public keys                                                         */

int epk_signify_pub_parse(const char *text, unsigned len, epk_sig_pub *out)
{
    uint8_t blob[128];
    unsigned blen = 0;

    memset(out, 0, sizeof(*out));
    strip_comment(text, len, out->comment, sizeof(out->comment));
    if (decode_b64_line(text, len, blob, sizeof(blob), &blen) != 0)
        return -1;
    if (check_magic(blob, blen, EPK_SIG_PUB_BLOB) != 0) return -1;
    memcpy(out->keynum, blob + 2, EPK_SIG_KEYNUM_LEN);
    memcpy(out->pub, blob + 2 + EPK_SIG_KEYNUM_LEN, 32);
    return 0;
}

int epk_signify_pub_load(const char *path, epk_sig_pub *out)
{
    uint8_t *data;
    unsigned len;
    int r;

    data = epk_read_file(path, &len);
    if (!data) return -1;
    r = epk_signify_pub_parse((const char *)data, len, out);
    epk_free(data);
    return r;
}

/* ------------------------------------------------------------------ */
/* secret keys                                                         */

int epk_signify_sec_parse(const char *text, unsigned len, epk_sig_sec *out)
{
    uint8_t blob[128];
    unsigned blen = 0;

    memset(out, 0, sizeof(*out));
    if (decode_b64_line(text, len, blob, sizeof(blob), &blen) != 0)
        return -1;
    if (check_magic(blob, blen, EPK_SIG_SEC_BLOB) != 0) return -1;
    memcpy(out->keynum, blob + 2, EPK_SIG_KEYNUM_LEN);
    memcpy(out->seed, blob + 2 + EPK_SIG_KEYNUM_LEN, 32);
    memcpy(out->pub, blob + 2 + EPK_SIG_KEYNUM_LEN + 32, 32);
    return 0;
}

int epk_signify_sec_load(const char *path, epk_sig_sec *out)
{
    uint8_t *data;
    unsigned len;
    int r;

    data = epk_read_file(path, &len);
    if (!data) return -1;
    r = epk_signify_sec_parse((const char *)data, len, out);
    epk_free(data);
    return r;
}

/* ------------------------------------------------------------------ */
/* signatures                                                          */

int epk_signify_sig_parse(const char *text, unsigned len,
                          uint8_t keynum[EPK_SIG_KEYNUM_LEN],
                          uint8_t sig[64])
{
    uint8_t blob[128];
    unsigned blen = 0;

    if (decode_b64_line(text, len, blob, sizeof(blob), &blen) != 0)
        return -1;
    if (check_magic(blob, blen, EPK_SIG_SIG_BLOB) != 0) return -1;
    memcpy(keynum, blob + 2, EPK_SIG_KEYNUM_LEN);
    memcpy(sig, blob + 2 + EPK_SIG_KEYNUM_LEN, 64);
    return 0;
}

int epk_signify_sig_load(const char *path,
                         uint8_t keynum[EPK_SIG_KEYNUM_LEN],
                         uint8_t sig[64])
{
    uint8_t *data;
    unsigned len;
    int r;

    data = epk_read_file(path, &len);
    if (!data) return -1;
    r = epk_signify_sig_parse((const char *)data, len, keynum, sig);
    epk_free(data);
    return r;
}

/* ------------------------------------------------------------------ */
/* verify                                                              */

int epk_signify_verify(const uint8_t pub[32],
                       const void *msg, unsigned msglen,
                       const uint8_t sig[64])
{
    return epk_ed25519_verify(pub, msg, (size_t)msglen, sig) == 0 ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/* key generation                                                      */

/* Read 32 bytes of entropy from /dev/urandom via the port layer. */
static int urandom32(uint8_t *out)
{
    epk_file f = epk_open("/dev/urandom", EPK_O_RDONLY);
    unsigned got = 0;
    if (!f) return -1;
    while (got < 32) {
        int n = epk_read(f, out + got, 32 - got);
        if (n <= 0) break;
        got += (unsigned)n;
    }
    epk_close(f);
    return got == 32 ? 0 : -1;
}

/* Fallback entropy pool: mix epk_seed()/time/ticks/stack through
 * SHA-512 and take 32 bytes. Weak-ish; documented in README. */
static void pool32(uint8_t *out)
{
    epk_sha512 h;
    uint8_t buf[128];
    unsigned i;
    uint32_t w;
    volatile void *sp = (volatile void *)&h;

    memset(buf, 0, sizeof(buf));
    for (i = 0; i < 24; i++) {
        w = epk_seed();
        w ^= w << 13; w ^= w >> 7; w ^= w << 17;
        buf[i * 4]     = (uint8_t)(w & 0xff);
        buf[i * 4 + 1] = (uint8_t)((w >> 8) & 0xff);
        buf[i * 4 + 2] = (uint8_t)((w >> 16) & 0xff);
        buf[i * 4 + 3] = (uint8_t)((w >> 24) & 0xff);
    }
    w = epk_time();
    buf[96] = (uint8_t)w;  buf[97] = (uint8_t)(w >> 8);
    w = epk_ticks();
    buf[98] = (uint8_t)w;  buf[99] = (uint8_t)(w >> 8);
    buf[100] = (uint8_t)((size_t)sp & 0xff);
    buf[101] = (uint8_t)(((size_t)sp >> 8) & 0xff);
    epk_sha512_buf(buf, sizeof(buf), out);
    memset(buf, 0, sizeof(buf));
}

void epk_signify_keygen(uint8_t seed[32], uint8_t pub[32],
                        uint8_t keynum[EPK_SIG_KEYNUM_LEN])
{
    uint8_t tmp[32];

    if (urandom32(seed) != 0) {
        pool32(seed);
        pool32(tmp);
        {   /* stir both pools once more */
            epk_sha512 h;
            uint8_t m[64], out[64];
            memcpy(m, seed, 32);
            memcpy(m + 32, tmp, 32);
            epk_sha512_init(&h);
            epk_sha512_update(&h, m, sizeof(m));
            epk_sha512_final(&h, out);
            memcpy(seed, out, 32);
            memset(m, 0, sizeof(m));
            memset(out, 0, sizeof(out));
        }
    }
    if (urandom32(keynum) != 0) pool32(keynum);
    epk_ed25519_pubkey(seed, pub);
    memset(tmp, 0, sizeof(tmp));
}

/* ------------------------------------------------------------------ */
/* writers                                                             */

static int write_two_lines(const char *path, const char *comment,
                           const uint8_t *blob, unsigned blen)
{
    char b64[160], out[512];
    int n;

    if (epk_base64_encode(blob, blen, b64, sizeof(b64)) < 0) return -1;
    n = epk_snprintf(out, sizeof(out),
                     "untrusted comment: %s\n%s\n",
                     comment ? comment : "", b64);
    if (n < 0) return -1;
    return epk_write_file(path, out, (unsigned)n);
}

int epk_signify_write_pub(const char *path, const char *comment,
                          const uint8_t keynum[EPK_SIG_KEYNUM_LEN],
                          const uint8_t pub[32])
{
    uint8_t blob[EPK_SIG_PUB_BLOB];
    blob[0] = 'E'; blob[1] = 'd';
    memcpy(blob + 2, keynum, EPK_SIG_KEYNUM_LEN);
    memcpy(blob + 2 + EPK_SIG_KEYNUM_LEN, pub, 32);
    return write_two_lines(path, comment, blob, sizeof(blob));
}

int epk_signify_write_sec(const char *path, const char *comment,
                          const uint8_t keynum[EPK_SIG_KEYNUM_LEN],
                          const uint8_t seed[32], const uint8_t pub[32])
{
    uint8_t blob[EPK_SIG_SEC_BLOB];
    blob[0] = 'E'; blob[1] = 'd';
    memcpy(blob + 2, keynum, EPK_SIG_KEYNUM_LEN);
    memcpy(blob + 2 + EPK_SIG_KEYNUM_LEN, seed, 32);
    memcpy(blob + 2 + EPK_SIG_KEYNUM_LEN + 32, pub, 32);
    return write_two_lines(path, comment, blob, sizeof(blob));
}

int epk_signify_write_sig(const char *path, const char *comment,
                          const uint8_t keynum[EPK_SIG_KEYNUM_LEN],
                          const uint8_t sig[64])
{
    uint8_t blob[EPK_SIG_SIG_BLOB];
    blob[0] = 'E'; blob[1] = 'd';
    memcpy(blob + 2, keynum, EPK_SIG_KEYNUM_LEN);
    memcpy(blob + 2 + EPK_SIG_KEYNUM_LEN, sig, 64);
    return write_two_lines(path, comment, blob, sizeof(blob));
}
