/* epk_sha256.c — SHA-256 / SHA-384 / SHA-512 / HMAC-SHA256 (FIPS 180-4). */
#include "epk_sha256.h"
#include "epk_libc.h"

static uint32_t ror32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

static const uint32_t K256[64] = {
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2 };

static uint32_t ld32be(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void st32be(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
}

static void sha256_block(uint32_t h[8], const uint8_t *p)
{
    uint32_t w[64], a, b, c, d, e, f, g, hh, t1, t2;
    int i;
    for (i = 0; i < 16; i++) w[i] = ld32be(p + i * 4);
    for (i = 16; i < 64; i++) {
        uint32_t s0 = ror32(w[i-15], 7) ^ ror32(w[i-15], 18) ^ (w[i-15] >> 3);
        uint32_t s1 = ror32(w[i-2], 17) ^ ror32(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a=h[0]; b=h[1]; c=h[2]; d=h[3]; e=h[4]; f=h[5]; g=h[6]; hh=h[7];
    for (i = 0; i < 64; i++) {
        uint32_t S1 = ror32(e,6) ^ ror32(e,11) ^ ror32(e,25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t S0 = ror32(a,2) ^ ror32(a,13) ^ ror32(a,22);
        uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
        t1 = hh + S1 + ch + K256[i] + w[i];
        t2 = S0 + mj;
        hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
}

void epk_sha256_init(epk_sha256 *c)
{
    c->h[0]=0x6a09e667; c->h[1]=0xbb67ae85; c->h[2]=0x3c6ef372; c->h[3]=0xa54ff53a;
    c->h[4]=0x510e527f; c->h[5]=0x9b05688c; c->h[6]=0x1f83d9ab; c->h[7]=0x5be0cd19;
    c->len = 0; c->buflen = 0;
}

void epk_sha256_update(epk_sha256 *c, const void *data, size_t n)
{
    const uint8_t *p = (const uint8_t *)data;
    c->len += n;
    if (c->buflen) {
        size_t take = 64 - c->buflen;
        if (take > n) take = n;
        memcpy(c->buf + c->buflen, p, take);
        c->buflen += take; p += take; n -= take;
        if (c->buflen == 64) { sha256_block(c->h, c->buf); c->buflen = 0; }
    }
    while (n >= 64) { sha256_block(c->h, p); p += 64; n -= 64; }
    if (n) { memcpy(c->buf, p, n); c->buflen = n; }
}

void epk_sha256_final(epk_sha256 *c, uint8_t out[32])
{
    uint64_t bits = c->len * 8;
    uint8_t pad[72];
    size_t plen;
    int i;

    plen = (c->buflen < 56) ? 56 - c->buflen : 120 - c->buflen;
    memset(pad, 0, sizeof(pad));
    pad[0] = 0x80;
    st32be(pad + plen, (uint32_t)(bits >> 32));
    st32be(pad + plen + 4, (uint32_t)bits);
    epk_sha256_update(c, pad, plen + 8);
    for (i = 0; i < 8; i++) st32be(out + i * 4, c->h[i]);
}

void epk_sha256_buf(const void *data, size_t n, uint8_t out[32])
{
    epk_sha256 c;
    epk_sha256_init(&c);
    epk_sha256_update(&c, data, n);
    epk_sha256_final(&c, out);
}

/* ---------------- SHA-512/384 ---------------- */

static const uint64_t K512[80] = {
0x428a2f98d728ae22ULL,0x7137449123ef65cdULL,0xb5c0fbcfec4d3b2fULL,0xe9b5dba58189dbbcULL,
0x3956c25bf348b538ULL,0x59f111f1b605d019ULL,0x923f82a4af194f9bULL,0xab1c5ed5da6d8118ULL,
0xd807aa98a3030242ULL,0x12835b0145706fbeULL,0x243185be4ee4b28cULL,0x550c7dc3d5ffb4e2ULL,
0x72be5d74f27b896fULL,0x80deb1fe3b1696b1ULL,0x9bdc06a725c71235ULL,0xc19bf174cf692694ULL,
0xe49b69c19ef14ad2ULL,0xefbe4786384f25e3ULL,0x0fc19dc68b8cd5b5ULL,0x240ca1cc77ac9c65ULL,
0x2de92c6f592b0275ULL,0x4a7484aa6ea6e483ULL,0x5cb0a9dcbd41fbd4ULL,0x76f988da831153b5ULL,
0x983e5152ee66dfabULL,0xa831c66d2db43210ULL,0xb00327c898fb213fULL,0xbf597fc7beef0ee4ULL,
0xc6e00bf33da88fc2ULL,0xd5a79147930aa725ULL,0x06ca6351e003826fULL,0x142929670a0e6e70ULL,
0x27b70a8546d22ffcULL,0x2e1b21385c26c926ULL,0x4d2c6dfc5ac42aedULL,0x53380d139d95b3dfULL,
0x650a73548baf63deULL,0x766a0abb3c77b2a8ULL,0x81c2c92e47edaee6ULL,0x92722c851482353bULL,
0xa2bfe8a14cf10364ULL,0xa81a664bbc423001ULL,0xc24b8b70d0f89791ULL,0xc76c51a30654be30ULL,
0xd192e819d6ef5218ULL,0xd69906245565a910ULL,0xf40e35855771202aULL,0x106aa07032bbd1b8ULL,
0x19a4c116b8d2d0c8ULL,0x1e376c085141ab53ULL,0x2748774cdf8eeb99ULL,0x34b0bcb5e19b48a8ULL,
0x391c0cb3c5c95a63ULL,0x4ed8aa4ae3418acbULL,0x5b9cca4f7763e373ULL,0x682e6ff3d6b2b8a3ULL,
0x748f82ee5defb2fcULL,0x78a5636f43172f60ULL,0x84c87814a1f0ab72ULL,0x8cc702081a6439ecULL,
0x90befffa23631e28ULL,0xa4506cebde82bde9ULL,0xbef9a3f7b2c67915ULL,0xc67178f2e372532bULL,
0xca273eceea26619cULL,0xd186b8c721c0c207ULL,0xeada7dd6cde0eb1eULL,0xf57d4f7fee6ed178ULL,
0x06f067aa72176fbaULL,0x0a637dc5a2c898a6ULL,0x113f9804bef90daeULL,0x1b710b35131c471bULL,
0x28db77f523047d84ULL,0x32caab7b40c72493ULL,0x3c9ebe0a15c9bebcULL,0x431d67c49c100d4cULL,
0x4cc5d4becb3e42b6ULL,0x597f299cfc657e2aULL,0x5fcb6fab3ad6faecULL,0x6c44198c4a475817ULL };

static uint64_t ror64(uint64_t x, int n) { return (x >> n) | (x << (64 - n)); }

static uint64_t ld64be(const uint8_t *p)
{
    int i; uint64_t v = 0;
    for (i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}

static void st64be(uint8_t *p, uint64_t v)
{
    int i;
    for (i = 7; i >= 0; i--) { p[i] = (uint8_t)v; v >>= 8; }
}

static void sha512_block(uint64_t h[8], const uint8_t *p)
{
    uint64_t w[80], a,b,c,d,e,f,g,hh,t1,t2;
    int i;
    for (i = 0; i < 16; i++) w[i] = ld64be(p + i * 8);
    for (i = 16; i < 80; i++) {
        uint64_t s0 = ror64(w[i-15],1) ^ ror64(w[i-15],8) ^ (w[i-15] >> 7);
        uint64_t s1 = ror64(w[i-2],19) ^ ror64(w[i-2],61) ^ (w[i-2] >> 6);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a=h[0];b=h[1];c=h[2];d=h[3];e=h[4];f=h[5];g=h[6];hh=h[7];
    for (i = 0; i < 80; i++) {
        uint64_t S1 = ror64(e,14) ^ ror64(e,18) ^ ror64(e,41);
        uint64_t ch = (e & f) ^ (~e & g);
        uint64_t S0 = ror64(a,28) ^ ror64(a,34) ^ ror64(a,39);
        uint64_t mj = (a & b) ^ (a & c) ^ (b & c);
        t1 = hh + S1 + ch + K512[i] + w[i];
        t2 = S0 + mj;
        hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
}

static void sha512_common_init(uint64_t h[8], int is384)
{
    if (is384) {
        h[0]=0xcbbb9d5dc1059ed8ULL; h[1]=0x629a292a367cd507ULL;
        h[2]=0x9159015a3070dd17ULL; h[3]=0x152fecd8f70e5939ULL;
        h[4]=0x67332667ffc00b31ULL; h[5]=0x8eb44a8768581511ULL;
        h[6]=0xdb0c2e0d64f98fa7ULL; h[7]=0x47b5481dbefa4fa4ULL;
    } else {
        h[0]=0x6a09e667f3bcc908ULL; h[1]=0xbb67ae8584caa73bULL;
        h[2]=0x3c6ef372fe94f82bULL; h[3]=0xa54ff53a5f1d36f1ULL;
        h[4]=0x510e527fade682d1ULL; h[5]=0x9b05688c2b3e6c1fULL;
        h[6]=0x1f83d9abfb41bd6bULL; h[7]=0x5be0cd19137e2179ULL;
    }
}

static void sha512_common(const void *data, size_t n, uint8_t out[64],
                          int trunc)
{
    epk_sha512 c;
    uint8_t raw[64];
    uint64_t bits;
    uint8_t pad[161];
    size_t plen;
    int i;

    sha512_common_init(c.h, trunc);
    c.len = 0; c.buflen = 0;

    bits = (uint64_t)n * 8;
    /* inline update */
    {
        const uint8_t *p = (const uint8_t *)data;
        c.len += n;
        if (c.buflen) {
            size_t take = 128 - c.buflen;
            if (take > n) take = n;
            memcpy(c.buf + c.buflen, p, take);
            c.buflen += take; p += take; n -= take;
            if (c.buflen == 128) { sha512_block(c.h, c.buf); c.buflen = 0; }
        }
        while (n >= 128) { sha512_block(c.h, p); p += 128; n -= 128; }
        if (n) { memcpy(c.buf, p, n); c.buflen = n; }
    }
    plen = (c.buflen < 112) ? 112 - c.buflen : 240 - c.buflen;
    memset(pad, 0, sizeof(pad));
    pad[0] = 0x80;
    st64be(pad + plen, 0);              /* high 64 bits of length (zero) */
    st64be(pad + plen + 8, bits);
    /* inline update of padding */
    {
        size_t m = plen + 16;
        const uint8_t *pp = pad;
        c.len += m;
        if (c.buflen) {
            size_t take = 128 - c.buflen;
            if (take > m) take = m;
            memcpy(c.buf + c.buflen, pp, take);
            c.buflen += take; pp += take; m -= take;
            if (c.buflen == 128) { sha512_block(c.h, c.buf); c.buflen = 0; }
        }
        while (m >= 128) { sha512_block(c.h, pp); pp += 128; m -= 128; }
        if (m) { memcpy(c.buf, pp, m); c.buflen = m; }
    }
    for (i = 0; i < 8; i++) st64be(raw + i * 8, c.h[i]);
    memcpy(out, raw, trunc ? 48 : 64);
}

void epk_sha512_buf(const void *data, size_t n, uint8_t out[64])
{
    sha512_common(data, n, out, 0);
}

void epk_sha384_buf(const void *data, size_t n, uint8_t out[48])
{
    uint8_t raw[64];
    sha512_common(data, n, raw, 1);
    memcpy(out, raw, 48);
}

/* incremental API (kept simple: buffer whole input length tracking) */
void epk_sha512_init(epk_sha512 *c) { sha512_common_init(c->h, 0); c->len = 0; c->buflen = 0; }
void epk_sha512_update(epk_sha512 *c, const void *data, size_t n)
{
    const uint8_t *p = (const uint8_t *)data;
    c->len += n;
    if (c->buflen) {
        size_t take = 128 - c->buflen;
        if (take > n) take = n;
        memcpy(c->buf + c->buflen, p, take);
        c->buflen += take; p += take; n -= take;
        if (c->buflen == 128) { sha512_block(c->h, c->buf); c->buflen = 0; }
    }
    while (n >= 128) { sha512_block(c->h, p); p += 128; n -= 128; }
    if (n) { memcpy(c->buf, p, n); c->buflen = n; }
}
void epk_sha512_final(epk_sha512 *c, uint8_t out[64])
{
    uint64_t bits = c->len * 8;
    uint8_t pad[257];
    size_t plen;
    int i;

    plen = (c->buflen < 112) ? 112 - c->buflen : 240 - c->buflen;
    memset(pad, 0, sizeof(pad));
    pad[0] = 0x80;
    st64be(pad + plen, 0);
    st64be(pad + plen + 8, bits);
    epk_sha512_update(c, pad, plen + 16);
    for (i = 0; i < 8; i++) st64be(out + i * 8, c->h[i]);
}

/* ---------------- HMAC-SHA256 ---------------- */
void epk_hmac_sha256_init(epk_hmac_sha256 *h, const uint8_t *key, size_t klen)
{
    uint8_t k[64], pad[64];
    size_t i;

    memset(k, 0, sizeof(k));
    if (klen > 64) {
        epk_sha256_buf(key, klen, k);
    } else {
        memcpy(k, key, klen);
    }
    for (i = 0; i < 64; i++) pad[i] = k[i] ^ 0x36;
    epk_sha256_init(&h->c);
    epk_sha256_update(&h->c, pad, 64);
    for (i = 0; i < 64; i++) h->opad[i] = k[i] ^ 0x5c;
}

void epk_hmac_sha256_update(epk_hmac_sha256 *h, const void *d, size_t n)
{
    epk_sha256_update(&h->c, d, n);
}

void epk_hmac_sha256_final(epk_hmac_sha256 *h, uint8_t out[32])
{
    uint8_t inner[32];
    epk_sha256 c2;
    epk_sha256_final(&h->c, inner);
    epk_sha256_init(&c2);
    epk_sha256_update(&c2, h->opad, 64);
    epk_sha256_update(&c2, inner, 32);
    epk_sha256_final(&c2, out);
}

void epk_hmac_sha256_buf(const uint8_t *key, size_t klen,
                         const void *d, size_t n, uint8_t out[32])
{
    epk_hmac_sha256 h;
    epk_hmac_sha256_init(&h, key, klen);
    epk_hmac_sha256_update(&h, d, n);
    epk_hmac_sha256_final(&h, out);
}
