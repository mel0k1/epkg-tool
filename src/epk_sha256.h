/* SHA-256 / SHA-384 / SHA-512 + HMAC-SHA256. Public-domain style. */
#ifndef EPK_SHA256_H
#define EPK_SHA256_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint32_t h[8];
    uint64_t len;              /* total bytes processed */
    uint8_t  buf[64];
    size_t   buflen;
} epk_sha256;

typedef struct {
    uint64_t h[8];
    uint64_t len;
    uint8_t  buf[128];
    size_t   buflen;
} epk_sha512;

void epk_sha256_init(epk_sha256 *c);
void epk_sha256_update(epk_sha256 *c, const void *data, size_t n);
void epk_sha256_final(epk_sha256 *c, uint8_t out[32]);
void epk_sha256_buf(const void *data, size_t n, uint8_t out[32]);

void epk_sha512_init(epk_sha512 *c);
void epk_sha512_update(epk_sha512 *c, const void *data, size_t n);
void epk_sha512_final(epk_sha512 *c, uint8_t out[64]);
void epk_sha512_buf(const void *data, size_t n, uint8_t out[64]);
/* 384 = 512 with different IV, truncated to 48 bytes */
void epk_sha384_buf(const void *data, size_t n, uint8_t out[48]);

typedef struct {
    epk_sha256 c;
    uint8_t opad[64];
} epk_hmac_sha256;

void epk_hmac_sha256_init(epk_hmac_sha256 *h, const uint8_t *key, size_t klen);
void epk_hmac_sha256_update(epk_hmac_sha256 *h, const void *d, size_t n);
void epk_hmac_sha256_final(epk_hmac_sha256 *h, uint8_t out[32]);
void epk_hmac_sha256_buf(const uint8_t *key, size_t klen,
                         const void *d, size_t n, uint8_t out[32]);

#endif
