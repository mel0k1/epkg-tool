/* epk_ed25519.h — Ed25519 signatures (RFC 8032) on top of epk_sha512.
 *
 * Pure C99 freestanding: 26-bit limb field arithmetic (radix 2^26),
 * extended twisted-Edwards coordinates, no 128-bit types, no timing
 * hardening (fine for offline repo signing / index auditing — see
 * README "Threat model").
 *
 *   pubkey derivation: epk_ed25519_pubkey(seed) -> pub
 *   sign:              epk_ed25519_sign(seed, msg) -> sig (64 bytes)
 *   verify:            epk_ed25519_verify(pub, msg, sig) -> 0 | -1
 */
#ifndef EPK_ED25519_H
#define EPK_ED25519_H

#include <stdint.h>
#include <stddef.h>

#define EPK_ED25519_SEED_LEN 32
#define EPK_ED25519_PUB_LEN  32
#define EPK_ED25519_SIG_LEN  64

/* Derive the public key from a 32-byte seed (the secret key). */
void epk_ed25519_pubkey(const uint8_t seed[32], uint8_t pub[32]);

/* Sign a message with the 32-byte seed. sig = R(32) || S(32). */
void epk_ed25519_sign(const uint8_t seed[32],
                      const void *msg, size_t msglen,
                      uint8_t sig[64]);

/* Verify. Returns 0 if valid, -1 if invalid (any reason). */
int epk_ed25519_verify(const uint8_t pub[32],
                       const void *msg, size_t msglen,
                       const uint8_t sig[64]);

#endif
