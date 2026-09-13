/* epk_signify.h — signify-compatible Ed25519 key and signature files.
 *
 * File formats (compatible with OpenBSD signify for public data):
 *
 *   <pubkey file>:  line 1: "untrusted comment: <comment>"
 *                   line 2: base64( "Ed" || keynum(8) || pubkey(32) )
 *                           == 42 bytes -> 56 base64 chars
 *   <secret file>:  line 1: comment
 *                   line 2: base64( "Ed" || keynum(8) || seed(32) || pub(32) )
 *                           == 74 bytes -> 100 base64 chars
 *                   (epkg extension of signify's private format; keep
 *                   this file OFFLINE, it is the signing key)
 *   <signature>:    line 1: comment
 *                   line 2: base64( "Ed" || keynum(8) || sig(64) )
 *                           == 74 bytes -> 100 base64 chars
 *
 * Public key and signature files produced here verify with
 * `signify -V -p pub -m message` and vice versa.
 */
#ifndef EPK_SIGNIFY_H
#define EPK_SIGNIFY_H

#include <stdint.h>

#define EPK_SIG_KEYNUM_LEN 8
#define EPK_SIG_PUB_BLOB   42     /* "Ed" + keynum + pub            */
#define EPK_SIG_SEC_BLOB   74     /* "Ed" + keynum + seed + pub     */
#define EPK_SIG_SIG_BLOB   74     /* "Ed" + keynum + 64-byte sig    */

typedef struct {
    uint8_t keynum[EPK_SIG_KEYNUM_LEN];
    uint8_t pub[32];
    char    comment[128];
} epk_sig_pub;

typedef struct {
    uint8_t keynum[EPK_SIG_KEYNUM_LEN];
    uint8_t seed[32];
    uint8_t pub[32];
} epk_sig_sec;

/* Parse a public key file from memory. 0 on success. */
int epk_signify_pub_parse(const char *text, unsigned len, epk_sig_pub *out);
/* Load from a path. 0 on success, -1 on I/O or format error. */
int epk_signify_pub_load(const char *path, epk_sig_pub *out);

/* Parse a secret key file from memory. 0 on success. */
int epk_signify_sec_parse(const char *text, unsigned len, epk_sig_sec *out);
int epk_signify_sec_load(const char *path, epk_sig_sec *out);

/* Parse a detached signature file from memory. 0 on success. */
int epk_signify_sig_parse(const char *text, unsigned len,
                          uint8_t keynum[EPK_SIG_KEYNUM_LEN],
                          uint8_t sig[64]);
int epk_signify_sig_load(const char *path,
                         uint8_t keynum[EPK_SIG_KEYNUM_LEN],
                         uint8_t sig[64]);

/* Verify a raw 64-byte Ed25519 signature over msg. 0 = valid. */
int epk_signify_verify(const uint8_t pub[32],
                       const void *msg, unsigned msglen,
                       const uint8_t sig[64]);

/* Generate a key: fills seed (32 random bytes), derives pub, makes a
 * fresh 8-byte keynum. Entropy: /dev/urandom through the port layer,
 * falling back to a mixed epk_seed()/time/ticks pool. */
void epk_signify_keygen(uint8_t seed[32], uint8_t pub[32],
                        uint8_t keynum[EPK_SIG_KEYNUM_LEN]);

/* Writers (untrusted comment line + base64 blob line + '\n'). 0 ok. */
int epk_signify_write_pub(const char *path, const char *comment,
                          const uint8_t keynum[EPK_SIG_KEYNUM_LEN],
                          const uint8_t pub[32]);
int epk_signify_write_sec(const char *path, const char *comment,
                          const uint8_t keynum[EPK_SIG_KEYNUM_LEN],
                          const uint8_t seed[32], const uint8_t pub[32]);
int epk_signify_write_sig(const char *path, const char *comment,
                          const uint8_t keynum[EPK_SIG_KEYNUM_LEN],
                          const uint8_t sig[64]);

#endif
