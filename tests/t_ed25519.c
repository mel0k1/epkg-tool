/* t_ed25519.c — RFC 8032 test vectors for epk_ed25519 (dev-time). */
#include <stdio.h>
#include <string.h>
#include "../src/epk_ed25519.h"

static int fails = 0;

static int unhex1(const char *h, unsigned char *out)
{
    int n = 0;
    while (h[n * 2] && h[n * 2 + 1]) {
        unsigned v = 0;
        int i;
        for (i = 0; i < 2; i++) {
            char c = h[n * 2 + i];
            int d = (c >= '0' && c <= '9') ? c - '0' :
                    (c >= 'a' && c <= 'f') ? c - 'a' + 10 :
                    (c >= 'A' && c <= 'F') ? c - 'A' + 10 : -1;
            if (d < 0) return -1;
            v = v * 16 + d;
        }
        out[n++] = (unsigned char)v;
    }
    return n;
}

static void vector(const char *name,
                   const char *seed_hex, const char *pub_hex,
                   const char *msg_hex, const char *sig_hex)
{
    unsigned char seed[32], pub[32], sig[64], msg[128], mine[32], msig[64];
    int mlen = unhex1(msg_hex, msg);

    unhex1(seed_hex, seed);
    unhex1(pub_hex, pub);
    unhex1(sig_hex, sig);

    epk_ed25519_pubkey(seed, mine);
    if (memcmp(mine, pub, 32) != 0) {
        printf("FAIL %s: pubkey mismatch\n     got %02x%02x...\n",
               name, mine[0], mine[1]);
        fails++;
    } else {
        printf("ok %s pubkey\n", name);
    }

    epk_ed25519_sign(seed, msg, (size_t)mlen, msig);
    if (memcmp(msig, sig, 64) != 0) {
        printf("FAIL %s: signature mismatch\n", name);
        fails++;
    } else {
        printf("ok %s sign\n", name);
    }

    if (epk_ed25519_verify(pub, msg, (size_t)mlen, sig) != 0) {
        printf("FAIL %s: verify rejected a valid signature\n", name);
        fails++;
    } else {
        printf("ok %s verify\n", name);
    }

    /* tamper: flip a message bit */
    {
        unsigned char bad[128];
        memcpy(bad, msg, (size_t)mlen);
        bad[0] ^= 0x01;
        if (mlen == 0) bad[0] = 0x01;
        if (epk_ed25519_verify(pub, bad, (size_t)(mlen ? mlen : 1), sig) == 0) {
            printf("FAIL %s: verify accepted tampered message\n", name);
            fails++;
        } else {
            printf("ok %s tamper-reject\n", name);
        }
    }
}

int main(void)
{
    vector("rfc8032-1",
           "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
           "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
           "",
           "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
           "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
    vector("rfc8032-2",
           "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
           "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
           "72",
           "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
           "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");
    vector("rfc8032-3",
           "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
           "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
           "af82",
           "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
           "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a");
    vector("rfc8032-sha(abc)",
           "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
           "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
           "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
           "1bbb0e85e4805e95b670714185e595cf7334e891ef5f971fd02bef64932bf3de"
           "1abb5599a49c9aab91618767188eaad6379f733b8e0715c5abd3d24cdd773905");

    if (fails) printf("== %d FAILURES ==\n", fails);
    else printf("== ALL ED25519 VECTORS PASSED ==\n");
    return fails ? 1 : 0;
}
