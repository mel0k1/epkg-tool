/* epkg_key.c — signify-style Ed25519 key tool for epkg repositories.
 *
 *   epkg-key gen   [-c comment] <keyfile>
 *       writes <keyfile> (secret) and <keyfile>.pub (public)
 *   epkg-key sign  -s <secret> -m <file> [-x <sig>]
 *       writes a detached signify-format signature (default <file>.sig)
 *   epkg-key verify -p <pubkey> -m <file> [-x <sig>]
 *       exit 0 if the signature is valid
 *   epkg-key fp    -p <pubkey>
 *       print the key fingerprint (keynum + public key, hex)
 */
#include <string.h>
#include "epk_signify.h"
#include "epk_ed25519.h"
#include "epk_util.h"
#include "../include/epk_port.h"

static void say(const char *s) { epk_print(s); }

static void usage(void)
{
    say(
"usage: epkg-key gen [-c comment] <keyfile>\n"
"       epkg-key sign -s <secret> -m <file> [-x <sig>]\n"
"       epkg-key verify -p <pubkey> -m <file> [-x <sig>]\n"
"       epkg-key fp -p <pubkey>\n");
}

static void hexprint(const char *tag, const uint8_t *d, unsigned n)
{
    char hex[129];
    epk_hex(d, n, hex);
    say(tag);
    say(hex);
    say("\n");
}

static int cmd_gen(int argc, char **argv)
{
    const char *comment = "";
    const char *keyfile = 0;
    char pubpath[512 + 8];
    uint8_t seed[32], pub[32], keynum[EPK_SIG_KEYNUM_LEN];
    epk_sig_sec sec;
    int i;

    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "-c") == 0 && i + 1 < argc)
            comment = argv[++i];
        else if (argv[i][0] != '-')
            keyfile = argv[i];
    }
    if (!keyfile) { usage(); return 1; }

    epk_signify_keygen(seed, pub, keynum);

    memset(&sec, 0, sizeof(sec));
    memcpy(sec.keynum, keynum, sizeof(sec.keynum));
    memcpy(sec.seed, seed, 32);
    memcpy(sec.pub, pub, 32);

    epk_snprintf(pubpath, sizeof(pubpath), "%s.pub", keyfile);
    if (epk_signify_write_sec(keyfile, comment, keynum, seed, pub) != 0 ||
        epk_signify_write_pub(pubpath, comment, keynum, pub) != 0) {
        say("epkg-key: cannot write key files\n");
        return 1;
    }
    {
        char msg[256 + 128];
        epk_snprintf(msg, sizeof(msg), "wrote %s (secret) and %s\n"
                     "keep the secret file offline; publish the .pub\n",
                     keyfile, pubpath);
        say(msg);
    }
    memset(&sec, 0, sizeof(sec));
    return 0;
}

static int cmd_sign(int argc, char **argv)
{
    const char *secfile = 0, *msgfile = 0, *sigfile = 0;
    char sigbuf[512];
    epk_sig_sec sec;
    uint8_t *msg;
    unsigned mlen;
    uint8_t sig[64];
    int i;

    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) secfile = argv[++i];
        else if (strcmp(argv[i], "-m") == 0 && i + 1 < argc) msgfile = argv[++i];
        else if (strcmp(argv[i], "-x") == 0 && i + 1 < argc) sigfile = argv[++i];
    }
    if (!secfile || !msgfile) { usage(); return 1; }
    if (!sigfile) {
        epk_snprintf(sigbuf, sizeof(sigbuf), "%s.sig", msgfile);
        sigfile = sigbuf;
    }

    if (epk_signify_sec_load(secfile, &sec) != 0) {
        say("epkg-key: cannot load secret key\n");
        return 1;
    }
    msg = epk_read_file(msgfile, &mlen);
    if (!msg) {
        say("epkg-key: cannot read message file\n");
        return 1;
    }
    epk_ed25519_sign(sec.seed, msg, mlen, sig);
    memset(msg, 0, mlen);
    epk_free(msg);

    if (epk_signify_write_sig(sigfile, "signature from epkg-key",
                              sec.keynum, sig) != 0) {
        say("epkg-key: cannot write signature\n");
        return 1;
    }
    {
        char m[600];
        epk_snprintf(m, sizeof(m), "signed %s -> %s\n", msgfile, sigfile);
        say(m);
    }
    return 0;
}

static int cmd_verify(int argc, char **argv)
{
    const char *pubfile = 0, *msgfile = 0, *sigfile = 0;
    char sigbuf[512];
    epk_sig_pub pub;
    uint8_t skey[EPK_SIG_KEYNUM_LEN], sig[64];
    uint8_t *msg;
    unsigned mlen;
    int i, ok;

    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) pubfile = argv[++i];
        else if (strcmp(argv[i], "-m") == 0 && i + 1 < argc) msgfile = argv[++i];
        else if (strcmp(argv[i], "-x") == 0 && i + 1 < argc) sigfile = argv[++i];
    }
    if (!pubfile || !msgfile) { usage(); return 1; }
    if (!sigfile) {
        epk_snprintf(sigbuf, sizeof(sigbuf), "%s.sig", msgfile);
        sigfile = sigbuf;
    }

    if (epk_signify_pub_load(pubfile, &pub) != 0) {
        say("epkg-key: cannot load public key\n");
        return 1;
    }
    if (epk_signify_sig_load(sigfile, skey, sig) != 0) {
        say("epkg-key: cannot load signature\n");
        return 1;
    }
    msg = epk_read_file(msgfile, &mlen);
    if (!msg) {
        say("epkg-key: cannot read message file\n");
        return 1;
    }
    ok = epk_signify_verify(pub.pub, msg, mlen, sig) == 0;
    epk_free(msg);

    if (ok) {
        say("signature is valid\n");
        return 0;
    }
    say("signature is INVALID\n");
    return 1;
}

static int cmd_fp(int argc, char **argv)
{
    const char *pubfile = 0;
    epk_sig_pub pub;
    int i;

    for (i = 0; i < argc; i++)
        if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) pubfile = argv[++i];
    if (!pubfile) { usage(); return 1; }
    if (epk_signify_pub_load(pubfile, &pub) != 0) {
        say("epkg-key: cannot load public key\n");
        return 1;
    }
    say("comment: ");
    say(pub.comment);
    say("\nkeynum : ");
    hexprint("", pub.keynum, EPK_SIG_KEYNUM_LEN);
    say("pubkey : ");
    hexprint("", pub.pub, 32);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) { usage(); return 1; }
    if (strcmp(argv[1], "gen") == 0)    return cmd_gen(argc - 2, argv + 2);
    if (strcmp(argv[1], "sign") == 0)   return cmd_sign(argc - 2, argv + 2);
    if (strcmp(argv[1], "verify") == 0) return cmd_verify(argc - 2, argv + 2);
    if (strcmp(argv[1], "fp") == 0)     return cmd_fp(argc - 2, argv + 2);
    usage();
    return 1;
}
