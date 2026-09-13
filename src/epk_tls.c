/*
 * epk_tls.c — TLS 1.2 client on top of the vendored BearSSL profile:
 *   suites : ECDHE_RSA / ECDHE_ECDSA with AES-128/256-GCM (SHA256/384)
 *   curves : x25519 + secp256r1/384r1/521r1 (br_ec_all_m31)
 *   verify : X.509 chain against a PEM trust-anchor file (br_x509_minimal)
 * All crypto is BearSSL (MIT license, see tls/bearssl/LICENSE.txt);
 * transport I/O goes through the epkg port layer.
 */
#include "epk_tls.h"
#include "epk_util.h"
#include "epk_libc.h"
#include "tls/bearssl/inc/bearssl.h"

#define TA_MAX 128

struct epk_tls {
    br_ssl_client_context   cc;
    br_x509_minimal_context xc;
    br_sslio_context        ioc;
    epk_sock                sock;
    unsigned char           ibuf[BR_SSL_BUFSIZE_MONO];
};

/* ------------------------------------------------------------------ */
/* trust anchors: PEM file -> br_x509_trust_anchor[]                   */

typedef struct {
    br_x509_trust_anchor *tas;
    unsigned              n, cap;
    epk_buf               dn;          /* current DN accumulator  */
    int                   failed;
    char                  why[64];
} ta_builder;

static void ta_dn_append(void *ctx, const void *buf, size_t len)
{
    ta_builder *b = (ta_builder *)ctx;
    epk_buf_append(&b->dn, buf, (unsigned)len);
}

static void ta_x509_push(void *ctx, const void *src, size_t len)
{
    br_x509_decoder_push((br_x509_decoder_context *)ctx, src, len);
}

static int ta_add_cert(ta_builder *b, br_x509_decoder_context *dc)
{
    const br_x509_pkey *pk;
    unsigned char *dncopy;
    br_x509_trust_anchor *ta;

    if (b->failed) return -1;
    if (br_x509_decoder_last_error(dc) != 0) {
        epk_snprintf(b->why, sizeof(b->why), "CA cert decode error");
        b->failed = 1;
        return -1;
    }
    if (b->n == TA_MAX) return 0;                    /* skip extras */

    if (b->n == b->cap) {
        unsigned ncap = b->cap ? b->cap * 2 : 16;
        void *np = epk_realloc(b->tas, ncap * sizeof(br_x509_trust_anchor));
        if (!np) goto oom;
        b->tas = (br_x509_trust_anchor *)np;
        b->cap = ncap;
    }

    dncopy = (unsigned char *)epk_malloc(b->dn.len ? b->dn.len : 1u);
    if (!dncopy) goto oom;
    memcpy(dncopy, b->dn.p, b->dn.len);

    pk = br_x509_decoder_get_pkey(dc);
    ta = &b->tas[b->n];
    memset(ta, 0, sizeof(*ta));
    ta->dn.data = dncopy;
    ta->dn.len = b->dn.len;
    ta->flags = br_x509_decoder_isCA(dc) ? BR_X509_TA_CA : 0;
    ta->pkey.key_type = pk->key_type;
    switch (pk->key_type) {
    case BR_KEYTYPE_RSA:
        ta->pkey.key.rsa.n = (unsigned char *)epk_malloc((unsigned)pk->key.rsa.nlen);
        ta->pkey.key.rsa.e = (unsigned char *)epk_malloc((unsigned)pk->key.rsa.elen);
        if (!ta->pkey.key.rsa.n || !ta->pkey.key.rsa.e) goto oom;
        memcpy(ta->pkey.key.rsa.n, pk->key.rsa.n, pk->key.rsa.nlen);
        memcpy(ta->pkey.key.rsa.e, pk->key.rsa.e, pk->key.rsa.elen);
        ta->pkey.key.rsa.nlen = pk->key.rsa.nlen;
        ta->pkey.key.rsa.elen = pk->key.rsa.elen;
        break;
    case BR_KEYTYPE_EC:
        ta->pkey.key.ec.q = (unsigned char *)epk_malloc((unsigned)pk->key.ec.qlen);
        if (!ta->pkey.key.ec.q) goto oom;
        memcpy(ta->pkey.key.ec.q, pk->key.ec.q, pk->key.ec.qlen);
        ta->pkey.key.ec.curve = pk->key.ec.curve;
        ta->pkey.key.ec.qlen = pk->key.ec.qlen;
        break;
    default:
        epk_snprintf(b->why, sizeof(b->why), "unsupported CA key type");
        b->failed = 1;
        return -1;
    }
    b->n++;
    return 0;
oom:
    epk_snprintf(b->why, sizeof(b->why), "out of memory");
    b->failed = 1;
    return -1;
}

static int ta_load(const char *path, br_x509_trust_anchor **out,
                   unsigned *outn, char *err, unsigned errcap)
{
    ta_builder b;
    br_pem_decoder_context pc;
    br_x509_decoder_context dc;
    uint8_t raw[4096];
    epk_file f;
    int n, have_dc = 0, r = -1;

    memset(&b, 0, sizeof(b));
    epk_buf_init(&b.dn);

    f = epk_open(path, EPK_O_RDONLY);
    if (!f) {
        epk_snprintf(err, errcap, "CA bundle not found: %s", path);
        epk_buf_free(&b.dn);
        epk_free(b.tas);
        return -1;
    }

    br_pem_decoder_init(&pc);
    for (;;) {
        size_t off = 0;
        n = epk_read(f, raw, sizeof(raw));
        if (n <= 0) break;
        while (off < (size_t)n) {
            size_t taken = br_pem_decoder_push(&pc, raw + off, (size_t)n - off);
            int ev;
            off += taken;
            ev = br_pem_decoder_event(&pc);
            if (ev == BR_PEM_BEGIN_OBJ) {
                if (strcmp(br_pem_decoder_name(&pc), "CERTIFICATE") == 0) {
                    epk_buf_clear(&b.dn);
                    br_x509_decoder_init(&dc, ta_dn_append, &b);
                    br_pem_decoder_setdest(&pc, ta_x509_push, &dc);
                    have_dc = 1;
                } else {
                    br_pem_decoder_setdest(&pc, 0, 0);
                    have_dc = 0;
                }
            } else if (ev == BR_PEM_END_OBJ) {
                if (have_dc) {
                    if (ta_add_cert(&b, &dc) != 0) goto out;
                    have_dc = 0;
                }
                br_pem_decoder_setdest(&pc, 0, 0);
            } else if (ev == BR_PEM_ERROR) {
                epk_snprintf(err, errcap, "bad PEM in %s", path);
                goto out;
            }
        }
    }
    epk_close(f);
    f = 0;

    if (b.failed) {
        epk_snprintf(err, errcap, "CA load: %s", b.why);
        goto out;
    }
    if (b.n == 0) {
        epk_snprintf(err, errcap, "no CERTIFICATE entries in %s", path);
        goto out;
    }
    *out = b.tas;
    *outn = b.n;
    epk_buf_free(&b.dn);
    return 0;
out:
    if (f) epk_close(f);
    epk_buf_free(&b.dn);
    epk_free(b.tas);
    return r;
}

/* ------------------------------------------------------------------ */
/* transport callbacks                                                 */

static int tls_low_read(void *ctx, unsigned char *data, size_t len)
{
    epk_sock s = *(epk_sock *)ctx;
    int r = epk_tcp_recv(s, data, (int)len);
    return r <= 0 ? -1 : r;
}

static int tls_low_write(void *ctx, const unsigned char *data, size_t len)
{
    epk_sock s = *(epk_sock *)ctx;
    int r = epk_tcp_send(s, data, (int)len);
    return r <= 0 ? -1 : r;
}

/* ------------------------------------------------------------------ */

epk_tls *epk_tls_connect(epk_sock sock, const char *host,
                         const char *ca_path,
                         char *err, unsigned errcap)
{
    static const uint16_t suites[] = {
        BR_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        BR_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        BR_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        BR_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    };
    epk_tls *t;
    br_x509_trust_anchor *anchors = 0;
    unsigned nanchors = 0;
    uint32_t seed[4];
    int i;
    int have_ca = (ca_path && ca_path[0]);

    t = (epk_tls *)epk_malloc(sizeof(epk_tls));
    if (!t) {
        epk_snprintf(err, errcap, "oom");
        return 0;
    }
    memset(t, 0, sizeof(*t));
    t->sock = sock;

    br_ssl_client_zero(&t->cc);

    br_ssl_engine_set_versions(&t->cc.eng, BR_TLS12, BR_TLS12);
    br_ssl_engine_set_suites(&t->cc.eng, suites,
                             (unsigned)(sizeof(suites) / sizeof(suites[0])));
    br_ssl_engine_set_aes_ctr(&t->cc.eng, &br_aes_big_ctr_vtable);
    br_ssl_engine_set_gcm(&t->cc.eng,
                          &br_sslrec_in_gcm_vtable, &br_sslrec_out_gcm_vtable);
    br_ssl_engine_set_ghash(&t->cc.eng, &br_ghash_ctmul32);
    br_ssl_engine_set_prf_sha256(&t->cc.eng, &br_tls12_sha256_prf);
    br_ssl_engine_set_prf_sha384(&t->cc.eng, &br_tls12_sha384_prf);
    br_ssl_engine_set_hash(&t->cc.eng, br_sha256_ID, &br_sha256_vtable);
    br_ssl_engine_set_hash(&t->cc.eng, br_sha384_ID, &br_sha384_vtable);
    br_ssl_engine_set_hash(&t->cc.eng, br_sha512_ID, &br_sha512_vtable);
    br_ssl_engine_set_ec(&t->cc.eng, &br_ec_all_m31);
    br_ssl_engine_set_ecdsa(&t->cc.eng, &br_ecdsa_i31_vrfy_asn1);
    br_ssl_engine_set_rsavrfy(&t->cc.eng, &br_rsa_i31_pkcs1_vrfy);

    /* seed the engine DRBG from the port layer (weak source is fine:
     * it is mixed into HMAC_DRBG and combined with sysrng if present) */
    for (i = 0; i < 4; i++) seed[i] = epk_seed();
    br_ssl_engine_inject_entropy(&t->cc.eng, seed, sizeof(seed));

    /* X.509 validation */
    if (have_ca) {
        if (ta_load(ca_path, &anchors, &nanchors, err, errcap) != 0) {
            epk_free(t);
            return 0;
        }
    }
    br_x509_minimal_init(&t->xc, &br_sha256_vtable, anchors, nanchors);
    br_x509_minimal_set_rsa(&t->xc, &br_rsa_i31_pkcs1_vrfy);
    br_x509_minimal_set_ecdsa(&t->xc, &br_ec_all_m31, &br_ecdsa_i31_vrfy_asn1);
    br_x509_minimal_set_hash(&t->xc, br_sha256_ID, &br_sha256_vtable);
    br_x509_minimal_set_hash(&t->xc, br_sha384_ID, &br_sha384_vtable);
    br_x509_minimal_set_hash(&t->xc, br_sha512_ID, &br_sha512_vtable);
    br_ssl_engine_set_x509(&t->cc.eng, &t->xc.vtable);

    br_ssl_engine_set_buffer(&t->cc.eng, t->ibuf, sizeof(t->ibuf), 0);
    if (br_ssl_client_reset(&t->cc, host, 0) != 1) {
        epk_snprintf(err, errcap, "TLS reset failed: %d",
                     br_ssl_engine_last_error(&t->cc.eng));
        epk_free(t);
        return 0;
    }

    br_sslio_init(&t->ioc, &t->cc.eng,
                  tls_low_read, &t->sock,
                  tls_low_write, &t->sock);

    /* Drive the handshake: pump raw records until the engine reports
     * BR_SSL_SENDAPP, which BearSSL sets once the handshake is fully
     * verified (server Finished checked). */
    for (;;) {
        int state = br_ssl_engine_current_state(&t->cc.eng);
        if (state == BR_SSL_CLOSED) {
            epk_snprintf(err, errcap, "TLS handshake failed: %d",
                         br_ssl_engine_last_error(&t->cc.eng));
            epk_free(t);
            return 0;
        }
        if (state & BR_SSL_SENDAPP) break;       /* handshake complete */
        {
            size_t rlen, wlen;
            unsigned char *rbuf, *wbuf;
            int progress = 0;

            if (state & BR_SSL_RECVREC) {
                rbuf = br_ssl_engine_recvrec_buf(&t->cc.eng, &rlen);
                if (rlen) {
                    int rr = epk_tcp_recv(sock, rbuf, (int)rlen);
                    if (rr <= 0) {
                        epk_snprintf(err, errcap, "TLS: transport read failed");
                        epk_free(t);
                        return 0;
                    }
                    br_ssl_engine_recvrec_ack(&t->cc.eng, (size_t)rr);
                    progress = 1;
                }
            }
            if (state & BR_SSL_SENDREC) {
                wbuf = br_ssl_engine_sendrec_buf(&t->cc.eng, &wlen);
                if (wlen) {
                    int w = 0;
                    while (w < (int)wlen) {
                        int ww = epk_tcp_send(sock, wbuf + w, (int)(wlen - (size_t)w));
                        if (ww <= 0) {
                            epk_snprintf(err, errcap, "TLS: transport write failed");
                            epk_free(t);
                            return 0;
                        }
                        w += ww;
                    }
                    br_ssl_engine_sendrec_ack(&t->cc.eng, wlen);
                    progress = 1;
                }
            }
            if (!progress) {
                epk_snprintf(err, errcap, "TLS: stuck during handshake");
                epk_free(t);
                return 0;
            }
        }
    }

    if (!have_ca) {
        epk_print("epkg: warning - no CA bundle configured, "
                  "certificate chain NOT verified\r\n");
    }
    return t;
}

int epk_tls_read(epk_tls *t, void *buf, unsigned len)
{
    int r;
    if (len == 0) return 0;
    r = br_sslio_read(&t->ioc, buf, len);
    if (r < 0) {
        return br_ssl_engine_current_state(&t->cc.eng) == BR_SSL_CLOSED ? 0 : -1;
    }
    return r;
}

int epk_tls_write(epk_tls *t, const void *buf, unsigned len)
{
    if (len == 0) return 0;
    if (br_sslio_write_all(&t->ioc, buf, len) != 0) return -1;
    if (br_sslio_flush(&t->ioc) != 0) return -1;
    return (int)len;
}

void epk_tls_close(epk_tls *t)
{
    if (!t) return;
    br_sslio_close(&t->ioc);          /* sends close_notify, best effort */
    epk_free(t);
}
