/*
 * epk_install.c — the epkg install/remove engine.
 *
 * install flow:
 *   index -> find pkg -> deps warning -> download .epkg (mirrors in order,
 *   sha256-checked against the index) -> gunzip -> tar -> PKGINFO
 *   -> manifest sha256 verify -> safe-path extract under root -> DB record
 */
#include "epk_install.h"
#include "epk_sha256.h"
#include "epk_inflate.h"
#include "epk_tar.h"
#include "epk_http.h"
#include "epk_pkginfo.h"
#include "epk_db.h"
#include "epk_signify.h"
#include "../include/epk_port.h"

#define DL_BUF_CAP (32u * 1024u * 1024u)

static void say(const char *s) { epk_print(s); }

static void err_set(epkg_ctx *ctx, const char *msg)
{
    epk_strlcpy(ctx->last_err, msg, sizeof(ctx->last_err));
}

/* ------------------------------------------------------------------ */
/* memory download sink (for index.json)                               */

typedef struct {
    uint8_t *buf;
    unsigned len, cap;
    int oom;
} dlmem_t;

static void dlmem_init(dlmem_t *m)
{
    m->buf = 0; m->len = 0; m->cap = 0; m->oom = 0;
}

static void dlmem_free(dlmem_t *m)
{
    epk_free(m->buf);
    dlmem_init(m);
}

static int dlmem_sink(void *v, const uint8_t *d, unsigned n)
{
    dlmem_t *m = (dlmem_t *)v;
    if (m->oom) return 0;
    if ((unsigned long)m->len + n > DL_BUF_CAP) { m->oom = 1; return 0; }
    if (m->len + n > m->cap) {
        unsigned ncap = m->cap ? m->cap : 8192;
        void *np;
        while (ncap < m->len + n) ncap *= 2;
        np = epk_realloc(m->buf, ncap);
        if (!np) { m->oom = 1; return 0; }
        m->buf = (uint8_t *)np;
        m->cap = ncap;
    }
    memcpy(m->buf + m->len, d, n);
    m->len += n;
    return 1;
}

/* ------------------------------------------------------------------ */
/* file download sink (streams to a temp file + sha256)                */

/* Resume-aware sink. The file is opened lazily in dlfile_onresp once the
 * server response is known: 206 → append at `expect` (pre-hashing the
 * existing .part), 2xx → fresh full write. On transport errors the .part
 * is kept so a later attempt (or a later epkg run) can resume. */
typedef struct {
    epk_sha256 sh;
    epk_file   f;
    unsigned long long n;    /* bytes already hashed/written      */
    int        failed;
    int        abort;        /* onresp rejected this response     */
    int        drop_part;    /* .part must be deleted + retried   */
    char       part[640];    /* .part path (lazy open)            */
    long long  expect;       /* offset we asked to resume from    */
} dlfile_t;

static int dlfile_sink(void *v, const uint8_t *d, unsigned n)
{
    dlfile_t *s = (dlfile_t *)v;
    epk_sha256_update(&s->sh, d, n);
    while (n) {
        int w = epk_write(s->f, d, n);
        if (w <= 0) { s->failed = 1; return 0; }
        s->n += (unsigned)w;
        d += w;
        n -= (unsigned)w;
    }
    return 1;
}

static int dlfile_onresp(void *v, long status, long long from,
                         long long total)
{
    dlfile_t *s = (dlfile_t *)v;
    (void)total;

    if (status == 206) {
        if (from != s->expect) {              /* server starts elsewhere */
            s->abort = 1; s->drop_part = 1;
            return -1;
        }
        s->f = epk_open(s->part, EPK_O_WRONLY);       /* append mode */
        if (!s->f) { s->failed = 1; return -1; }
        epk_seek(s->f, 0, EPK_SEEK_END);
        epk_sha256_init(&s->sh);
        s->n = 0;
        {
            /* re-hash what we already have on disk */
            epk_file r = epk_open(s->part, EPK_O_RDONLY);
            uint8_t buf[8192];
            int n;
            if (!r) {
                epk_close(s->f); s->f = 0;
                s->abort = 1; s->drop_part = 1;
                return -1;
            }
            while ((n = epk_read(r, buf, sizeof(buf))) > 0) {
                epk_sha256_update(&s->sh, buf, (unsigned)n);
                s->n += (unsigned long long)n;
            }
            epk_close(r);
            if (n < 0 || s->n != (unsigned long long)from) {
                epk_close(s->f); s->f = 0;
                s->abort = 1; s->drop_part = 1;
                return -1;
            }
        }
        return 0;
    }
    if (status >= 200 && status < 300) {
        /* server ignored Range (or plain GET): full restart */
        s->f = epk_open(s->part, EPK_O_WRONLY | EPK_O_CREATE | EPK_O_TRUNC);
        if (!s->f) { s->failed = 1; return -1; }
        epk_sha256_init(&s->sh);
        s->n = 0;
        return 0;
    }
    if (status == 416) {          /* .part larger than the object */
        s->abort = 1; s->drop_part = 1;
        return -1;
    }
    s->abort = 1;                 /* 404 etc: keep .part, next mirror */
    return -1;
}

/* ------------------------------------------------------------------ */
/* cached index                                                        */

static int load_cached_index(epkg_ctx *ctx)
{
    char path[512];
    uint8_t *data;
    unsigned len;

    if (ctx->ix_loaded) return 0;
    epk_index_free(&ctx->ix);
    epk_snprintf(path, sizeof(path), "%s/index.json", ctx->conf->db);
    data = epk_read_file(path, &len);
    if (!data) return 1;
    if (epk_index_parse(&ctx->ix, (char *)data, len) != 0) {
        epk_free(data);
        return 1;
    }
    ctx->ix_loaded = 1;
    return 0;
}

int epkg_open(epkg_ctx *ctx, const epk_conf *conf)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->conf = conf;
    return 0;
}

void epkg_close(epkg_ctx *ctx)
{
    epk_index_free(&ctx->ix);
    ctx->ix_loaded = 0;
}

/* ------------------------------------------------------------------ */
/* index signatures (epkg audit)                                       */

/* 0 = off, 1 = warn (accept failures with a warning), 2 = strict */
static int audit_mode(const epk_conf *conf)
{
    if (!conf->pubkey[0]) return 0;
    if (strcmp(conf->audit, "off") == 0) return 0;
    if (strcmp(conf->audit, "warn") == 0) return 1;
    return 2;                       /* strict (default) */
}

/* Resolve conf->pubkey: a file path (contains '.') or inline base64
 * (a signify blob starts with "RW"; base64 never contains '.').
 * 0 on success. */
static int load_pubkey(const epk_conf *conf, epk_sig_pub *pub)
{
    const char *s = conf->pubkey;
    char tmp[600];
    unsigned n;

    if (!s[0]) return -1;
    if (strchr(s, '.'))
        return epk_signify_pub_load(s, pub);
    if (s[0] == 'R' && s[1] == 'W') {
        /* inline: base64 blob on its own line */
        n = (unsigned)strlen(s);
        if (n >= sizeof(tmp) - 2) return -1;
        memcpy(tmp, s, n);
        tmp[n] = '\n'; tmp[n + 1] = 0;
        return epk_signify_pub_parse(tmp, n + 1, pub);
    }
    return epk_signify_pub_load(s, pub);    /* bare relative path */
}

static void print_keyfp(const epk_sig_pub *pub)
{
    char hex[129], msg[200];
    epk_hex(pub->keynum, EPK_SIG_KEYNUM_LEN, hex);
    epk_snprintf(msg, sizeof(msg), "key %.16s/", hex);
    say(msg);
    epk_hex(pub->pub, 32, hex);
    say(hex);
    say("\n");
}

/* Fetch <base>/index.sig into memory. 0 on success. */
static int fetch_sig(const epk_conf *conf, const char *base,
                     dlmem_t *mem, char *err, unsigned errcap)
{
    char url[600];
    epk_snprintf(url, sizeof(url), "%s/index.sig", base);
    dlmem_init(mem);
    if (epk_http_get(url, conf->ca[0] ? conf->ca : 0,
                     dlmem_sink, mem, err, errcap) != 0) {
        dlmem_free(mem);
        return -1;
    }
    return 0;
}

int epkg_cmd_audit(epkg_ctx *ctx, const char *repo,
                   const char *file, const char *sigfile,
                   const char *pubkey)
{
    epk_sig_pub pub;
    const epk_conf *conf = ctx->conf;
    char path[512], msg[600];
    uint8_t *data = 0, *sigdata = 0;
    unsigned dlen = 0, siglen = 0;
    uint8_t skey[EPK_SIG_KEYNUM_LEN], sig[64];
    int rc = 1, am = audit_mode(conf);

    if (pubkey && pubkey[0]) {
        epk_strlcpy(path, pubkey, sizeof(path));
        {
            epk_conf tmp;
            memset(&tmp, 0, sizeof(tmp));
            epk_strlcpy(tmp.pubkey, path, sizeof(tmp.pubkey));
            if (load_pubkey(&tmp, &pub) != 0) {
                err_set(ctx, "cannot load public key");
                return 1;
            }
        }
    } else {
        if (load_pubkey(conf, &pub) != 0) {
            err_set(ctx, "no pubkey configured (set 'pubkey =' in epkg.conf "
                         "or pass --pubkey)");
            return 1;
        }
    }

    say("audit: pubkey ");
    print_keyfp(&pub);

    if (file && file[0]) {
        char sbuf[560];
        if (!sigfile || !sigfile[0]) {
            epk_snprintf(sbuf, sizeof(sbuf), "%s.sig", file);
            sigfile = sbuf;
        }
        data = epk_read_file(file, &dlen);
        sigdata = epk_read_file(sigfile, &siglen);
        epk_snprintf(msg, sizeof(msg), "audit: file %s vs %s: ",
                     file, sigfile);
        say(msg);
        if (!data || !sigdata ||
            epk_signify_sig_parse((const char *)sigdata, siglen,
                                  skey, sig) != 0) {
            say("INVALID (unreadable signature)\n");
            goto out;
        }
        rc = epk_signify_verify(pub.pub, data, dlen, sig) == 0 ? 0 : 1;
        say(rc == 0 ? "VALID\n" : "INVALID\n");
        goto out;
    }

    if (repo && repo[0]) {
        dlmem_t mem, memsig;
        char err[256] = {0};
        (void)am;
        dlmem_init(&mem);
        {
            char url[600];
            epk_snprintf(url, sizeof(url), "%s/index.json", repo);
            if (epk_http_get(url, conf->ca[0] ? conf->ca : 0,
                             dlmem_sink, &mem, err, sizeof(err)) != 0) {
                dlmem_free(&mem);
                err_set(ctx, "cannot download index.json for audit");
                return 1;
            }
        }
        if (fetch_sig(conf, repo, &memsig, err, sizeof(err)) != 0) {
            dlmem_free(&mem);
            err_set(ctx, "cannot download index.sig for audit");
            return 1;
        }
        data = mem.buf; dlen = mem.len;
        sigdata = memsig.buf; siglen = memsig.len;
        say("audit: ");
        say(repo);
        say("/index.json: ");
        if (!sigdata ||
            epk_signify_sig_parse((const char *)sigdata, siglen,
                                  skey, sig) != 0) {
            say("INVALID (unreadable signature)\n");
            goto out;
        }
        rc = epk_signify_verify(pub.pub, data, dlen, sig) == 0 ? 0 : 1;
        say(rc == 0 ? "VALID\n" : "INVALID\n");
        goto out;
    }

    /* default: the cached index */
    {
        epk_snprintf(path, sizeof(path), "%s/index.json", conf->db);
        data = epk_read_file(path, &dlen);
        epk_snprintf(path, sizeof(path), "%s/index.sig", conf->db);
        sigdata = epk_read_file(path, &siglen);
        if (!data) {
            err_set(ctx, "no cached index (run 'epkg update' first)");
            goto out;
        }
        if (!sigdata) {
            err_set(ctx, "no cached index.sig (repo mirror without "
                         "signatures?); run 'epkg audit --repo <url>'");
            goto out;
        }
        say("audit: cached index: ");
        if (epk_signify_sig_parse((const char *)sigdata, siglen,
                                  skey, sig) != 0) {
            say("INVALID (unreadable signature)\n");
            goto out;
        }
        rc = epk_signify_verify(pub.pub, data, dlen, sig) == 0 ? 0 : 1;
        say(rc == 0 ? "VALID\n" : "INVALID\n");
    }
out:
    epk_free(data);
    epk_free(sigdata);
    return rc;
}

/* ------------------------------------------------------------------ */
/* update                                                              */

int epkg_cmd_update(epkg_ctx *ctx)
{
    char url[600], path[512], tmp[600];
    unsigned mi;
    int ok = 0;

    if (ctx->conf->nmirrors == 0) {
        err_set(ctx, "no mirrors configured (see epkg.conf)");
        return 1;
    }
    epk_mkdir_p(ctx->conf->db);
    epk_snprintf(path, sizeof(path), "%s/index.json", ctx->conf->db);
    epk_snprintf(tmp, sizeof(tmp), "%s.part", path);

    for (mi = 0; mi < ctx->conf->nmirrors && !ok; mi++) {
        char err[256] = {0};
        dlmem_t mem;
        epk_index probe;
        int parsed;

        dlmem_init(&mem);
        epk_snprintf(url, sizeof(url), "%s/index.json",
                     ctx->conf->mirrors[mi]);
        say("fetching ");
        say(url);
        say("\n");

        if (epk_http_get(url, ctx->conf->ca[0] ? ctx->conf->ca : 0,
                         dlmem_sink, &mem, err, sizeof(err)) != 0) {
            say("  mirror failed: ");
            say(err[0] ? err : "transport error");
            say("\n");
            dlmem_free(&mem);
            continue;
        }

        /* NUL-terminate for the parser */
        {
            void *np = epk_realloc(mem.buf, mem.len + 1);
            if (!np) { dlmem_free(&mem); continue; }
            mem.buf = (uint8_t *)np;
            mem.buf[mem.len] = 0;
        }

        /* validate before installing the cache */
        parsed = (epk_index_parse(&probe, (char *)mem.buf, mem.len) == 0);
        if (parsed) {
            int am = audit_mode(ctx->conf);
            int accepted = 1;

            /* signify/ed25519 index signature check */
            if (am != 0) {
                epk_sig_pub pub;
                dlmem_t memsig;
                char err2[256] = {0};

                if (load_pubkey(ctx->conf, &pub) != 0) {
                    say("  pubkey configured but unreadable\n");
                    dlmem_free(&mem);
                    continue;
                }
                if (fetch_sig(ctx->conf, ctx->conf->mirrors[mi],
                              &memsig, err2, sizeof(err2)) != 0) {
                    if (am >= 2) {
                        say("  no index.sig on mirror, rejecting "
                            "(audit=strict)\n");
                        accepted = 0;
                    } else {
                        say("WARNING: no index.sig on mirror "
                            "(audit=warn)\n");
                    }
                } else {
                    uint8_t skey[EPK_SIG_KEYNUM_LEN], sig[64];
                    int vok = 0;
                    if (epk_signify_sig_parse((const char *)memsig.buf,
                                              memsig.len, skey, sig) == 0)
                        vok = epk_signify_verify(pub.pub, mem.buf,
                                                 mem.len, sig) == 0;
                    if (vok) {
                        char hex[129], msg2[80];
                        epk_hex(pub.keynum, EPK_SIG_KEYNUM_LEN, hex);
                        epk_snprintf(msg2, sizeof(msg2),
                                     "  index signature ok (key %.16s)\n",
                                     hex);
                        say(msg2);
                        /* cache the signature next to the index */
                        {
                            char sp[512], st[512];
                            epk_snprintf(sp, sizeof(sp), "%s/index.sig",
                                         ctx->conf->db);
                            epk_snprintf(st, sizeof(st), "%s.part", sp);
                            if (epk_write_file(st, memsig.buf,
                                               memsig.len) == 0)
                                epk_rename(st, sp);
                        }
                    } else if (am >= 2) {
                        say("  index signature INVALID, rejecting mirror "
                            "(audit=strict)\n");
                        accepted = 0;
                    } else {
                        say("WARNING: index signature INVALID, accepting "
                            "(audit=warn)\n");
                    }
                    dlmem_free(&memsig);
                }
            }

            if (accepted) {
                char msg[64];
                epk_snprintf(msg, sizeof(msg), "index updated: %u packages\n",
                             probe.n);
                epk_index_free(&probe);
                {
                    int wr = epk_write_file(tmp, mem.buf, mem.len);
                    if (wr == 0 && epk_rename(tmp, path) == 0) {
                        ok = 1;
                        say(msg);
                    } else {
                        epk_unlink(tmp);
                    }
                }
            } else {
                epk_index_free(&probe);
            }
        } else {
            say("  not a valid epkg index\n");
        }
        dlmem_free(&mem);
    }

    if (!ok) {
        err_set(ctx, "all mirrors failed for index.json");
        return 1;
    }
    epk_index_free(&ctx->ix);
    ctx->ix_loaded = 0;
    return 0;
}

static int ensure_index(epkg_ctx *ctx, int refresh)
{
    if (!refresh && ctx->ix_loaded) return 0;
    if (!refresh && load_cached_index(ctx) == 0) return 0;
    if (epkg_cmd_update(ctx) != 0) return 1;
    if (load_cached_index(ctx) != 0) {
        err_set(ctx, "index cache missing after update");
        return 1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* download package to cache (with resume after connection loss)       */

#define DL_MAX_ATTEMPTS 4      /* resume attempts per mirror          */

static long long fsize_of(const char *path)
{
    epk_file f = epk_open(path, EPK_O_RDONLY);
    long end;
    if (!f) return -1;
    end = epk_seek(f, 0, EPK_SEEK_END);
    epk_close(f);
    return end < 0 ? -1 : (long long)end;
}

static int hash_file_hex(const char *path, char *hex /* 65 bytes */)
{
    epk_file f = epk_open(path, EPK_O_RDONLY);
    epk_sha256 sh;
    uint8_t buf[8192], dig[32];
    int n;
    if (!f) return -1;
    epk_sha256_init(&sh);
    while ((n = epk_read(f, buf, sizeof(buf))) > 0)
        epk_sha256_update(&sh, buf, (unsigned)n);
    epk_close(f);
    if (n < 0) return -1;
    epk_sha256_final(&sh, dig);
    epk_hex(dig, 32, hex);
    return 0;
}

static int fetch_to_cache(epkg_ctx *ctx, const epk_idx_entry *e)
{
    char path[600], tmp[640], hex[65], url[900], msg[320];
    uint8_t digest[32];
    unsigned mi;

    if (!e->filename[0] && !e->url[0]) {
        epk_snprintf(ctx->last_err, sizeof(ctx->last_err),
                     "index entry for %s has no filename", e->pkgname);
        return 1;
    }

    epk_snprintf(path, sizeof(path), "%s/%s", ctx->conf->cache,
                 e->filename[0] ? e->filename : e->pkgname);
    epk_snprintf(tmp, sizeof(tmp), "%s.part", path);
    epk_mkdir_p(ctx->conf->cache);

    /* final file already cached and matching? */
    if (e->sha256[0] && fsize_of(path) >= 0) {
        if (hash_file_hex(path, hex) == 0 &&
            strcmp(hex, e->sha256) == 0) return 0;
    }

    for (mi = 0; mi < ctx->conf->nmirrors; mi++) {
        int attempt, next_mirror = 0;

        if (e->url[0]) {
            /* absolute URL overrides mirrors entirely */
            if (mi > 0) break;
            epk_strlcpy(url, e->url, sizeof(url));
        } else {
            epk_snprintf(url, sizeof(url), "%s/packages/%s",
                         ctx->conf->mirrors[mi], e->filename);
        }

        for (attempt = 0; attempt < DL_MAX_ATTEMPTS && !next_mirror;
             attempt++) {
            char err[256] = {0};
            dlfile_t df;
            epk_http_res res;
            long long part = fsize_of(tmp);
            int rc;

            if (part < 0) part = 0;

            /* sanity-check the .part against the known total size */
            if (part > 0 && e->size > 0) {
                if (part == (long long)e->size) {
                    /* complete but not yet renamed */
                    hash_file_hex(tmp, hex);
                    if (!e->sha256[0] || strcmp(hex, e->sha256) == 0) {
                        if (epk_rename(tmp, path) == 0) return 0;
                        err_set(ctx, "cache rename failed");
                        return 1;
                    }
                    epk_unlink(tmp);
                    part = 0;
                } else if (part > (long long)e->size) {
                    epk_unlink(tmp);           /* stale junk */
                    part = 0;
                }
            }

            memset(&df, 0, sizeof(df));
            epk_strlcpy(df.part, tmp, sizeof(df.part));
            df.expect = part;

            say("fetching ");
            say(url);
            if (part > 0) {
                if (e->size > 0)
                    epk_snprintf(msg, sizeof(msg),
                                 " (resuming at %lld/%lld bytes)",
                                 part, (long long)e->size);
                else
                    epk_snprintf(msg, sizeof(msg),
                                 " (resuming at %lld bytes)", part);
                say(msg);
            }
            say("\n");

            rc = epk_http_get_ex(url,
                                 ctx->conf->ca[0] ? ctx->conf->ca : 0,
                                 part > 0 ? part : -1,
                                 dlfile_sink, &df,
                                 dlfile_onresp, &res,
                                 err, sizeof(err));
            if (df.f) epk_close(df.f);
            df.f = 0;

            if (df.drop_part) {
                epk_unlink(tmp);
                continue;                      /* fresh attempt */
            }
            if (rc == 0 && !df.failed && !df.abort) {
                epk_sha256_final(&df.sh, digest);
                epk_hex(digest, 32, hex);
                if (e->sha256[0] && strcmp(hex, e->sha256) != 0) {
                    say("  sha256 mismatch, trying next mirror\n");
                    epk_unlink(tmp);
                    next_mirror = 1;
                } else if (epk_rename(tmp, path) == 0) {
                    return 0;
                } else {
                    err_set(ctx, "cache rename failed");
                    return 1;
                }
            } else if (rc >= 300) {            /* HTTP error */
                epk_snprintf(msg, sizeof(msg),
                             "  HTTP %ld from mirror, trying next\n", rc);
                say(msg);
                next_mirror = 1;               /* keep .part */
            } else if (rc == 0 || df.failed) { /* local write failure */
                say("  local write failed, retrying\n");
            } else {
                /* transport error: keep .part and resume */
                epk_snprintf(msg, sizeof(msg),
                             "  connection lost at %llu bytes (%s), "
                             "will resume\n",
                             (unsigned long long)df.n,
                             err[0] ? err : "transport error");
                say(msg);
            }
        }
    }

    epk_snprintf(ctx->last_err, sizeof(ctx->last_err),
                 "failed to fetch %s from all mirrors", e->pkgname);
    return 1;
}

/* ------------------------------------------------------------------ */
/* extraction: gz -> tar pull chain                                    */

typedef struct {
    epk_file  f;
    epk_gz    gz;
    epk_buf   out;          /* decompressed staging             */
    int       done, err;
} gzs_t;

static int gz_out(void *v, const uint8_t *d, unsigned n)
{
    gzs_t *g = (gzs_t *)v;
    if (epk_buf_append(&g->out, d, n) != 0) { g->err = 1; return 0; }
    return 1;
}

static long gzs_pull(void *v, uint8_t *buf, unsigned len)
{
    gzs_t *g = (gzs_t *)v;
    unsigned take;

    while (g->out.len == 0 && !g->done && !g->err) {
        uint8_t raw[8192];
        int n = epk_read(g->f, raw, sizeof(raw));
        int r;
        if (n < 0) { g->err = 1; return -1; }
        if (n == 0) { g->err = 1; return -1; }   /* truncated gzip */
        r = epk_gz_feed(&g->gz, raw, (unsigned)n);
        if (r < 0 || g->err) { g->err = 1; return -1; }
        if (r == 1) g->done = 1;
    }
    if (g->err) return -1;
    if (g->out.len == 0) return 0;               /* clean EOF */

    take = g->out.len < len ? g->out.len : len;
    memcpy(buf, g->out.p, take);
    memmove(g->out.p, g->out.p + take, g->out.len - take);
    g->out.len -= take;
    return (long)take;
}

/* manifest hash: for every regular file entry (archive order,
 * PKGINFO excluded): u32le(pathlen) path u32le(contentlen) content */
static int path_safe(const char *p)
{
    const char *s = p;
    if (!p[0]) return 0;
    if (p[0] == '/') return 0;
    for (;;) {
        const char *c = s;
        if (c[0] == '.' && c[1] == '.' &&
            (c[2] == '/' || c[2] == 0)) return 0;
        s = strchr(s, '/');
        if (!s) break;
        s++;
        if (!*s) return 0;                       /* trailing slash */
    }
    return 1;
}

#define EPK_MAX_FILES 4096
#define EPK_MAX_LINKS  512

typedef struct {
    const char   *root;
    epk_sha256    manifest;
    char        (*files)[256];
    unsigned      nfiles;
    char        (*links)[256];   /* symlink paths created this run  */
    unsigned      nlinks;
    int           symkeep;       /* policy: keep (1) or deny (0)    */
    int           have_pkginfo;
    epk_pkginfo   pi;
    int           error;
    char          why[128];
} extract_state;

static int record_file(extract_state *st, const char *rel)
{
    unsigned i;
    if (st->nfiles >= EPK_MAX_FILES) {
        epk_snprintf(st->why, sizeof(st->why), "too many files in package");
        st->error = 1;
        return 0;
    }
    for (i = 0; i < st->nfiles; i++)
        if (strcmp(st->files[i], rel) == 0) return 1;
    epk_strlcpy(st->files[st->nfiles++], rel, sizeof(st->files[0]));
    return 1;
}

static int mk_parents(char *path /* mutable, cap>=512 */)
{
    char *s;
    for (s = path + 1; *s; s++) {
        if (*s == '/') {
            *s = 0;
            epk_mkdir(path);                 /* ok if exists */
            *s = '/';
        }
    }
    return 0;
}

static int is_pkginfo_name(const char *name)
{
    const char *b = strrchr(name, '/');
    b = b ? b + 1 : name;
    return strcmp(b, "PKGINFO") == 0 || strcmp(b, ".PKGINFO") == 0;
}

/* True if any path component of rel was created as a symlink earlier in
 * THIS package. Classic tar-symlink-attack guard: without it a package
 * could write through its own link outside the extraction root. */
static int path_crosses_link(const extract_state *st, const char *rel)
{
    unsigned i;
    size_t rl = strlen(rel);
    for (i = 0; i < st->nlinks; i++) {
        size_t ll = strlen(st->links[i]);
        if (rl > ll && strncmp(rel, st->links[i], ll) == 0 && rel[ll] == '/')
            return 1;
    }
    return 0;
}

static int handle_entry(extract_state *st, epk_tar *tar,
                        epk_tar_pull pull, void *pctx,
                        const epk_tar_entry *e)
{
    char full[768], rel[412];
    uint8_t buf[8192];
    long n;
    uint64_t left;
    epk_file f;

    epk_strlcpy(rel, e->name, sizeof(rel));
    {
        size_t rl = strlen(rel);
        while (rl && rel[rl-1] == '/') rel[--rl] = 0;   /* strip trailing / */
    }
    if (!rel[0]) return 1;
    if (!path_safe(rel)) {
        epk_snprintf(st->why, sizeof(st->why),
                     "unsafe path in package: %s", rel);
        st->error = 1;
        return 0;
    }

    if (e->type == '5') {                        /* directory */
        epk_snprintf(full, sizeof(full), "%s%s", st->root, rel);
        mk_parents(full);
        epk_mkdir(full);
        return 1;
    }
    if (e->type == '2') {                        /* symlink */
        char target[256];

        if (!st->symkeep) {
            say("note: skipping symlink ");
            say(rel);
            say("\n");
            return 1;
        }
        if (path_crosses_link(st, rel)) {
            epk_snprintf(st->why, sizeof(st->why),
                         "entry under a symlink of this package: %s", rel);
            st->error = 1;
            return 0;
        }
        if (!e->link[0]) {
            epk_snprintf(st->why, sizeof(st->why),
                         "symlink without target: %s", rel);
            st->error = 1;
            return 0;
        }
        epk_strlcpy(target, e->link, sizeof(target));
        epk_snprintf(full, sizeof(full), "%s%s", st->root, rel);
        mk_parents(full);
        epk_unlink(full);                        /* replace silently */
        if (epk_symlink(target, full) != 0) {
            say("note: cannot create symlink (no OS support?), skipping: ");
            say(rel);
            say("\n");
            return 1;
        }
        if (st->nlinks < EPK_MAX_LINKS)
            epk_strlcpy(st->links[st->nlinks++], rel,
                        sizeof(st->links[0]));
        record_file(st, rel);    /* DB list: remove() unlinks links */
        return 1;
    }
    if (e->type != '0' && e->type != 0 && e->type != 'L')
        return 1;                                /* hardlink etc. */

    if (is_pkginfo_name(rel)) {
        /* read whole PKGINFO (bounded) */
        char pibuf[16384];
        unsigned plen = 0;
        if (e->size > sizeof(pibuf) - 1) {
            epk_snprintf(st->why, sizeof(st->why), "PKGINFO too large");
            st->error = 1;
            return 0;
        }
        while (plen < (unsigned)e->size) {
            n = epk_tar_read(tar, pull, pctx, (uint8_t *)pibuf + plen,
                             (unsigned)e->size - plen);
            if (n <= 0) {
                epk_snprintf(st->why, sizeof(st->why), "truncated PKGINFO");
                st->error = 1;
                return 0;
            }
            plen += (unsigned)n;
        }
        pibuf[plen] = 0;
        if (epk_pkginfo_parse(&st->pi, pibuf, plen) != 0) {
            epk_snprintf(st->why, sizeof(st->why), "bad PKGINFO");
            st->error = 1;
            return 0;
        }
        st->have_pkginfo = 1;
        return 1;
    }

    if (!record_file(st, rel)) return 0;

    epk_snprintf(full, sizeof(full), "%s%s", st->root, rel);
    mk_parents(full);
    f = epk_open(full, EPK_O_WRONLY | EPK_O_CREATE | EPK_O_TRUNC);
    if (!f) {
        epk_snprintf(st->why, sizeof(st->why), "cannot create %s", rel);
        st->error = 1;
        return 0;
    }

    {
        /* manifest: u32le(pathlen) path u32le(contentlen) content */
        uint8_t lb[4];
        size_t pl = strlen(rel);
        uint64_t sz = e->size;
        lb[0] = (uint8_t)(pl & 0xff);
        lb[1] = (uint8_t)((pl >> 8) & 0xff);
        lb[2] = 0;
        lb[3] = 0;
        epk_sha256_update(&st->manifest, lb, 4);
        epk_sha256_update(&st->manifest, rel, pl);
        lb[0] = (uint8_t)(sz & 0xff);
        lb[1] = (uint8_t)((sz >> 8) & 0xff);
        lb[2] = (uint8_t)((sz >> 16) & 0xff);
        lb[3] = (uint8_t)((sz >> 24) & 0xff);
        epk_sha256_update(&st->manifest, lb, 4);
    }

    left = e->size;
    while (left) {
        n = epk_tar_read(tar, pull, pctx, buf,
                         left > sizeof(buf) ? sizeof(buf) : (unsigned)left);
        if (n <= 0) {
            epk_snprintf(st->why, sizeof(st->why), "truncated entry %s", rel);
            st->error = 1;
            epk_close(f);
            return 0;
        }
        if (epk_write(f, buf, (unsigned)n) != n) {
            epk_snprintf(st->why, sizeof(st->why), "write failed %s", rel);
            st->error = 1;
            epk_close(f);
            return 0;
        }
        epk_sha256_update(&st->manifest, buf, (unsigned)n);
        left -= (uint64_t)n;
    }
    epk_close(f);
    return 1;
}

static int install_from_file(epkg_ctx *ctx, const char *path,
                             const epk_idx_entry *e)
{
    epk_file f;
    gzs_t g;
    epk_tar tar;
    epk_tar_entry te;
    extract_state st;
    char hex[65], msg[300];
    uint8_t digest[32];
    int r;

    f = epk_open(path, EPK_O_RDONLY);
    if (!f) {
        err_set(ctx, "cannot open cached package");
        return 1;
    }

    memset(&g, 0, sizeof(g));
    g.f = f;
    epk_buf_init(&g.out);
    epk_gz_init(&g.gz, gz_out, &g);

    epk_tar_init(&tar);

    memset(&st, 0, sizeof(st));
    st.root = ctx->conf->root;
    st.files = (char (*)[256])epk_malloc(EPK_MAX_FILES * 256);
    st.links = (char (*)[256])epk_malloc(EPK_MAX_LINKS * 256);
    st.symkeep = strcmp(ctx->conf->symlinks, "keep") == 0;
    if (!st.files || !st.links) {
        epk_free(st.files);
        epk_free(st.links);
        epk_buf_free(&g.out);
        epk_close(f);
        err_set(ctx, "out of memory");
        return 1;
    }
    epk_sha256_init(&st.manifest);

    /* PKGINFO must come first in every .epkg we produce; walk until seen */
    r = epk_tar_next(&tar, gzs_pull, &g, &te);
    while (r == 1) {
        if (is_pkginfo_name(te.name)) {
            char pibuf[16384];
            unsigned plen = 0;
            long n;
            if (te.size > sizeof(pibuf) - 1) {
                err_set(ctx, "PKGINFO too large");
                goto fail;
            }
            while (plen < (unsigned)te.size) {
                n = epk_tar_read(&tar, gzs_pull, &g,
                                 (uint8_t *)pibuf + plen,
                                 (unsigned)te.size - plen);
                if (n <= 0) { err_set(ctx, "truncated PKGINFO"); goto fail; }
                plen += (unsigned)n;
            }
            pibuf[plen] = 0;
            if (epk_pkginfo_parse(&st.pi, pibuf, plen) != 0) {
                err_set(ctx, "bad PKGINFO inside package");
                goto fail;
            }
            st.have_pkginfo = 1;
            break;                                /* entries follow */
        }
        /* PKGINFO must be first: anything before it is unexpected */
        if (epk_tar_skip(&tar, gzs_pull, &g) != 0) break;
        r = epk_tar_next(&tar, gzs_pull, &g, &te);
    }
    if (r != 1 || !st.have_pkginfo) {
        err_set(ctx, "no PKGINFO in package (corrupt archive?)");
        goto fail;
    }

    /* metadata sanity vs index */
    if (e && strcmp(st.pi.pkgname, e->pkgname) != 0) {
        epk_snprintf(ctx->last_err, sizeof(ctx->last_err),
                     "PKGINFO name %s does not match index %s",
                     st.pi.pkgname, e->pkgname);
        goto fail;
    }

    /* remaining entries */
    for (;;) {
        r = epk_tar_next(&tar, gzs_pull, &g, &te);
        if (r == 0) break;
        if (r < 0) {
            epk_snprintf(ctx->last_err, sizeof(ctx->last_err),
                         "archive error: %s", g.err ? "corrupt data" : "tar");
            goto fail;
        }
        if (!handle_entry(&st, &tar, gzs_pull, &g, &te)) {
            err_set(ctx, st.why);
            goto fail;
        }
    }

    if (g.err) {
        err_set(ctx, "corrupt gzip data");
        goto fail;
    }

    /* manifest integrity */
    if (st.pi.sha256[0]) {
        epk_sha256_final(&st.manifest, digest);
        epk_hex(digest, 32, hex);
        if (strcmp(hex, st.pi.sha256) != 0) {
            err_set(ctx, "package content hash mismatch (PKGINFO.sha256)");
            goto fail;
        }
    }

    /* register */
    {
        epk_db_rec rec;
        memset(&rec, 0, sizeof(rec));
        epk_strlcpy(rec.pkgname, st.pi.pkgname, sizeof(rec.pkgname));
        epk_strlcpy(rec.pkgver, st.pi.pkgver, sizeof(rec.pkgver));
        epk_strlcpy(rec.pkgdesc, st.pi.pkgdesc, sizeof(rec.pkgdesc));
        epk_strlcpy(rec.deps, st.pi.deps, sizeof(rec.deps));
        if (epk_db_add(ctx->conf->db, &rec,
                       st.files, st.nfiles) != 0) {
            err_set(ctx, "failed to update installed db");
            goto fail;
        }
    }
    epk_snprintf(msg, sizeof(msg), "installed %s-%s (%u files%s)\n",
                 st.pi.pkgname, st.pi.pkgver, st.nfiles,
                 st.nlinks ? ", incl. symlinks" : "");
    say(msg);

    epk_free(st.files);
    epk_free(st.links);
    epk_buf_free(&g.out);
    epk_close(f);
    return 0;
fail:
    epk_free(st.files);
    epk_free(st.links);
    epk_buf_free(&g.out);
    epk_close(f);
    return 1;
}

/* ------------------------------------------------------------------ */
/* commands (continued)                                                */

static int db_installed_cb(const char *name, char *ver, unsigned cap,
                           void *ud)
{
    epkg_ctx *ctx = (epkg_ctx *)ud;
    epk_db_rec rec;
    if (!epk_db_installed(ctx->conf->db, name, &rec)) return 0;
    if (ver && cap) epk_strlcpy(ver, rec.pkgver, cap);
    return 1;
}

/* ------------------------------------------------------------------ */
/* world file helpers (apk-style "explicitly installed" list)          */

static void world_add_many(epkg_ctx *ctx, const char *const *names,
                           unsigned n)
{
    if (epk_db_world_add(ctx->conf->db, names, n) != 0)
        say("WARNING: failed to update the world file\n");
}

/* genesis bootstrap hint: printed after a successful transaction that
 * went into a non-default root */
static void genesis_hint(epkg_ctx *ctx)
{
    char msg[600];
    if (strcmp(ctx->conf->root, "/") == 0) return;
    epk_snprintf(msg, sizeof(msg),
                 "genesis: image root '%s' updated (db: %s).\n"
                 "         next step: chroot %s /bin/sh\n",
                 ctx->conf->root, ctx->conf->db, ctx->conf->root);
    say(msg);
}

int epkg_cmd_fetch(epkg_ctx *ctx, const char *name)
{
    const epk_idx_entry *e;

    if (ensure_index(ctx, 0) != 0) return 1;
    e = epk_index_get(&ctx->ix, name);
    if (!e) {
        epk_snprintf(ctx->last_err, sizeof(ctx->last_err),
                     "package not found: %s", name);
        return 1;
    }
    return fetch_to_cache(ctx, e);
}

int epkg_cmd_search(epkg_ctx *ctx, const char *term)
{
    const epk_idx_entry *res[64];
    unsigned n, i;
    char line[400];

    if (ensure_index(ctx, 0) != 0) return 1;
    n = epk_index_search(&ctx->ix, term, res, 64);
    for (i = 0; i < n; i++) {
        epk_snprintf(line, sizeof(line), "%-20s %-12s %s\n",
                     res[i]->pkgname, res[i]->pkgver, res[i]->pkgdesc);
        say(line);
    }
    if (!n) say("no results\n");
    return 0;
}

int epkg_cmd_info(epkg_ctx *ctx, const char *name)
{
    const epk_idx_entry *e;
    char line[400];
    epk_db_rec rec;

    if (ensure_index(ctx, 0) != 0) return 1;
    e = epk_index_get(&ctx->ix, name);
    if (!e) {
        epk_snprintf(ctx->last_err, sizeof(ctx->last_err),
                     "package not found: %s", name);
        return 1;
    }
    epk_snprintf(line, sizeof(line),
                 "name    : %s\nversion : %s\ndesc    : %s\nsize    : %lld\n",
                 e->pkgname, e->pkgver, e->pkgdesc, e->size);
    say(line);
    if (e->deps[0]) {
        epk_snprintf(line, sizeof(line), "deps    : %s\n", e->deps);
        say(line);
    }
    if (e->filename[0]) {
        epk_snprintf(line, sizeof(line), "file    : %s\nsha256  : %s\n",
                     e->filename, e->sha256);
        say(line);
    }
    say(epk_db_installed(ctx->conf->db, name, &rec)
        ? "status  : installed\n" : "status  : not installed\n");
    return 0;
}

int epkg_cmd_list(epkg_ctx *ctx)
{
    char **names;
    unsigned n, i;
    char line[400];
    epk_db_rec rec;

    names = epk_db_list(ctx->conf->db, &n);
    if (!names) { say("no packages installed\n"); return 0; }
    if (n == 0) say("no packages installed\n");
    for (i = 0; i < n; i++) {
        epk_db_installed(ctx->conf->db, names[i], &rec);
        epk_snprintf(line, sizeof(line), "%-20s %-12s %s%s\n",
                     names[i], rec.pkgver, rec.pkgdesc,
                     epk_db_world_has(ctx->conf->db, names[i])
                         ? "  [world]" : "");
        say(line);
    }
    epk_db_files_free(names, n);
    return 0;
}

/* install one package (no dependency logic — callers resolve first) */
static int remove_one(epkg_ctx *ctx, const char *name, int warn_reverse);

static int install_one(epkg_ctx *ctx, const char *name)
{
    const epk_idx_entry *e = epk_index_get(&ctx->ix, name);
    char path[600], msg[300];
    epk_db_rec rec;

    if (!e) {
        epk_snprintf(ctx->last_err, sizeof(ctx->last_err),
                     "package not found: %s", name);
        return 1;
    }
    if (epk_db_installed(ctx->conf->db, name, &rec) &&
        strcmp(rec.pkgver, e->pkgver) == 0) {
        epk_snprintf(msg, sizeof(msg), "%s-%s already installed\n",
                     name, rec.pkgver);
        say(msg);
        return 0;
    }

    /* reinstall/replace: remove old files first (no reverse-dep noise) */
    if (epk_db_installed(ctx->conf->db, name, &rec))
        remove_one(ctx, name, 0);

    epk_snprintf(msg, sizeof(msg), "installing %s-%s\n",
                 e->pkgname, e->pkgver);
    say(msg);

    if (fetch_to_cache(ctx, e) != 0) return 1;
    epk_snprintf(path, sizeof(path), "%s/%s", ctx->conf->cache,
                 e->filename[0] ? e->filename : e->pkgname);
    return install_from_file(ctx, path, e);
}

int epkg_cmd_install(epkg_ctx *ctx, const char *const *names,
                     unsigned n, unsigned flags)
{
    unsigned k;

    if (ensure_index(ctx, 0) != 0) return 1;

    if (flags & EPKG_F_NO_DEPS) {
        /* v1 semantics: install exactly the named packages, warn about
         * their direct dependencies, resolve nothing */
        for (k = 0; k < n; k++) {
            const epk_idx_entry *e = epk_index_get(&ctx->ix, names[k]);
            char deps[256], *tok, *next, msg[300];
            if (!e) {
                epk_snprintf(ctx->last_err, sizeof(ctx->last_err),
                             "package not found: %s", names[k]);
                return 1;
            }
            epk_strlcpy(deps, e->deps, sizeof(deps));
            tok = deps;
            while (tok && *tok) {
                char dname[64], dver[64], dop;
                next = strchr(tok, ',');
                if (next) *next++ = 0;
                if (epk_dep_parse(tok, dname, sizeof(dname), &dop,
                                  dver, sizeof(dver)) == 0 &&
                    !epk_db_installed(ctx->conf->db, dname, 0)) {
                    epk_snprintf(msg, sizeof(msg),
                                 "WARNING: dependency missing for %s: %s\n",
                                 names[k], dname);
                    say(msg);
                }
                tok = next;
            }
        }
        for (k = 0; k < n; k++)
            if (install_one(ctx, names[k]) != 0) return 1;
        world_add_many(ctx, names, n);
        genesis_hint(ctx);
        return 0;
    }

    /* dep-resolution v2 */
    {
        epk_dep_plan plan;
        unsigned i;
        char msg[400];

        if (epk_dep_plan_init(&plan) != 0) {
            err_set(ctx, "out of memory");
            return 1;
        }
        if (epk_dep_resolve(&ctx->ix, names, n, db_installed_cb, ctx,
                            &plan) != 0) {
            epk_dep_plan_free(&plan);
            err_set(ctx, "dependency resolution failed (out of memory)");
            return 1;
        }
        if (plan.nmissing) {
            epk_strlcpy(msg, "unsatisfiable, not in index: ", sizeof(msg));
            for (i = 0; i < plan.nmissing; i++) {
                epk_strlcat(msg, plan.missing[i], sizeof(msg));
                if (i + 1 < plan.nmissing) epk_strlcat(msg, ", ", sizeof(msg));
            }
            epk_dep_plan_free(&plan);
            epk_strlcpy(ctx->last_err, msg, sizeof(ctx->last_err));
            return 1;
        }
        if (plan.nconflicts) {
            say("dependency conflicts:\n");
            for (i = 0; i < plan.nconflicts; i++) {
                say("  ");
                say(plan.conflicts[i]);
                say("\n");
            }
            epk_dep_plan_free(&plan);
            epk_strlcpy(ctx->last_err,
                        "refusing to install (use --no-deps to override)",
                        sizeof(ctx->last_err));
            return 1;
        }

        if (plan.norder > n) {           /* extra deps were pulled in */
            epk_snprintf(msg, sizeof(msg), "plan (%u): ", plan.norder);
            say(msg);
            for (i = 0; i < plan.norder; i++) {
                const epk_idx_entry *e =
                    epk_index_get(&ctx->ix, plan.order[i]);
                epk_snprintf(msg, sizeof(msg), "%s%s-%s",
                             i ? ", " : "", plan.order[i],
                             e ? e->pkgver : "?");
                say(msg);
            }
            say("\n");
        }

        for (i = 0; i < plan.norder; i++) {
            if (install_one(ctx, plan.order[i]) != 0) {
                epk_dep_plan_free(&plan);
                return 1;
            }
        }
        world_add_many(ctx, names, n);
        epk_dep_plan_free(&plan);
        genesis_hint(ctx);
        return 0;
    }
}

/* epkg upgrade [names...]
 *
 * No names: upgrade every package in the world file that has a newer
 * version in the index. With names: upgrade (or install) exactly those
 * and record them in world. Dependencies of the new versions are
 * re-resolved; outdated deps are pulled up to the index version instead
 * of failing the transaction (EPK_DEP_F_UPGRADE).
 */
int epkg_cmd_upgrade(epkg_ctx *ctx, const char *const *names, unsigned n)
{
    static const char *roots[512];
    unsigned nroots = 0, i;
    char msg[400];
    char **owned_world = 0;
    unsigned nworld = 0;

    if (ensure_index(ctx, 0) != 0) return 1;

    if (n == 0) {
        /* upgrade all world packages that are outdated in the index */
        owned_world = epk_db_world_list(ctx->conf->db, &nworld);
        if (!owned_world || nworld == 0) {
            epk_db_files_free(owned_world, nworld);
            say("(nothing to do: world is empty)\n");
            return 0;
        }
        for (i = 0; i < nworld && nroots < 512; i++) {
            const epk_idx_entry *e = epk_index_get(&ctx->ix, owned_world[i]);
            epk_db_rec rec;
            if (!e) {
                epk_snprintf(msg, sizeof(msg),
                             "WARNING: world package %s is not in the "
                             "index, skipping\n", owned_world[i]);
                say(msg);
                continue;
            }
            if (!epk_db_installed(ctx->conf->db, owned_world[i], &rec)) {
                roots[nroots++] = owned_world[i];   /* reinstall */
                continue;
            }
            if (epk_vercmp(e->pkgver, rec.pkgver) > 0)
                roots[nroots++] = owned_world[i];
        }
        if (nroots == 0) {
            epk_db_files_free(owned_world, nworld);
            say("(nothing to do)\n");
            return 0;
        }
    } else {
        for (i = 0; i < n && nroots < 512; i++)
            roots[nroots++] = names[i];
    }

    {
        epk_dep_plan plan;

        if (epk_dep_plan_init(&plan) != 0) {
            epk_db_files_free(owned_world, nworld);
            err_set(ctx, "out of memory");
            return 1;
        }
        if (epk_dep_resolve_ex(&ctx->ix, roots, nroots, db_installed_cb,
                               ctx, &plan, EPK_DEP_F_UPGRADE) != 0) {
            epk_dep_plan_free(&plan);
            epk_db_files_free(owned_world, nworld);
            err_set(ctx, "dependency resolution failed (out of memory)");
            return 1;
        }
        if (plan.nmissing) {
            epk_strlcpy(msg, "unsatisfiable, not in index: ", sizeof(msg));
            for (i = 0; i < plan.nmissing; i++) {
                epk_strlcat(msg, plan.missing[i], sizeof(msg));
                if (i + 1 < plan.nmissing) epk_strlcat(msg, ", ", sizeof(msg));
            }
            epk_dep_plan_free(&plan);
            epk_db_files_free(owned_world, nworld);
            epk_strlcpy(ctx->last_err, msg, sizeof(ctx->last_err));
            return 1;
        }
        if (plan.nconflicts) {
            say("dependency conflicts:\n");
            for (i = 0; i < plan.nconflicts; i++) {
                say("  ");
                say(plan.conflicts[i]);
                say("\n");
            }
            epk_dep_plan_free(&plan);
            epk_db_files_free(owned_world, nworld);
            epk_strlcpy(ctx->last_err,
                        "refusing to upgrade",
                        sizeof(ctx->last_err));
            return 1;
        }

        epk_snprintf(msg, sizeof(msg), "upgrade plan (%u): ", plan.norder);
        say(msg);
        for (i = 0; i < plan.norder; i++) {
            const epk_idx_entry *e = epk_index_get(&ctx->ix, plan.order[i]);
            epk_snprintf(msg, sizeof(msg), "%s%s-%s",
                         i ? ", " : "", plan.order[i],
                         e ? e->pkgver : "?");
            say(msg);
        }
        say("\n");

        for (i = 0; i < plan.norder; i++) {
            const epk_idx_entry *e = epk_index_get(&ctx->ix, plan.order[i]);
            epk_db_rec rec;
            if (e && epk_db_installed(ctx->conf->db, plan.order[i], &rec) &&
                epk_vercmp(e->pkgver, rec.pkgver) > 0) {
                epk_snprintf(msg, sizeof(msg), "upgrading %s %s -> %s\n",
                             plan.order[i], rec.pkgver, e->pkgver);
                say(msg);
            }
            if (install_one(ctx, plan.order[i]) != 0) {
                epk_dep_plan_free(&plan);
                epk_db_files_free(owned_world, nworld);
                return 1;
            }
        }
        epk_dep_plan_free(&plan);
    }

    if (n > 0) {
        /* explicit upgrade requests join world (apk semantics) */
        world_add_many(ctx, names, n);
    }
    epk_db_files_free(owned_world, nworld);
    genesis_hint(ctx);
    return 0;
}

int epkg_cmd_depsof(epkg_ctx *ctx, const char *const *names, unsigned n,
                    unsigned flags)
{
    epk_dep_plan plan;
    unsigned i, k;
    char msg[400];
    int bad = 0;

    if (ensure_index(ctx, 0) != 0) return 1;

    if (flags & EPKG_F_NO_DEPS) {
        for (k = 0; k < n; k++) {
            const epk_idx_entry *e = epk_index_get(&ctx->ix, names[k]);
            if (!e) {
                epk_snprintf(ctx->last_err, sizeof(ctx->last_err),
                             "package not found: %s", names[k]);
                return 1;
            }
            epk_snprintf(msg, sizeof(msg), "%s-%s deps: %s\n",
                         e->pkgname, e->pkgver,
                         e->deps[0] ? e->deps : "(none)");
            say(msg);
        }
        return 0;
    }

    if (epk_dep_plan_init(&plan) != 0) {
        err_set(ctx, "out of memory");
        return 1;
    }
    if (epk_dep_resolve(&ctx->ix, names, n, db_installed_cb, ctx,
                        &plan) != 0) {
        epk_dep_plan_free(&plan);
        err_set(ctx, "dependency resolution failed (out of memory)");
        return 1;
    }

    for (i = 0; i < plan.norder; i++) {
        const epk_idx_entry *e = epk_index_get(&ctx->ix, plan.order[i]);
        epk_db_rec rec;
        int inst = epk_db_installed(ctx->conf->db, plan.order[i], &rec);
        epk_snprintf(msg, sizeof(msg), "%u: %s-%s%s\n",
                     i, plan.order[i], e ? e->pkgver : "?",
                     inst ? " (installed)" : "");
        say(msg);
    }
    for (i = 0; i < plan.nmissing; i++) {
        epk_snprintf(msg, sizeof(msg), "missing: %s\n", plan.missing[i]);
        say(msg);
        bad = 1;
    }
    for (i = 0; i < plan.nconflicts; i++) {
        epk_snprintf(msg, sizeof(msg), "conflict: %s\n", plan.conflicts[i]);
        say(msg);
        bad = 1;
    }
    if (!plan.norder && !plan.nmissing && !plan.nconflicts)
        say("(nothing to do)\n");
    epk_dep_plan_free(&plan);
    return bad;
}

/* remove one installed package; warn_reverse: report installed packages
 * that depend on it (dep-resolution v2 keeps an eye on breakage) */
static int remove_one(epkg_ctx *ctx, const char *name, int warn_reverse)
{
    epk_db_rec rec;
    char **files;
    unsigned nf, i;
    char msg[300];

    if (!epk_db_installed(ctx->conf->db, name, &rec)) {
        epk_snprintf(ctx->last_err, sizeof(ctx->last_err),
                     "not installed: %s", name);
        return 1;
    }

    if (warn_reverse) {
        char **all = epk_db_list(ctx->conf->db, &nf);
        unsigned q;
        for (q = 0; all && q < nf; q++) {
            epk_db_rec or2;
            char deps[256], *tok, *next;
            if (strcmp(all[q], name) == 0) continue;
            if (!epk_db_installed(ctx->conf->db, all[q], &or2)) continue;
            epk_strlcpy(deps, or2.deps, sizeof(deps));
            tok = deps;
            while (tok && *tok) {
                char dname[64], dver[64], dop;
                next = strchr(tok, ',');
                if (next) *next++ = 0;
                if (epk_dep_parse(tok, dname, sizeof(dname), &dop,
                                  dver, sizeof(dver)) == 0 &&
                    strcmp(dname, name) == 0) {
                    epk_snprintf(msg, sizeof(msg),
                                 "WARNING: %s-%s depends on %s\n",
                                 all[q], or2.pkgver, name);
                    say(msg);
                    break;
                }
                tok = next;
            }
        }
        if (all) epk_db_files_free(all, nf);
    }

    epk_snprintf(msg, sizeof(msg), "removing %s-%s\n", name, rec.pkgver);
    say(msg);

    files = epk_db_files(ctx->conf->db, name, &nf);
    if (files) {
        for (i = 0; i < nf; i++) {
            char full[600];
            char *s;
            epk_snprintf(full, sizeof(full), "%s%s",
                         ctx->conf->root, files[i]);
            epk_unlink(full);          /* works on symlinks as well */
            /* try to drop now-empty parent dirs (best effort) */
            s = strrchr(full, '/');
            while (s && s != full) {
                *s = 0;
                if (epk_rmdir(full) != 0) break;
                s = strrchr(full, '/');
            }
        }
        epk_db_files_free(files, nf);
    }
    epk_db_remove(ctx->conf->db, name);
    return 0;
}

int epkg_cmd_remove(epkg_ctx *ctx, const char *const *names, unsigned n)
{
    unsigned k;

    for (k = 0; k < n; k++)
        if (remove_one(ctx, names[k], 1) != 0) return 1;
    epk_db_world_del(ctx->conf->db, names, n);
    return 0;
}
