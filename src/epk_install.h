/* epk_install.h — repository fetch + install/remove engine. */
#ifndef EPK_INSTALL_H
#define EPK_INSTALL_H

#include "epk_conf.h"
#include "epk_index.h"
#include "epk_deps.h"

typedef struct {
    const epk_conf *conf;
    epk_index       ix;          /* cached index (loaded on demand)  */
    int             ix_loaded;
    char            last_err[256];
} epkg_ctx;

/* flags for epkg_cmd_install */
#define EPKG_F_NO_DEPS   1u   /* skip dependency resolution (v1 mode) */

/* Open/close a package-manager context. */
int  epkg_open(epkg_ctx *ctx, const epk_conf *conf);
void epkg_close(epkg_ctx *ctx);

/* Commands. Return 0 on success, 1 on error (message in ctx->last_err). */
int epkg_cmd_update(epkg_ctx *ctx);
int epkg_cmd_install(epkg_ctx *ctx, const char *const *names,
                     unsigned n, unsigned flags);
int epkg_cmd_upgrade(epkg_ctx *ctx, const char *const *names, unsigned n);
int epkg_cmd_remove(epkg_ctx *ctx, const char *const *names, unsigned n);
int epkg_cmd_search(epkg_ctx *ctx, const char *term);
int epkg_cmd_info(epkg_ctx *ctx, const char *name);
int epkg_cmd_list(epkg_ctx *ctx);
int epkg_cmd_fetch(epkg_ctx *ctx, const char *name);

/* epkg audit — verify the signify/ed25519 signature of a repo index.
 *   repo != NULL     : download <repo>/index.json + index.sig and check
 *   file != NULL     : check <file> against <sigfile or file.sig>
 *   otherwise        : check the cached index in <db>/index.json vs
 *                      <db>/index.sig
 * pubkey: command-line override or conf->pubkey (path or inline base64).
 * Returns 0 if the signature is valid. */
int epkg_cmd_audit(epkg_ctx *ctx, const char *repo,
                   const char *file, const char *sigfile,
                   const char *pubkey);

/* Print the dependency plan for names[] without installing anything
 * ("epkg deps ..." command). */
int epkg_cmd_depsof(epkg_ctx *ctx, const char *const *names, unsigned n,
                    unsigned flags);

#endif
