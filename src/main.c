/* main.c — epkg command line interface. */
#include <stdio.h>
#include "epk_conf.h"
#include "epk_install.h"
#include "../include/epk_port.h"

static void usage(void)
{
    epk_print(
"epkg - package manager for hobby operating systems (apk-tools style)\n"
"\n"
"usage: epkg [options] <command> [args]\n"
"\n"
"commands:\n"
"  update               fetch fresh index.json from the mirrors\n"
"  search <term>        search the index (name + description)\n"
"  info <pkg>           show package details\n"
"  deps <pkg>...        show the resolved dependency plan\n"
"  install <pkg>...     download, verify and unpack package(s);\n"
"                       dependencies are resolved and pulled in\n"
"                       automatically (v2 resolver); names join world\n"
"  upgrade [pkg]...     upgrade world packages (or the named ones) to\n"
"                       the newest index version; dependencies of the\n"
"                       new versions are re-resolved and pulled in\n"
"  remove <pkg>...      remove installed package(s) (leaves world)\n"
"  list                 list installed packages ([world] = explicit)\n"
"  fetch <pkg>          download package to cache only\n"
"  audit                verify the ed25519 (signify) index signature:\n"
"                         epkg audit              cached index vs index.sig\n"
"                         epkg audit --repo URL   fetch and verify\n"
"                         epkg audit --file F [--sig S] [--pubkey K]\n"
"                       'epkg update' checks the signature automatically\n"
"                       when 'pubkey =' is set in epkg.conf\n"
"  version              print version\n"
"\n"
"options:\n"
"  --root <dir>         operate on a system image under <dir>\n"
"                       (genesis bootstrap: db, cache and extraction\n"
"                       all live inside the image; see README.md)\n"
"  --conf <file>        use this epkg.conf instead of the search path\n"
"  --db <dir>           override the installed-db directory\n"
"  --cachedir <dir>     override the download cache directory\n"
"  --no-deps            (install/deps) skip dependency resolution;\n"
"                       deps are only warned about (v1 behaviour)\n"
"\n"
"config: /etc/epkg.conf (mirrors, db, cache, root, ca, symlinks,\n"
"        pubkey, audit)\n"
"env   : EPKG_CONF EPKG_ROOT EPKG_DB EPKG_CACHE EPKG_CA EPKG_SYMLINKS\n"
"        EPKG_PUBKEY EPKG_AUDIT\n"
"\n"
"downloads are resumable: an interrupted fetch keeps <file>.part in the\n"
"cache and continues from where it left off (HTTP Range).\n");
}

/* split command args into flags + package names */
static int parse_args(const char *const *argv, unsigned argc,
                      const char *const **names, unsigned *nnames,
                      unsigned *flags)
{
    static const char *vec[256];
    unsigned i, n = 0;

    *flags = 0;
    for (i = 0; i < argc && n < 256; i++) {
        if (strcmp(argv[i], "--no-deps") == 0) {
            *flags |= EPKG_F_NO_DEPS;
            continue;
        }
        vec[n++] = argv[i];
    }
    *names = vec;
    *nnames = n;
    return 0;
}

/* Extract global options from anywhere in argv; the remaining tokens
 * (command + its arguments) come back through cmd/rest.  Allows both
 *   epkg --root /mnt install base
 * and
 *   epkg install --root /mnt base
 */
static void parse_globals(int argc, char **argv,
                          const char **cmd,
                          const char *const **rest, unsigned *nrest,
                          const char **opt_conf, const char **opt_root,
                          const char **opt_db, const char **opt_cachedir)
{
    static const char *vec[512];
    unsigned n = 0;
    int i;

    *cmd = 0;
    *opt_conf = *opt_root = *opt_db = *opt_cachedir = 0;
    for (i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "--conf") == 0 && i + 1 < argc) {
            *opt_conf = argv[++i];
        } else if (strcmp(a, "--root") == 0 && i + 1 < argc) {
            *opt_root = argv[++i];
        } else if (strcmp(a, "--db") == 0 && i + 1 < argc) {
            *opt_db = argv[++i];
        } else if (strcmp(a, "--cachedir") == 0 && i + 1 < argc) {
            *opt_cachedir = argv[++i];
        } else if (!*cmd) {
            *cmd = a;
        } else if (n < 512) {
            vec[n++] = a;
        }
    }
    *rest = vec;
    *nrest = n;
}

typedef struct {
    int    argc;
    char **argv;
} epk_main_args;

int epkg_main(int argc, char **argv)
{
    epk_conf conf;
    epkg_ctx ctx;
    const char *cmd, *opt_conf, *opt_root, *opt_db, *opt_cachedir;
    const char *const *args;
    unsigned nargs;

    parse_globals(argc, argv, &cmd, &args, &nargs,
                  &opt_conf, &opt_root, &opt_db, &opt_cachedir);

    if (!cmd) {
        usage();
        return 1;
    }
    if (strcmp(cmd, "version") == 0 || strcmp(cmd, "--version") == 0) {
        epk_print("epkg-tools 1.3 (C99 freestanding, BearSSL, ed25519 audit)\n");
        return 0;
    }
    if (strcmp(cmd, "help") == 0 || strcmp(cmd, "--help") == 0 ||
        strcmp(cmd, "-h") == 0) {
        usage();
        return 0;
    }

    epk_conf_defaults(&conf);
    if (opt_conf) {
        if (epk_conf_parse_file(&conf, opt_conf) != 0) {
            epk_print("epkg: cannot open config: ");
            epk_print(opt_conf);
            epk_print("\n");
            return 1;
        }
    } else {
        /* standard search: $EPKG_CONF, /etc/epkg.conf, ./epkg.conf */
        epk_conf_load(&conf);
    }
    epk_conf_env_overrides(&conf);
    if (opt_root) {
        epk_strlcpy(conf.root, opt_root, sizeof(conf.root));
        conf.root_set = 1;
    }
    epk_conf_derive_root(&conf);        /* genesis: db/cache under root */
    if (opt_db) {
        epk_strlcpy(conf.db, opt_db, sizeof(conf.db));
        conf.db_set = 1;
    }
    if (opt_cachedir) {
        epk_strlcpy(conf.cache, opt_cachedir, sizeof(conf.cache));
        conf.cache_set = 1;
    }

    epkg_open(&ctx, &conf);

    if (strcmp(cmd, "update") == 0) {
        return epkg_cmd_update(&ctx) ? 1 : 0;
    }
    if (strcmp(cmd, "search") == 0) {
        int i;
        int rc = 0;
        if (nargs < 1) { epk_print("search: missing term\n"); return 1; }
        for (i = 0; (unsigned)i < nargs && rc == 0; i++)
            rc = epkg_cmd_search(&ctx, args[i]);
        if (rc) epk_print(ctx.last_err), epk_print("\n");
        epkg_close(&ctx);
        return rc;
    }
    if (strcmp(cmd, "info") == 0) {
        int rc;
        if (nargs < 1) { epk_print("info: missing package\n"); return 1; }
        rc = epkg_cmd_info(&ctx, args[0]);
        if (rc) epk_print(ctx.last_err), epk_print("\n");
        epkg_close(&ctx);
        return rc;
    }
    if (strcmp(cmd, "deps") == 0) {
        int rc;
        unsigned flags;
        if (nargs < 1) { epk_print("deps: missing package\n"); return 1; }
        parse_args(args, nargs, &args, &nargs, &flags);
        rc = epkg_cmd_depsof(&ctx, args, nargs, flags);
        if (rc) epk_print(ctx.last_err), epk_print("\n");
        epkg_close(&ctx);
        return rc;
    }
    if (strcmp(cmd, "install") == 0) {
        int rc;
        unsigned flags;
        if (nargs < 1) { epk_print("install: missing package\n"); return 1; }
        parse_args(args, nargs, &args, &nargs, &flags);
        rc = epkg_cmd_install(&ctx, args, nargs, flags);
        if (rc) epk_print(ctx.last_err), epk_print("\n");
        epkg_close(&ctx);
        return rc;
    }
    if (strcmp(cmd, "upgrade") == 0) {
        int rc;
        rc = epkg_cmd_upgrade(&ctx, args, nargs);
        if (rc) epk_print(ctx.last_err), epk_print("\n");
        epkg_close(&ctx);
        return rc;
    }
    if (strcmp(cmd, "remove") == 0 || strcmp(cmd, "uninstall") == 0) {
        int rc;
        if (nargs < 1) { epk_print("remove: missing package\n"); return 1; }
        rc = epkg_cmd_remove(&ctx, args, nargs);
        if (rc) epk_print(ctx.last_err), epk_print("\n");
        epkg_close(&ctx);
        return rc;
    }
    if (strcmp(cmd, "list") == 0) {
        return epkg_cmd_list(&ctx) ? 1 : 0;
    }
    if (strcmp(cmd, "fetch") == 0) {
        int rc;
        if (nargs < 1) { epk_print("fetch: missing package\n"); return 1; }
        rc = epkg_cmd_fetch(&ctx, args[0]);
        if (rc) epk_print(ctx.last_err), epk_print("\n");
        epkg_close(&ctx);
        return rc;
    }
    if (strcmp(cmd, "audit") == 0) {
        const char *repo = 0, *file = 0, *sig = 0, *pk = 0;
        int i;
        for (i = 0; (unsigned)i < nargs; i++) {
            if (strcmp(args[i], "--repo") == 0 && (unsigned)(i + 1) < nargs)
                repo = args[++i];
            else if (strcmp(args[i], "--file") == 0 && (unsigned)(i + 1) < nargs)
                file = args[++i];
            else if (strcmp(args[i], "--sig") == 0 && (unsigned)(i + 1) < nargs)
                sig = args[++i];
            else if (strcmp(args[i], "--pubkey") == 0 && (unsigned)(i + 1) < nargs)
                pk = args[++i];
        }
        {
            int rc = epkg_cmd_audit(&ctx, repo, file, sig, pk);
            if (rc) epk_print(ctx.last_err), epk_print("\n");
            epkg_close(&ctx);
            return rc;
        }
    }

    epk_print("epkg: unknown command '");
    epk_print(cmd);
    epk_print("'\n\n");
    usage();
    epkg_close(&ctx);
    return 1;
}

/* epkg sits on a dedicated big stack: its deepest frames (extract,
 * PKGINFO, inflate state) overflow small kernel stacks (see
 * epk_bigstack_run in the port layer). */
static int bigstack_thunk(void *v)
{
    epk_main_args *a = (epk_main_args *)v;
    return epkg_main(a->argc, a->argv);
}

int main(int argc, char **argv)
{
    epk_main_args a;
    a.argc = argc;
    a.argv = argv;
    return epk_bigstack_run(bigstack_thunk, &a);
}

