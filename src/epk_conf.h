/* epk_conf.h — epkg.conf parser + default paths. */
#ifndef EPK_CONF_H
#define EPK_CONF_H

#include "epk_util.h"

#define EPK_MAX_MIRRORS 8

typedef struct {
    char mirrors[EPK_MAX_MIRRORS][256];
    unsigned nmirrors;
    char db[256];        /* installed DB + cached index         */
    char cache[256];     /* downloaded .epkg cache              */
    char root[256];      /* extraction root ("/" on a real OS)  */
    char ca[256];        /* PEM bundle for TLS ("" = none)      */
    char symlinks[12];   /* "deny" (default) or "keep"          */
    char pubkey[512];    /* signify pubkey: file path OR inline
                          * base64 (starts with "RW"); "" = off */
    char audit[12];      /* "strict" (default), "warn", "off"   */

    /* which keys were explicitly set (config file, env or CLI);
     * used by epk_conf_derive_root() for genesis bootstrap */
    unsigned char db_set, cache_set, root_set, ca_set, pubkey_set;
} epk_conf;

/* Reset to built-in defaults (db=/var/lib/epkg, cache=/var/cache/epkg,
 * root=/, symlinks=deny). */
void epk_conf_defaults(epk_conf *c);

/* Parse one config file on top of the current settings. 0 on success,
 * -1 if the file cannot be opened. */
int  epk_conf_parse_file(epk_conf *c, const char *path);

/* Apply EPKG_* environment overrides. */
void epk_conf_env_overrides(epk_conf *c);

/* Load configuration (compat wrapper): defaults + config search path
 * ($EPKG_CONF, /etc/epkg.conf, ./epkg.conf) + environment overrides. */
void epk_conf_load(epk_conf *c);

/* Genesis bootstrap: if root != "/" and db/cache were NOT set
 * explicitly, place them inside the image:
 *   <root>/var/lib/epkg, <root>/var/cache/epkg.
 * Call after applying --root (or a config file "root =" line). */
void epk_conf_derive_root(epk_conf *c);

#endif
