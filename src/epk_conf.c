/* epk_conf.c — epkg.conf parser. */
#include "epk_conf.h"
#include "../include/epk_port.h"

/* Parse one line on a local copy. The caller walks the original
 * NUL-split buffer; mutating it here (key trim, '=' split) used to
 * break the walk and drop mirror/ca/pubkey on "key=value" lines. */
static void conf_apply_line(epk_conf *c, const char *line)
{
    char buf[512];
    char *eq, *key, *val;
    char tmp[256];
    char *h;
    size_t n;

    epk_strlcpy(buf, line, sizeof(buf));

    /* strip comments */
    h = strchr(buf, '#');
    if (h) *h = 0;

    key = buf;
    /* trim left */
    while (*key == ' ' || *key == '\t') key++;
    if (!*key) return;
    /* trim right */
    n = strlen(key);
    while (n && (key[n-1] == ' ' || key[n-1] == '\t' ||
                 key[n-1] == '\r' || key[n-1] == '\n'))
        key[--n] = 0;
    if (!*key) return;

    eq = strchr(key, '=');
    if (!eq) return;
    *eq = 0;
    val = eq + 1;
    while (*val == ' ' || *val == '\t') val++;
    n = strlen(key);
    while (n && (key[n-1] == ' ' || key[n-1] == '\t')) key[--n] = 0;

    epk_strlcpy(tmp, val, sizeof(tmp));
    if (strcmp(key, "mirror") == 0) {
        if (c->nmirrors < EPK_MAX_MIRRORS)
            epk_strlcpy(c->mirrors[c->nmirrors++], tmp,
                        sizeof(c->mirrors[0]));
    } else if (strcmp(key, "db") == 0) {
        epk_strlcpy(c->db, tmp, sizeof(c->db));
        c->db_set = 1;
    } else if (strcmp(key, "cache") == 0) {
        epk_strlcpy(c->cache, tmp, sizeof(c->cache));
        c->cache_set = 1;
    } else if (strcmp(key, "root") == 0) {
        epk_strlcpy(c->root, tmp, sizeof(c->root));
        c->root_set = 1;
    } else if (strcmp(key, "ca") == 0) {
        epk_strlcpy(c->ca, tmp, sizeof(c->ca));
        c->ca_set = 1;
    } else if (strcmp(key, "symlinks") == 0) {
        epk_strlcpy(c->symlinks, tmp, sizeof(c->symlinks));
    } else if (strcmp(key, "pubkey") == 0) {
        epk_strlcpy(c->pubkey, tmp, sizeof(c->pubkey));
        c->pubkey_set = 1;
    } else if (strcmp(key, "audit") == 0) {
        epk_strlcpy(c->audit, tmp, sizeof(c->audit));
    }
    /* unknown keys ignored (forward compatible) */
}

void epk_conf_defaults(epk_conf *c)
{
    memset(c, 0, sizeof(*c));
    epk_strlcpy(c->db, "/var/lib/epkg", sizeof(c->db));
    epk_strlcpy(c->cache, "/var/cache/epkg", sizeof(c->cache));
    epk_strlcpy(c->root, "/", sizeof(c->root));
    epk_strlcpy(c->symlinks, "deny", sizeof(c->symlinks));
    epk_strlcpy(c->audit, "strict", sizeof(c->audit));
}

int epk_conf_parse_file(epk_conf *c, const char *path)
{
    epk_file f;
    uint8_t raw[4096];
    unsigned n = 0, i;
    int r;

    f = epk_open(path, EPK_O_RDONLY);
    if (!f) return -1;
    while (n < sizeof(raw) &&
           (r = epk_read(f, raw + n, sizeof(raw) - n)) > 0)
        n += (unsigned)r;
    epk_close(f);

    /* parse: split on newlines (in place) */
    for (i = 0; i < n; i++)
        if (raw[i] == '\n' || raw[i] == '\r') raw[i] = 0;
    raw[n < sizeof(raw) ? n : sizeof(raw) - 1] = 0;
    {
        char *line = (char *)raw;
        while (*line) {
            conf_apply_line(c, line);
            line += strlen(line) + 1;
        }
    }
    return 0;
}

void epk_conf_env_overrides(epk_conf *c)
{
    const char *env;

    env = epk_getenv("EPKG_ROOT");
    if (env) { epk_strlcpy(c->root, env, sizeof(c->root)); c->root_set = 1; }
    env = epk_getenv("EPKG_DB");
    if (env) { epk_strlcpy(c->db, env, sizeof(c->db)); c->db_set = 1; }
    env = epk_getenv("EPKG_CACHE");
    if (env) { epk_strlcpy(c->cache, env, sizeof(c->cache)); c->cache_set = 1; }
    env = epk_getenv("EPKG_CA");
    if (env) { epk_strlcpy(c->ca, env, sizeof(c->ca)); c->ca_set = 1; }
    env = epk_getenv("EPKG_SYMLINKS");
    if (env) epk_strlcpy(c->symlinks, env, sizeof(c->symlinks));
    env = epk_getenv("EPKG_PUBKEY");
    if (env) { epk_strlcpy(c->pubkey, env, sizeof(c->pubkey)); c->pubkey_set = 1; }
    env = epk_getenv("EPKG_AUDIT");
    if (env) epk_strlcpy(c->audit, env, sizeof(c->audit));
}

void epk_conf_load(epk_conf *c)
{
    /* config file search */
    {
        const char *cand[3];
        int k;
        cand[0] = epk_getenv("EPKG_CONF");
        cand[1] = "/etc/epkg.conf";
        cand[2] = "epkg.conf";
        for (k = 0; k < 3; k++)
            if (cand[k] && epk_conf_parse_file(c, cand[k]) == 0) break;
    }

    epk_conf_env_overrides(c);
}

void epk_conf_derive_root(epk_conf *c)
{
    char rbuf[256], join[256];
    size_t n;

    epk_strlcpy(rbuf, c->root, sizeof(rbuf));
    n = strlen(rbuf);
    while (n > 1 && (rbuf[n-1] == '/' || rbuf[n-1] == ' ')) rbuf[--n] = 0;
    if (n == 0) { rbuf[0] = '/'; rbuf[1] = 0; }
    if (strcmp(rbuf, "/") == 0) return;   /* live system: nothing to do */

    /* join = image path without trailing slash (for <root>/var/...);
     * c->root must KEEP a trailing slash: the engine concatenates
     * root + relative-path (rel has no leading '/'), so without the
     * slash files would land in "<root>usr/..." */
    epk_strlcpy(join, rbuf, sizeof(join));
    n = strlen(rbuf);
    if (n + 1 < sizeof(rbuf)) { rbuf[n++] = '/'; rbuf[n] = 0; }
    epk_strlcpy(c->root, rbuf, sizeof(c->root));

    if (!c->db_set)
        epk_snprintf(c->db, sizeof(c->db), "%s/var/lib/epkg", join);
    if (!c->cache_set)
        epk_snprintf(c->cache, sizeof(c->cache), "%s/var/cache/epkg", join);
}
