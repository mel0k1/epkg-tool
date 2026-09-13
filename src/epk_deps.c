/*
 * epk_deps.c — dependency resolution v2 (see epk_deps.h).
 *
 * Algorithm: iterative post-order DFS over index entries.
 *   WHITE = unseen, GREY = on current chain (cycle detection), BLACK = done.
 * Post-order emission gives the deps-first install order naturally.
 */
#include "epk_deps.h"
#include "epk_util.h"
#include "../include/epk_port.h"

#include <stdint.h>

/* ------------------------------------------------------------------ */
/* version compare                                                     */

static int vdig(int c) { return c >= '0' && c <= '9'; }

int epk_vercmp(const char *a, const char *b)
{
    const unsigned char *p, *q;

    if (!a) a = "";
    if (!b) b = "";
    p = (const unsigned char *)a;
    q = (const unsigned char *)b;

    while (*p || *q) {
        if (*p && *q && vdig(*p) && vdig(*q)) {
            unsigned long x = 0, y = 0;
            while (vdig(*p)) x = x * 10 + (unsigned)(*p++ - '0');
            while (vdig(*q)) y = y * 10 + (unsigned)(*q++ - '0');
            if (x != y) return x < y ? -1 : 1;
        } else if (*p && *q && !vdig(*p) && !vdig(*q)) {
            if (*p != *q) return *p < *q ? -1 : 1;
            p++; q++;
        } else {
            /* one side ended or digit/non-digit mismatch at the same
             * position: NUL sorts below everything (shorter is smaller) */
            if (*p != *q) return *p < *q ? -1 : 1;
            p++; q++;
        }
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* dep token parsing                                                   */

static void dep_trim(char *s)
{
    size_t n = strlen(s);
    while (n && (s[n-1] == ' ' || s[n-1] == '\t' ||
                 s[n-1] == '\r' || s[n-1] == '\n'))
        s[--n] = 0;
    {
        size_t off = 0;
        while (s[off] == ' ' || s[off] == '\t') off++;
        if (off) memmove(s, s + off, n - off + 1);
    }
}

int epk_dep_parse(const char *tok,
                  char *name, unsigned namecap,
                  char *op, char *ver, unsigned vercap)
{
    const char *c = tok;
    const char *nstart;
    size_t nl;
    const char *vstart = 0;

    *op = 0;
    ver[0] = 0;
    if (!tok) return -1;

    while (*c == ' ' || *c == '\t') c++;
    nstart = c;
    while (*c && *c != '=' && *c != '<' && *c != '>' &&
           *c != ' ' && *c != '\t')
        c++;
    nl = (size_t)(c - nstart);
    if (nl == 0 || nl >= namecap) return -1;
    memcpy(name, nstart, nl);
    name[nl] = 0;

    /* skip whitespace before operator */
    while (*c == ' ' || *c == '\t') c++;

    if (*c == '>' || *c == '<' || *c == '=') {
        char o = *c++;
        if (*c == '=' && o != '=') {          /* ">=" or "<=" */
            o = (o == '>') ? 'G' : 'L';
            c++;
        } else if (*c == '=') {               /* "==" */
            c++;
        }
        *op = o;
        while (*c == ' ' || *c == '\t') c++;
        vstart = c;
        while (*c && *c != ' ' && *c != '\t' && *c != ',') c++;
        {
            size_t vl = (size_t)(c - vstart);
            if (vl == 0 || vl >= vercap) return -1;
            memcpy(ver, vstart, vl);
            ver[vl] = 0;
        }
    }
    dep_trim(name);
    dep_trim(ver);
    if (!name[0]) return -1;
    if (*op && !ver[0]) return -1;      /* operator without version */
    return 0;
}

int epk_dep_satisfied(char op, const char *want, const char *have)
{
    int c;
    if (!want || !want[0]) return 1;
    if (!have || !have[0]) return 0;
    c = epk_vercmp(have, want);
    switch (op ? op : '=') {
    case '=': return c == 0;
    case '<': return c <  0;
    case '>': return c >  0;
    case 'L': return c <= 0;
    case 'G': return c >= 0;
    default:  return 0;
    }
}

/* ------------------------------------------------------------------ */
/* resolver                                                            */

int epk_dep_plan_init(epk_dep_plan *p)
{
    memset(p, 0, sizeof(*p));
    p->order     = (char (*)[64])epk_malloc(EPK_DEP_MAXPLAN * 64);
    p->missing   = (char (*)[64])epk_malloc(EPK_DEP_MAXMISS  * 64);
    p->conflicts = (char (*)[160])epk_malloc(EPK_DEP_MAXCONF * 160);
    if (!p->order || !p->missing || !p->conflicts) {
        epk_dep_plan_free(p);
        return -1;
    }
    return 0;
}

void epk_dep_plan_free(epk_dep_plan *p)
{
    epk_free(p->order);
    epk_free(p->missing);
    epk_free(p->conflicts);
    memset(p, 0, sizeof(*p));
}

typedef struct {
    const epk_index       *ix;
    epk_dep_installed_fn   is_inst;
    void                  *ud;
    epk_dep_plan          *plan;
    unsigned               flags;    /* RS_F_*                            */

    uint8_t    *color;       /* per index entry: 0/1/2              */
    const char *chain[EPK_DEP_MAXDEPTH + 1];  /* names on the path  */
    unsigned    depth;
    int         hard_err;    /* OOM / overflow                      */
} rs_ctx;

#define RS_F_UPGRADE 1u   /* mirrors EPK_DEP_F_UPGRADE */

static void rs_conflict(rs_ctx *r, const char *msg)
{
    if (r->plan->nconflicts < EPK_DEP_MAXCONF)
        epk_strlcpy(r->plan->conflicts[r->plan->nconflicts++], msg, 160);
}

static void rs_missing(rs_ctx *r, const char *name)
{
    unsigned i;
    for (i = 0; i < r->plan->nmissing; i++)
        if (strcmp(r->plan->missing[i], name) == 0) return;
    if (r->plan->nmissing < EPK_DEP_MAXMISS)
        epk_strlcpy(r->plan->missing[r->plan->nmissing++], name, 64);
}

static const char *op_str(char op)
{
    switch (op) {
    case 'G': return ">=";
    case 'L': return "<=";
    case '>': return ">";
    case '<': return "<";
    case '=': return "=";
    default:  return "==";
    }
}

static int rs_in_order(rs_ctx *r, const char *name)
{
    unsigned i;
    for (i = 0; i < r->plan->norder; i++)
        if (strcmp(r->plan->order[i], name) == 0) return 1;
    return 0;
}

static int rs_push_order(rs_ctx *r, const char *name)
{
    if (r->plan->norder >= EPK_DEP_MAXPLAN || rs_in_order(r, name)) return 0;
    epk_strlcpy(r->plan->order[r->plan->norder++], name, 64);
    return 0;
}

static void rs_build_chain_msg(rs_ctx *r, const char *again,
                               char *out, unsigned cap)
{
    char line[200];
    unsigned start = 0, i;

    /* find where the cycle begins on the current path */
    for (i = 0; i < r->depth && i < EPK_DEP_MAXDEPTH; i++)
        if (strcmp(r->chain[i], again) == 0) { start = i; break; }
    line[0] = 0;
    for (i = start; i < r->depth && i < EPK_DEP_MAXDEPTH; i++) {
        if (line[0]) epk_strlcat(line, " -> ", sizeof(line));
        epk_strlcat(line, r->chain[i], sizeof(line));
    }
    epk_strlcat(line, " -> ", sizeof(line));
    epk_strlcat(line, again, sizeof(line));
    epk_strlcpy(out, line, cap);
}

static void rs_visit(rs_ctx *r, const epk_idx_entry *e);

/* handle one dep token of entry e */
static void rs_dep(rs_ctx *r, const epk_idx_entry *e, const char *tok)
{
    char name[64], ver[64], op;
    char have[64];
    const epk_idx_entry *de;

    if (epk_dep_parse(tok, name, sizeof(name), &op,
                      ver, sizeof(ver)) != 0) {
        char msg[160];
        epk_snprintf(msg, sizeof(msg),
                     "malformed dependency '%s' of %s", tok, e->pkgname);
        rs_conflict(r, msg);
        return;
    }

    /* 1) installed and satisfying? */
    have[0] = 0;
    if (r->is_inst && r->is_inst(name, have, sizeof(have), r->ud)) {
        if (epk_dep_satisfied(op, ver[0] ? ver : 0, have)) return;
        if (r->flags & RS_F_UPGRADE) {
            /* upgrade mode: pull the newer index version in instead of
             * failing the whole transaction. install_one() will then
             * replace the outdated copy. */
            de = epk_index_get(r->ix, name);
            if (de && (!ver[0] || epk_dep_satisfied(op, ver, de->pkgver))) {
                rs_visit(r, de);
                return;
            }
        }
        {
            char msg[160];
            epk_snprintf(msg, sizeof(msg),
                         "version conflict: %s needs %s %s %s, have %s",
                         e->pkgname, name, op_str(op), ver, have);
            rs_conflict(r, msg);
        }
        return;                      /* no more fallbacks */
    }

    /* 2) in the index? */
    de = epk_index_get(r->ix, name);
    if (!de) {
        rs_missing(r, name);
        return;
    }
    if (ver[0] && !epk_dep_satisfied(op, ver, de->pkgver)) {
        char msg[160];
        epk_snprintf(msg, sizeof(msg),
                     "version conflict: %s needs %s %s %s, index has %s",
                     e->pkgname, name, op_str(op), ver, de->pkgver);
        rs_conflict(r, msg);
        return;
    }

    /* 3) recurse (DFS: dependencies first) */
    rs_visit(r, de);
}

static void rs_visit(rs_ctx *r, const epk_idx_entry *e)
{
    unsigned idx = (unsigned)(e - r->ix->pkgs);
    char deps[256];
    char *tok, *next;

    if (idx >= r->ix->n) return;

    if (r->color[idx] == 2) return;                    /* done        */
    if (r->color[idx] == 1) {                          /* cycle!      */
        char msg[160];
        rs_build_chain_msg(r, e->pkgname, msg, sizeof(msg));
        rs_conflict(r, msg);
        return;
    }
    if (r->depth >= EPK_DEP_MAXDEPTH) {
        char msg[160];
        epk_snprintf(msg, sizeof(msg),
                     "dependency chain too deep (>%u) at %s",
                     (unsigned)EPK_DEP_MAXDEPTH, e->pkgname);
        rs_conflict(r, msg);
        return;
    }

    r->color[idx] = 1;                                 /* on chain    */
    r->chain[r->depth++] = e->pkgname;

    epk_strlcpy(deps, e->deps, sizeof(deps));
    tok = deps;
    while (tok && *tok) {
        next = strchr(tok, ',');
        if (next) *next++ = 0;
        if (*tok) rs_dep(r, e, tok);
        tok = next;
    }

    r->depth--;
    r->color[idx] = 2;                                 /* done        */
    rs_push_order(r, e->pkgname);
}

int epk_dep_resolve_ex(const epk_index *ix,
                       const char *const *roots, unsigned nroots,
                       epk_dep_installed_fn installed_fn, void *ud,
                       epk_dep_plan *plan, unsigned flags)
{
    rs_ctx r;
    unsigned k;

    memset(&r, 0, sizeof(r));
    r.ix = ix;
    r.is_inst = installed_fn;
    r.ud = ud;
    r.plan = plan;
    r.flags = flags & EPK_DEP_F_UPGRADE;

    r.color = (uint8_t *)epk_malloc(ix->n ? ix->n : 1);
    if (!r.color) return -1;
    memset(r.color, 0, ix->n ? ix->n : 1);

    for (k = 0; k < nroots; k++) {
        char name[64], ver[64], op;
        const epk_idx_entry *e;

        /* roots go in even if already installed (caller decides) */
        if (epk_dep_parse(roots[k], name, sizeof(name), &op,
                          ver, sizeof(ver)) != 0) {
            char msg[160];
            epk_snprintf(msg, sizeof(msg), "bad package name '%s'",
                         roots[k]);
            rs_conflict(&r, msg);
            continue;
        }
        e = epk_index_get(ix, name);
        if (!e) {
            rs_missing(&r, name);
            continue;
        }
        if (ver[0]) {
            /* explicit constraint on the root itself */
            if (!epk_dep_satisfied(op, ver, e->pkgver)) {
                char msg[160];
                epk_snprintf(msg, sizeof(msg),
                             "version conflict: requested %s %s %s, "
                             "index has %s",
                             name, op_str(op), ver, e->pkgver);
                rs_conflict(&r, msg);
                continue;
            }
        }
        rs_visit(&r, e);
    }

    epk_free(r.color);
    return 0;
}

int epk_dep_resolve(const epk_index *ix,
                    const char *const *roots, unsigned nroots,
                    epk_dep_installed_fn installed_fn, void *ud,
                    epk_dep_plan *plan)
{
    return epk_dep_resolve_ex(ix, roots, nroots, installed_fn, ud,
                              plan, 0);
}
