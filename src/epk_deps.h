/*
 * epk_deps.h — dependency resolution v2.
 *
 * Resolves a requested package set against the repository index into an
 * install plan (topologically sorted, dependencies first), with:
 *   - automatic pull-in of missing dependencies
 *   - version constraints:  name, name=1.2, name>=1.2, name>1.2,
 *                           name<=1.2, name<1.2
 *   - already-installed packages satisfy their dependents
 *   - cycle detection (a -> b -> a) and version-conflict reporting
 *   - missing-package reporting (dep named but not in the index)
 */
#ifndef EPK_DEPS_H
#define EPK_DEPS_H

#include "epk_index.h"

#define EPK_DEP_MAXPLAN   512   /* max packages in one plan          */
#define EPK_DEP_MAXMISS    64   /* max reported missing packages     */
#define EPK_DEP_MAXCONF     8   /* max reported conflicts/cycles     */
#define EPK_DEP_MAXDEPTH   64   /* max dependency chain depth        */

typedef struct {
    char  (*order)[64];      /* install order, dependencies first  */
    unsigned norder;
    char  (*missing)[64];    /* required names absent from index   */
    unsigned nmissing;
    char  (*conflicts)[160]; /* cycles / version conflicts (text)  */
    unsigned nconflicts;
} epk_dep_plan;

/* Prepare a plan (allocates the arrays). 0 on success. */
int  epk_dep_plan_init(epk_dep_plan *p);
void epk_dep_plan_free(epk_dep_plan *p);

/* Query callback: is package <name> installed? If yes and ver_out is
 * non-NULL, copy the installed version into it. 1 = installed. */
typedef int (*epk_dep_installed_fn)(const char *name,
                                    char *ver_out, unsigned vercap,
                                    void *ud);

/* Resolve the dependency closure of roots[] against the index.
 * Always produces a best-effort plan; problems are reported in the plan:
 *   - nmissing / nconflicts > 0  => caller should refuse (or fall back
 *     to its own policy, e.g. --no-deps).
 * Returns 0 on success (including "plan with problems"), -1 on hard
 * error (OOM, too many packages). */
int epk_dep_resolve(const epk_index *ix,
                    const char *const *roots, unsigned nroots,
                    epk_dep_installed_fn installed_fn, void *ud,
                    epk_dep_plan *plan);

/* Flags for epk_dep_resolve_ex. */
#define EPK_DEP_F_UPGRADE  1u   /* outdated deps are pulled up to the
                                 * index version instead of failing
                                 * with a version conflict ("epkg
                                 * upgrade" builds on this) */

/* Like epk_dep_resolve, but with behaviour flags. */
int epk_dep_resolve_ex(const epk_index *ix,
                       const char *const *roots, unsigned nroots,
                       epk_dep_installed_fn installed_fn, void *ud,
                       epk_dep_plan *plan, unsigned flags);

/* Parse one dependency token: "name", "name=1.2", "name>=1.2" ...
 * name/ver must hold the pieces; *op gets one of:
 *   0  plain name      '='  exact       '>'  strictly greater
 *   '<' strictly less  'G'  greater-or-equal    'L'  less-or-equal
 * Whitespace around the pieces is stripped. 0 on success. */
int epk_dep_parse(const char *tok,
                  char *name, unsigned namecap,
                  char *op, char *ver, unsigned vercap);

/* Does version "have" satisfy "op want"? op==0 or '=' means exact;
 * NULL/empty have means "unknown" (never satisfies an exact want). */
int epk_dep_satisfied(char op, const char *want, const char *have);

/* Compare two versions. <0 / 0 / >0. Segment-wise: numeric runs compare
 * numerically, everything else bytewise; separators cancel when equal.
 *   1.2.10 > 1.2.9   1.0-r1 > 1.0-r0   1.0 > 0.99   1.02 == 1.2 */
int epk_vercmp(const char *a, const char *b);

#endif
