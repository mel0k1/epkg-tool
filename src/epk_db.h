/* epk_db.h — installed-packages database (flat text files). */
#ifndef EPK_DB_H
#define EPK_DB_H

#include "epk_util.h"

typedef struct {
    char pkgname[64];
    char pkgver[64];
    char pkgdesc[256];
    char deps[256];
} epk_db_rec;

/* Is <name> installed? Fills rec if non-NULL. 1 = yes. */
int  epk_db_installed(const char *db, const char *name, epk_db_rec *rec);

/* Record an installed package + its file list (rows of 256-byte paths).
 * 0 on success. */
int  epk_db_add(const char *db, const epk_db_rec *rec,
                const char (*files)[256], unsigned nfiles);

/* Remove package records + file list. 0 on success. */
int  epk_db_remove(const char *db, const char *name);

/* Load the file list for an installed package.
 * Returns malloc'd array of malloc'd strings; count in *n. NULL = error. */
char **epk_db_files(const char *db, const char *name, unsigned *n);
void   epk_db_files_free(char **files, unsigned n);

/* Enumerate installed package names (malloc'd array of malloc'd strings). */
char **epk_db_list(const char *db, unsigned *n);

/* ------------------------------------------------------------------ */
/* World file (apk-style): <db>/world, one package name per line.       */
/* The world file lists packages the user explicitly asked for;         */
/* "epkg upgrade" without arguments upgrades exactly these.             */

/* Enumerate world entries (malloc'd array of malloc'd strings).
 * NULL/0 = no world file or empty. */
char **epk_db_world_list(const char *db, unsigned *n);

/* Add names to world (duplicates are ignored). 0 on success. */
int    epk_db_world_add(const char *db, const char *const *names,
                        unsigned n);

/* Drop names from world (missing names are ignored). 0 on success. */
int    epk_db_world_del(const char *db, const char *const *names,
                        unsigned n);

/* Is <name> listed in world? 1 = yes. */
int    epk_db_world_has(const char *db, const char *name);

#endif
