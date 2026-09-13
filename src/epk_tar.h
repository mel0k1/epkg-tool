/* Streaming USTAR (POSIX tar) reader. */
#ifndef EPK_TAR_H
#define EPK_TAR_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    char     name[412];        /* prefix + name, NUL-terminated  */
    char     link[100];
    uint64_t size;
    unsigned mode;
    unsigned mtime;
    char     type;             /* '0' file '5' dir '1' hard '2' symlink */
} epk_tar_entry;

/* pull callback: like read(2): >0 bytes, 0 = EOF, <0 = error */
typedef long (*epk_tar_pull)(void *ctx, uint8_t *buf, unsigned len);

typedef struct {
    uint8_t  blk[512];
    unsigned blkpos;
    int      state;              /* 0 want header, 1 in payload/pad, 2 eof */
    uint64_t entsize;            /* full size of current entry          */
    uint64_t remaining;          /* payload bytes not yet consumed      */
    char     longname[1024];
    int      has_longname;
    int      err;
} epk_tar;

void epk_tar_init(epk_tar *t);

/* Advance to the next entry.
 * Returns 1 = entry filled, 0 = clean end of archive, -1 = error. */
int epk_tar_next(epk_tar *t, epk_tar_pull pull, void *ctx, epk_tar_entry *e);

/* Read entry payload (only for regular files; size tracked internally). */
long epk_tar_read(epk_tar *t, epk_tar_pull pull, void *ctx,
                  uint8_t *buf, unsigned len);

/* Discard the rest of the current entry payload. 0 ok, -1 err. */
int epk_tar_skip(epk_tar *t, epk_tar_pull pull, void *ctx);

#endif
