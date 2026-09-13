/*
 * epk_libc.h — minimal string/memory declarations used by the epkg core.
 *
 * The core assumes the classic mem/str functions below exist in the
 * environment (any freestanding compiler runtime already requires
 * memcpy/memset/memmove/memcmp, and every hobby OS ships the rest).
 * If your OS lacks one, provide it — see PORTING.md. Nothing else
 * from libc is used anywhere in the core.
 */
#ifndef EPK_LIBC_H
#define EPK_LIBC_H

#include <stdint.h>
#include <stddef.h>

void *memcpy(void *dst, const void *src, size_t n);
void *memmove(void *dst, const void *src, size_t n);
void *memset(void *dst, int c, size_t n);
int   memcmp(const void *a, const void *b, size_t n);
size_t strlen(const char *s);
char *strcpy(char *dst, const char *src);
int   strcmp(const char *a, const char *b);
int   strncmp(const char *a, const char *b, size_t n);
char *strchr(const char *s, int c);
char *strrchr(const char *s, int c);
char *strstr(const char *haystack, const char *needle);
void *memchr(const void *s, int c, size_t n);

/* Tiny printf-style formatter provided by the core itself (epk_util.c):
 * supports %s %c %d %i %u %x %X %p %zu %llu, %% and width with '0'-pad,
 * e.g. "%08x". Enough for paths, sizes and hex dumps; nothing more. */
int epk_snprintf(char *buf, size_t cap, const char *fmt, ...);

#endif /* EPK_LIBC_H */
