/* CRC-32 (IEEE 802.3, as used by gzip) + Adler-32. */
#ifndef EPK_CRC32_H
#define EPK_CRC32_H

#include <stdint.h>
#include <stddef.h>

uint32_t epk_crc32(uint32_t crc, const void *data, size_t n);
uint32_t epk_adler32(uint32_t s, const void *data, size_t n);

#endif
