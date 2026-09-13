/* epk_crc32.c — CRC-32 and Adler-32. */
#include "epk_crc32.h"

uint32_t epk_crc32(uint32_t crc, const void *data, size_t n)
{
    static uint32_t table[256];
    static int have = 0;
    const uint8_t *p = (const uint8_t *)data;
    uint32_t c = crc ^ 0xFFFFFFFFu;

    if (!have) {
        uint32_t i, k, v;
        for (i = 0; i < 256; i++) {
            v = i;
            for (k = 0; k < 8; k++)
                v = (v & 1) ? 0xEDB88320u ^ (v >> 1) : v >> 1;
            table[i] = v;
        }
        have = 1;
    }
    while (n--) c = table[(c ^ *p++) & 0xFFu] ^ (c >> 8);
    return c ^ 0xFFFFFFFFu;
}

uint32_t epk_adler32(uint32_t s, const void *data, size_t n)
{
    uint32_t a = s & 0xFFFFu, b = (s >> 16) & 0xFFFFu;
    const uint8_t *p = (const uint8_t *)data;

    while (n) {
        size_t chunk = n > 5552 ? 5552 : n;
        n -= chunk;
        while (chunk--) {
            a += *p++;
            b += a;
        }
        a %= 65521u;
        b %= 65521u;
    }
    return (b << 16) | a;
}
