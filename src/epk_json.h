/*
 * epk_json.h — tiny JSON parser (RFC 8259 subset) for repository indexes.
 *
 * Freestanding C99, no float math (numbers parsed as int64), values live
 * in fixed-size arena blocks (stable pointers), decoded strings tracked
 * for cleanup.
 */
#ifndef EPK_JSON_H
#define EPK_JSON_H

#include <stdint.h>
#include <stddef.h>

typedef enum {
    EJ_NULL = 0, EJ_BOOL, EJ_INT, EJ_STR, EJ_ARR, EJ_OBJ
} ej_type;

typedef struct ej_value ej_value;
struct ej_value {
    ej_type t;
    union {
        int     b;
        int64_t i;
        struct { const char *s; unsigned n; } str;
        struct { ej_value **items; unsigned n; } arr;
        struct { const char **keys; ej_value **vals; unsigned n; } obj;
    } v;
};

typedef struct ej_block ej_block;
struct ej_block {
    ej_block *next;
    unsigned  used;
    ej_value  v[128];
};

typedef struct ej_aux ej_aux;
struct ej_aux {
    ej_aux *next;
    void   *p;
};

typedef struct {
    ej_block *blocks;
    ej_aux   *aux;               /* decoded string buffers */
    unsigned  depth;
    char      err[80];
    int       failed;
    ej_value *root;
} epk_json;

/* Parse text (takes ownership; may modify it in place). 0 on success. */
int  epk_json_parse(epk_json *j, char *text);
void epk_json_free(epk_json *j);

/* ---- accessors (all NULL/error tolerant) ---- */
ej_value    *ej_get(const ej_value *obj, const char *key);
const char  *ej_get_str(const ej_value *obj, const char *key);
int64_t      ej_get_int(const ej_value *obj, const char *key);
int          ej_get_bool(const ej_value *obj, const char *key);
unsigned     ej_arr_len(const ej_value *arr);
ej_value    *ej_arr_at(const ej_value *arr, unsigned i);

#endif /* EPK_JSON_H */
