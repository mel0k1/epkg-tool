/* epk_json.c — tiny JSON parser with stable arena. See epk_json.h. */
#include "epk_json.h"
#include "epk_util.h"
#include "../include/epk_port.h"

#define EJ_MAX_DEPTH 64

typedef struct {
    epk_json   *j;
    const char *p;
} ej_ctx;

static void ej_fail(epk_json *j, const char *msg)
{
    if (!j->failed) {
        j->failed = 1;
        epk_strlcpy(j->err, msg, sizeof(j->err));
    }
}

static ej_value *ej_newval(epk_json *j)
{
    ej_block *b = j->blocks;
    if (!b || b->used == (sizeof(b->v) / sizeof(b->v[0]))) {
        b = (ej_block *)epk_malloc(sizeof(ej_block));
        if (!b) { ej_fail(j, "oom"); return 0; }
        b->used = 0;
        b->next = j->blocks;
        j->blocks = b;
    }
    memset(&b->v[b->used], 0, sizeof(ej_value));
    return &b->v[b->used++];
}

static void ej_aux_add(epk_json *j, void *p)
{
    ej_aux *a = (ej_aux *)epk_malloc(sizeof(ej_aux));
    if (!a) return;                          /* leak on oom, acceptable */
    a->p = p;
    a->next = j->aux;
    j->aux = a;
}

static int ws(int c) { return c == ' ' || c == '\t' || c == '\n' || c == '\r'; }

static void ej_skipws(ej_ctx *c)
{
    while (*c->p && ws((unsigned char)*c->p)) c->p++;
}

static int ej_hex4(const char *p, unsigned *out)
{
    int i;
    unsigned v = 0;
    for (i = 0; i < 4; i++) {
        int d = epk_hexval((unsigned char)p[i]);
        if (d < 0) return -1;
        v = v * 16 + (unsigned)d;
    }
    *out = v;
    return 0;
}

/* decode string body into a fresh buffer; advances c->p past the
 * closing quote; result tracked in j->aux for later cleanup */
static const char *ej_escape(ej_ctx *c, unsigned *outlen)
{
    epk_json *j = c->j;
    epk_buf out;
    const char *p = c->p;

    epk_buf_init(&out);
    while (*p && *p != '"') {
        if (*p == '\\') {
            p++;
            switch (*p) {
            case '"':  epk_buf_appendc(&out, '"');  p++; break;
            case '\\': epk_buf_appendc(&out, '\\'); p++; break;
            case '/':  epk_buf_appendc(&out, '/');  p++; break;
            case 'b':  epk_buf_appendc(&out, '\b'); p++; break;
            case 'f':  epk_buf_appendc(&out, '\f'); p++; break;
            case 'n':  epk_buf_appendc(&out, '\n'); p++; break;
            case 'r':  epk_buf_appendc(&out, '\r'); p++; break;
            case 't':  epk_buf_appendc(&out, '\t'); p++; break;
            case 'u': {
                unsigned cp;
                if (ej_hex4(p + 1, &cp) != 0) {
                    epk_buf_free(&out);
                    ej_fail(j, "bad \\u escape");
                    return 0;
                }
                p += 5;
                if (cp >= 0xD800 && cp <= 0xDBFF && p[0] == '\\' && p[1] == 'u') {
                    unsigned lo;
                    if (ej_hex4(p + 2, &lo) == 0 &&
                        lo >= 0xDC00 && lo <= 0xDFFF) {
                        cp = 0x10000u + ((cp - 0xD800u) << 10) + (lo - 0xDC00u);
                        p += 6;
                    }
                }
                if (cp < 0x80) {
                    epk_buf_appendc(&out, (uint8_t)cp);
                } else if (cp < 0x800) {
                    epk_buf_appendc(&out, (uint8_t)(0xC0 | (cp >> 6)));
                    epk_buf_appendc(&out, (uint8_t)(0x80 | (cp & 0x3F)));
                } else if (cp < 0x10000) {
                    epk_buf_appendc(&out, (uint8_t)(0xE0 | (cp >> 12)));
                    epk_buf_appendc(&out, (uint8_t)(0x80 | ((cp >> 6) & 0x3F)));
                    epk_buf_appendc(&out, (uint8_t)(0x80 | (cp & 0x3F)));
                } else {
                    epk_buf_appendc(&out, (uint8_t)(0xF0 | (cp >> 18)));
                    epk_buf_appendc(&out, (uint8_t)(0x80 | ((cp >> 12) & 0x3F)));
                    epk_buf_appendc(&out, (uint8_t)(0x80 | ((cp >> 6) & 0x3F)));
                    epk_buf_appendc(&out, (uint8_t)(0x80 | (cp & 0x3F)));
                }
                break;
            }
            default:
                epk_buf_free(&out);
                ej_fail(j, "bad escape");
                return 0;
            }
        } else {
            epk_buf_appendc(&out, (uint8_t)*p++);
        }
        if (out.len > 1024u * 1024u) {
            epk_buf_free(&out);
            ej_fail(j, "string too long");
            return 0;
        }
    }
    if (*p != '"') {
        epk_buf_free(&out);
        ej_fail(j, "unterminated string");
        return 0;
    }
    epk_buf_appendc(&out, 0);
    c->p = p + 1;
    *outlen = out.len - 1;
    ej_aux_add(j, out.p);
    return (const char *)out.p;
}

static ej_value *ej_parse_value(ej_ctx *c);

static ej_value *ej_parse_string(ej_ctx *c)
{
    epk_json *j = c->j;
    unsigned len;
    const char *dec;
    ej_value *v;

    c->p++;
    dec = ej_escape(c, &len);
    if (!dec) return 0;

    v = ej_newval(j);
    if (!v) return 0;
    v->t = EJ_STR;
    v->v.str.s = dec;
    v->v.str.n = len;
    return v;
}

static ej_value *ej_parse_number(ej_ctx *c)
{
    epk_json *j = c->j;
    const char *p = c->p;
    int neg = 0;
    int64_t mant = 0;
    int exp = 0, digits = 0;
    ej_value *v;

    if (*p == '-') { neg = 1; p++; }
    while (*p >= '0' && *p <= '9') {
        if (digits < 18) { mant = mant * 10 + (*p - '0'); digits++; }
        p++;
    }
    if (*p == '.') {
        p++;
        while (*p >= '0' && *p <= '9') {
            if (digits < 18) { mant = mant * 10 + (*p - '0'); digits++; exp--; }
            p++;
        }
    }
    if (*p == 'e' || *p == 'E') {
        int sign = 1, ev = 0;
        p++;
        if (*p == '+') p++;
        else if (*p == '-') { sign = -1; p++; }
        while (*p >= '0' && *p <= '9') {
            if (ev < 18) ev = ev * 10 + (*p - '0');
            p++;
        }
        exp += sign * ev;
    }
    while (exp > 0) { mant *= 10; exp--; }
    while (exp < 0 && mant && mant % 10 == 0) { mant /= 10; exp++; }

    v = ej_newval(j);
    if (!v) return 0;
    v->t = EJ_INT;
    v->v.i = neg ? -mant : mant;
    c->p = p;
    return v;
}

static ej_value *ej_parse_array(ej_ctx *c)
{
    epk_json *j = c->j;
    ej_value *v;
    epk_buf items;
    unsigned n = 0;

    epk_buf_init(&items);
    c->p++;
    v = ej_newval(j);
    if (!v) { epk_buf_free(&items); return 0; }
    v->t = EJ_ARR;

    ej_skipws(c);
    if (*c->p == ']') { c->p++; return v; }

    for (;;) {
        ej_value *item = ej_parse_value(c);
        if (!item) { epk_buf_free(&items); return 0; }
        epk_buf_append(&items, &item, sizeof(ej_value *));
        n++;
        ej_skipws(c);
        if (*c->p == ',') { c->p++; ej_skipws(c); continue; }
        if (*c->p == ']') { c->p++; break; }
        ej_fail(j, "expected , or ]");
        epk_buf_free(&items);
        return 0;
    }
    v->v.arr.items = (ej_value **)items.p;
    v->v.arr.n = n;
    ej_aux_add(j, items.p);
    return v;
}

static ej_value *ej_parse_object(ej_ctx *c)
{
    epk_json *j = c->j;
    ej_value *v;
    epk_buf keys, vals;
    unsigned n = 0;

    epk_buf_init(&keys);
    epk_buf_init(&vals);
    c->p++;
    v = ej_newval(j);
    if (!v) { epk_buf_free(&keys); epk_buf_free(&vals); return 0; }
    v->t = EJ_OBJ;

    ej_skipws(c);
    if (*c->p == '}') { c->p++; return v; }

    for (;;) {
        const char *key;
        unsigned klen = 0;
        ej_value *val;

        ej_skipws(c);
        if (*c->p != '"') {
            ej_fail(j, "expected key string");
            goto fail;
        }
        c->p++;
        key = ej_escape(c, &klen);
        if (!key) goto fail;

        ej_skipws(c);
        if (*c->p != ':') { epk_free((void *)key); ej_fail(j, "expected :"); goto fail; }
        c->p++;
        ej_skipws(c);

        val = ej_parse_value(c);
        if (!val) { epk_free((void *)key); goto fail; }

        epk_buf_append(&keys, &key, sizeof(char *));
        epk_buf_append(&vals, &val, sizeof(ej_value *));
        n++;

        ej_skipws(c);
        if (*c->p == ',') { c->p++; continue; }
        if (*c->p == '}') { c->p++; break; }
        ej_fail(j, "expected , or }");
        goto fail;
    }
    v->v.obj.keys = (const char **)keys.p;
    v->v.obj.vals = (ej_value **)vals.p;
    v->v.obj.n = n;
    ej_aux_add(j, keys.p);
    ej_aux_add(j, vals.p);
    return v;
fail:
    epk_buf_free(&keys);
    epk_buf_free(&vals);
    return 0;
}

static ej_value *ej_parse_value(ej_ctx *c)
{
    epk_json *j = c->j;
    ej_value *v = 0;

    if (j->failed) return 0;
    if (++j->depth > EJ_MAX_DEPTH) { ej_fail(j, "too deep"); return 0; }

    ej_skipws(c);
    switch (*c->p) {
    case '"': v = ej_parse_string(c); break;
    case '[': v = ej_parse_array(c); break;
    case '{': v = ej_parse_object(c); break;
    case 't':
        if (strncmp(c->p, "true", 4) == 0) {
            v = ej_newval(j);
            if (v) { v->t = EJ_BOOL; v->v.b = 1; }
            c->p += 4;
        } else ej_fail(j, "bad literal");
        break;
    case 'f':
        if (strncmp(c->p, "false", 5) == 0) {
            v = ej_newval(j);
            if (v) { v->t = EJ_BOOL; v->v.b = 0; }
            c->p += 5;
        } else ej_fail(j, "bad literal");
        break;
    case 'n':
        if (strncmp(c->p, "null", 4) == 0) {
            v = ej_newval(j);
            if (v) v->t = EJ_NULL;
            c->p += 4;
        } else ej_fail(j, "bad literal");
        break;
    default:
        if (*c->p == '-' || (*c->p >= '0' && *c->p <= '9')) {
            v = ej_parse_number(c);
        } else {
            ej_fail(j, "unexpected character");
        }
        break;
    }
    j->depth--;
    return v;
}

int epk_json_parse(epk_json *j, char *text)
{
    ej_ctx c;
    ej_value *root;

    memset(j, 0, sizeof(*j));
    c.j = j;
    c.p = text;
    root = ej_parse_value(&c);
    if (!root) return -1;
    ej_skipws(&c);
    if (*c.p) { ej_fail(j, "trailing data"); return -1; }
    j->root = root;
    return 0;
}

void epk_json_free(epk_json *j)
{
    while (j->blocks) {
        ej_block *b = j->blocks;
        j->blocks = b->next;
        epk_free(b);
    }
    while (j->aux) {
        ej_aux *a = j->aux;
        j->aux = a->next;
        epk_free(a->p);
        epk_free(a);
    }
    memset(j, 0, sizeof(*j));
}

/* ------------------------------------------------------------------ */

ej_value *ej_get(const ej_value *obj, const char *key)
{
    unsigned i;
    if (!obj || obj->t != EJ_OBJ) return 0;
    for (i = 0; i < obj->v.obj.n; i++)
        if (strcmp(obj->v.obj.keys[i], key) == 0)
            return obj->v.obj.vals[i];
    return 0;
}

const char *ej_get_str(const ej_value *obj, const char *key)
{
    ej_value *v = ej_get(obj, key);
    return (v && v->t == EJ_STR) ? v->v.str.s : 0;
}

int64_t ej_get_int(const ej_value *obj, const char *key)
{
    ej_value *v = ej_get(obj, key);
    return (v && v->t == EJ_INT) ? v->v.i : 0;
}

int ej_get_bool(const ej_value *obj, const char *key)
{
    ej_value *v = ej_get(obj, key);
    return (v && v->t == EJ_BOOL) ? v->v.b : 0;
}

unsigned ej_arr_len(const ej_value *arr)
{
    return (arr && arr->t == EJ_ARR) ? arr->v.arr.n : 0;
}

ej_value *ej_arr_at(const ej_value *arr, unsigned i)
{
    if (!arr || arr->t != EJ_ARR || i >= arr->v.arr.n) return 0;
    return arr->v.arr.items[i];
}
