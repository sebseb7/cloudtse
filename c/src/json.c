#include "json.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

static const char *find_key(const char *json, const char *key) {
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *p = json;
    while ((p = strstr(p, pattern)) != NULL) {
        const char *after = p + strlen(pattern);
        while (*after && isspace((unsigned char)*after)) {
            after++;
        }
        if (*after == ':') {
            return after + 1;
        }
        p++;
    }
    return NULL;
}

int json_get_string(const char *json, const char *key, char *out, size_t outlen) {
    if (!json || !key || !out || outlen == 0) {
        return -1;
    }
    const char *val = find_key(json, key);
    if (!val) {
        return -1;
    }
    while (*val && isspace((unsigned char)*val)) {
        val++;
    }
    if (*val == '"') {
        val++;
        size_t o = 0;
        while (*val && *val != '"' && o + 1 < outlen) {
            if (*val == '\\' && val[1]) {
                val++;
            }
            out[o++] = *val++;
        }
        out[o] = '\0';
        return 0;
    }
    if (*val == 'n' && strncmp(val, "null", 4) == 0) {
        out[0] = '\0';
        return 0;
    }
    size_t o = 0;
    while (*val && *val != ',' && *val != '}' && *val != ']' && !isspace((unsigned char)*val) &&
           o + 1 < outlen) {
        out[o++] = *val++;
    }
    out[o] = '\0';
    return out[0] ? 0 : -1;
}

int json_escape(const char *in, char *out, size_t outlen) {
    size_t o = 0;
    for (const char *p = in; *p; p++) {
        const char *esc = NULL;
        char single[2] = {*p, '\0'};
        switch (*p) {
        case '"':
            esc = "\\\"";
            break;
        case '\\':
            esc = "\\\\";
            break;
        case '\n':
            esc = "\\n";
            break;
        case '\r':
            esc = "\\r";
            break;
        case '\t':
            esc = "\\t";
            break;
        default:
            if (o + 1 >= outlen) {
                return -1;
            }
            out[o++] = *p;
            continue;
        }
        size_t elen = strlen(esc);
        if (o + elen >= outlen) {
            return -1;
        }
        memcpy(out + o, esc, elen);
        o += elen;
        (void)single;
    }
    if (o >= outlen) {
        return -1;
    }
    out[o] = '\0';
    return 0;
}
