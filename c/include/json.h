#ifndef CLOUDTSE_JSON_H
#define CLOUDTSE_JSON_H

#include <stddef.h>

int json_get_string(const char *json, const char *key, char *out, size_t outlen);
int json_escape(const char *in, char *out, size_t outlen);

#endif
