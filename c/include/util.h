#ifndef CLOUDTSE_UTIL_H
#define CLOUDTSE_UTIL_H

#include <stddef.h>
#include <stdint.h>

void util_now_iso(char *buf, size_t buflen);
void util_fcc_log_time(const char *iso_string, char *buf, size_t buflen);
int util_random_bytes(uint8_t *buf, size_t len);
int util_random_hex(char *out, size_t outlen, size_t nbytes);
int util_random_base64(char *out, size_t outlen, size_t nbytes);
int util_base64_decode(const char *in, char *out, size_t outlen);
void util_trim(char *s);
int util_is_hex_serial(const char *s);
void util_uppercase(char *s);
void util_strlcpy(char *dst, const char *src, size_t size);

#endif
