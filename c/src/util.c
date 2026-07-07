#include "util.h"

#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

double util_monotonic_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

void util_now_iso(char *buf, size_t buflen) {
    time_t now = time(NULL);
    struct tm tm;
    gmtime_r(&now, &tm);
    strftime(buf, buflen, "%Y-%m-%dT%H:%M:%S.000Z", &tm);
}

void util_fcc_log_time(const char *iso_string, char *buf, size_t buflen) {
    int y, mo, d, h, mi, s;
    if (sscanf(iso_string, "%d-%d-%dT%d:%d:%d", &y, &mo, &d, &h, &mi, &s) >= 6) {
        snprintf(buf, buflen, "%04d-%02d-%02dT%02d:%02d:%02d", y, mo, d, h, mi, s);
        return;
    }
    time_t now = time(NULL);
    struct tm tm;
    gmtime_r(&now, &tm);
    strftime(buf, buflen, "%Y-%m-%dT%H:%M:%S", &tm);
}

int util_random_bytes(uint8_t *buf, size_t len) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return -1;
    }
    ssize_t n = read(fd, buf, len);
    close(fd);
    return (n == (ssize_t)len) ? 0 : -1;
}

int util_random_hex(char *out, size_t outlen, size_t nbytes) {
    if (outlen < nbytes * 2 + 1) {
        return -1;
    }
    uint8_t buf[64];
    if (nbytes > sizeof(buf)) {
        return -1;
    }
    if (util_random_bytes(buf, nbytes) != 0) {
        return -1;
    }
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < nbytes; i++) {
        out[i * 2] = hex[(buf[i] >> 4) & 0xF];
        out[i * 2 + 1] = hex[buf[i] & 0xF];
    }
    out[nbytes * 2] = '\0';
    return 0;
}

int util_random_base64(char *out, size_t outlen, size_t nbytes) {
    uint8_t buf[64];
    if (nbytes > sizeof(buf) || outlen < ((nbytes + 2) / 3) * 4 + 1) {
        return -1;
    }
    if (util_random_bytes(buf, nbytes) != 0) {
        return -1;
    }
    size_t o = 0;
    for (size_t i = 0; i < nbytes; i += 3) {
        uint32_t n = (uint32_t)buf[i] << 16;
        if (i + 1 < nbytes) {
            n |= (uint32_t)buf[i + 1] << 8;
        }
        if (i + 2 < nbytes) {
            n |= buf[i + 2];
        }
        out[o++] = b64_table[(n >> 18) & 63];
        out[o++] = b64_table[(n >> 12) & 63];
        out[o++] = (i + 1 < nbytes) ? b64_table[(n >> 6) & 63] : '=';
        out[o++] = (i + 2 < nbytes) ? b64_table[n & 63] : '=';
    }
    out[o] = '\0';
    return 0;
}

int util_base64_encode(const uint8_t *in, size_t inlen, char *out, size_t outlen) {
    size_t need = ((inlen + 2) / 3) * 4 + 1;
    if (outlen < need) {
        return -1;
    }
    size_t o = 0;
    for (size_t i = 0; i < inlen; i += 3) {
        uint32_t n = (uint32_t)in[i] << 16;
        if (i + 1 < inlen) {
            n |= (uint32_t)in[i + 1] << 8;
        }
        if (i + 2 < inlen) {
            n |= in[i + 2];
        }
        out[o++] = b64_table[(n >> 18) & 63];
        out[o++] = b64_table[(n >> 12) & 63];
        out[o++] = (i + 1 < inlen) ? b64_table[(n >> 6) & 63] : '=';
        out[o++] = (i + 2 < inlen) ? b64_table[n & 63] : '=';
    }
    out[o] = '\0';
    return 0;
}

int util_bytes_to_hex(const uint8_t *in, size_t inlen, char *out, size_t outlen) {
    if (outlen < inlen * 2 + 1) {
        return -1;
    }
    static const char hex[] = "0123456789ABCDEF";
    for (size_t i = 0; i < inlen; i++) {
        out[i * 2] = hex[(in[i] >> 4) & 0xF];
        out[i * 2 + 1] = hex[in[i] & 0xF];
    }
    out[inlen * 2] = '\0';
    return 0;
}

static int b64_val(int c) {
    if (c >= 'A' && c <= 'Z') {
        return c - 'A';
    }
    if (c >= 'a' && c <= 'z') {
        return c - 'a' + 26;
    }
    if (c >= '0' && c <= '9') {
        return c - '0' + 52;
    }
    if (c == '+') {
        return 62;
    }
    if (c == '/') {
        return 63;
    }
    return -1;
}

int util_base64_decode(const char *in, char *out, size_t outlen) {
    size_t len = strlen(in);
    size_t o = 0;
    uint32_t buf = 0;
    int bits = 0;

    for (size_t i = 0; i < len; i++) {
        if (in[i] == '=' || in[i] == '\n' || in[i] == '\r') {
            continue;
        }
        int v = b64_val(in[i]);
        if (v < 0) {
            continue;
        }
        buf = (buf << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (o + 1 >= outlen) {
                return -1;
            }
            out[o++] = (char)((buf >> bits) & 0xFF);
        }
    }
    if (o >= outlen) {
        return -1;
    }
    out[o] = '\0';
    return (int)o;
}

void util_trim(char *s) {
    if (!s) {
        return;
    }
    size_t len = strlen(s);
    while (len > 0 && isspace((unsigned char)s[len - 1])) {
        s[--len] = '\0';
    }
    size_t start = 0;
    while (s[start] && isspace((unsigned char)s[start])) {
        start++;
    }
    if (start > 0) {
        memmove(s, s + start, strlen(s + start) + 1);
    }
}

int util_is_hex_serial(const char *s) {
    if (!s || strlen(s) < 32) {
        return 0;
    }
    for (const char *p = s; *p; p++) {
        if (!isxdigit((unsigned char)*p)) {
            return 0;
        }
    }
    return 1;
}

void util_uppercase(char *s) {
    for (; *s; s++) {
        *s = (char)toupper((unsigned char)*s);
    }
}

void util_strlcpy(char *dst, const char *src, size_t size) {
    if (size == 0) {
        return;
    }
    snprintf(dst, size, "%s", src ? src : "");
}
