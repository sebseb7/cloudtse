#include "config.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

cloudtse_config_t g_config;

static void set_default_db_path(char *buf, size_t buflen) {
    if (buflen == 0) {
        return;
    }

    char exe[512];
    ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (n > 0) {
        exe[n] = '\0';
        char *slash = strrchr(exe, '/');
        if (slash) {
            *slash = '\0';
            slash = strrchr(exe, '/');
            if (slash) {
                *slash = '\0';
                size_t root_len = strlen(exe);
                const char *rel = CLOUDTSE_DEFAULT_DB_PATH;
                size_t rel_len = strlen(rel);
                if (root_len + 1 + rel_len < buflen) {
                    memcpy(buf, exe, root_len);
                    buf[root_len] = '/';
                    memcpy(buf + root_len + 1, rel, rel_len + 1);
                    return;
                }
            }
        }
    }
    util_strlcpy(buf, CLOUDTSE_DEFAULT_DB_PATH, buflen);
}

static const char *env_or(const char *key, const char *fallback) {
    const char *v = getenv(key);
    return (v && v[0]) ? v : fallback;
}

void config_load(void) {
    const char *host = env_or("CLOUDTSE_HOST", CLOUDTSE_DEFAULT_HOST);
    const char *port_str = env_or("CLOUDTSE_PORT", "20001");
    const char *eas = env_or("CLOUDTSE_EAS_CODE", CLOUDTSE_DEFAULT_EAS_CODE);
    const char *serial = env_or("CLOUDTSE_TSE_SERIAL", CLOUDTSE_DEFAULT_TSE_SERIAL);
    const char *fcc = env_or("CLOUDTSE_FCC_VERSION", CLOUDTSE_DEFAULT_FCC_VERSION);
    const char *db = getenv("CLOUDTSE_DB_PATH");
    const char *log = getenv("CLOUDTSE_LOG");
    const char *pub = getenv("CLOUDTSE_PUBLIC_IP");

    strncpy(g_config.host, host, sizeof(g_config.host) - 1);
    g_config.port = (uint16_t)atoi(port_str);
    if (g_config.port == 0) {
        g_config.port = CLOUDTSE_DEFAULT_PORT;
    }
    strncpy(g_config.eas_code, eas, sizeof(g_config.eas_code) - 1);
    strncpy(g_config.tse_serial, serial, sizeof(g_config.tse_serial) - 1);
    strncpy(g_config.fcc_version, fcc, sizeof(g_config.fcc_version) - 1);
    g_config.log_requests = !(log && strcmp(log, "0") == 0);

    if (db && db[0]) {
        strncpy(g_config.db_path, db, sizeof(g_config.db_path) - 1);
    } else {
        set_default_db_path(g_config.db_path, sizeof(g_config.db_path));
    }

    g_config.public_ip[0] = '\0';
    if (pub && pub[0]) {
        strncpy(g_config.public_ip, pub, sizeof(g_config.public_ip) - 1);
        util_trim(g_config.public_ip);
    }
}
