#include "config.h"
#include "util.h"

#include <openssl/sha.h>
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

/* Parse CLOUDTSE_SELF_TEST_AT as HH:MM (local). Empty/off/disabled → hour=-1. */
static void parse_self_test_at(const char *raw, int *hour_out, int *min_out) {
    *hour_out = -1;
    *min_out = 0;
    if (!raw) {
        return;
    }
    while (*raw == ' ' || *raw == '\t') {
        raw++;
    }
    if (!raw[0] || strcmp(raw, "off") == 0 || strcmp(raw, "disabled") == 0 ||
        strcmp(raw, "-") == 0) {
        return;
    }
    int hour = 0;
    int minute = 0;
    const char *colon = strchr(raw, ':');
    if (colon) {
        hour = atoi(raw);
        minute = atoi(colon + 1);
    } else {
        hour = atoi(raw);
        minute = 0;
    }
    if (hour < 0 || hour > 23 || minute < 0 || minute > 59) {
        return;
    }
    *hour_out = hour;
    *min_out = minute;
}

void config_load(void) {
    const char *host = env_or("CLOUDTSE_HOST", CLOUDTSE_DEFAULT_HOST);
    const char *port_str = env_or("CLOUDTSE_PORT", "20001");
    const char *eas = env_or("CLOUDTSE_EAS_CODE", CLOUDTSE_DEFAULT_EAS_CODE);
    /* No compiled-in default on purpose: this must come from .env (loaded
     * into the environment by start.sh) so it stays out of version control
     * and matches whichever clients were actually provisioned. Value is a
     * comma-separated list of client_id serials. Empty/unset means open
     * self-registration (any client_id + correct EAS code). */
    const char *allowed_client = env_or("CLOUDTSE_ALLOWED_CLIENT_SERIAL", "");
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
    strncpy(g_config.allowed_client_serial, allowed_client,
            sizeof(g_config.allowed_client_serial) - 1);
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

    const char *mode = env_or("CLOUDTSE_TSE_MODE", "sim");
    if (strcmp(mode, "hardware") == 0 || strcmp(mode, "hw") == 0 || strcmp(mode, "1") == 0) {
        g_config.tse_mode = TSE_MODE_HARDWARE;
        util_strlcpy(g_config.fcc_version, CLOUDTSE_DEFAULT_FCC_VERSION_HW,
                     sizeof(g_config.fcc_version));
    } else {
        g_config.tse_mode = TSE_MODE_SIM;
    }

    g_config.tse_device[0] = '\0';
    g_config.worm_path[0] = '\0';
    util_strlcpy(g_config.worm_lib, env_or("CLOUDTSE_WORM_LIB", CLOUDTSE_DEFAULT_WORM_LIB),
                 sizeof(g_config.worm_lib));
    g_config.worm_admin_pin[0] = '\0';
    g_config.worm_admin_puk[0] = '\0';
    g_config.worm_time_admin_pin[0] = '\0';
    const char *admin_pin = getenv("CLOUDTSE_WORM_ADMIN_PIN");
    const char *admin_puk = getenv("CLOUDTSE_WORM_ADMIN_PUK");
    const char *time_pin = getenv("CLOUDTSE_WORM_TIME_ADMIN_PIN");
    if (admin_pin && admin_pin[0]) {
        util_strlcpy(g_config.worm_admin_pin, admin_pin, sizeof(g_config.worm_admin_pin));
    }
    if (admin_puk && admin_puk[0]) {
        util_strlcpy(g_config.worm_admin_puk, admin_puk, sizeof(g_config.worm_admin_puk));
    }
    if (time_pin && time_pin[0]) {
        util_strlcpy(g_config.worm_time_admin_pin, time_pin,
                     sizeof(g_config.worm_time_admin_pin));
    }
    util_strlcpy(g_config.worm_credential_seed,
                 env_or("CLOUDTSE_WORM_CREDENTIAL_SEED", CLOUDTSE_DEFAULT_WORM_CREDENTIAL_SEED),
                 sizeof(g_config.worm_credential_seed));

    parse_self_test_at(getenv("CLOUDTSE_SELF_TEST_AT"), &g_config.self_test_at_hour,
                       &g_config.self_test_at_minute);

    g_config.leaf_certificate[0] = '\0';
    g_config.tse_public_key_b64[0] = '\0';
    const char *leaf_env = getenv("CLOUDTSE_LEAF_CERTIFICATE");
    if (leaf_env && leaf_env[0]) {
        static char file_buf[8192];
        const char *cert_src = leaf_env;
        FILE *f = fopen(leaf_env, "r");
        if (f) {
            size_t n = fread(file_buf, 1, sizeof(file_buf) - 1, f);
            file_buf[n] = '\0';
            fclose(f);
            cert_src = file_buf;
        }
        const char *p = strstr(cert_src, "-----BEGIN CERTIFICATE-----");
        if (p) {
            p += 27;
        } else {
            p = cert_src;
        }
        size_t idx = 0;
        while (*p && idx < sizeof(g_config.leaf_certificate) - 1) {
            if (strncmp(p, "-----END", 8) == 0) {
                break;
            }
            if (*p >= 33 && *p <= 126) {
                g_config.leaf_certificate[idx++] = *p;
            }
            p++;
        }
        g_config.leaf_certificate[idx] = '\0';

        char der[8192];
        int der_len = util_base64_decode(g_config.leaf_certificate, der, sizeof(der));
        if (der_len > 0) {
            static const unsigned char p256_sig[] = {
                0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
                0x03, 0x42, 0x00, 0x04
            };
            for (int i = 0; i <= der_len - (int)sizeof(p256_sig) - 64; i++) {
                if (memcmp(der + i, p256_sig, sizeof(p256_sig)) == 0) {
                    int spki_start = i - 13;
                    if (spki_start >= 0 && spki_start + 91 <= der_len) {
                        util_base64_encode((const uint8_t *)der + i + sizeof(p256_sig) - 1, 65,
                                           g_config.tse_public_key_b64,
                                           sizeof(g_config.tse_public_key_b64));
                        
                        unsigned char hash[SHA256_DIGEST_LENGTH];
                        SHA256((const unsigned char *)der + i + sizeof(p256_sig) - 1, 65, hash);
                        
                        char derived_serial[128];
                        util_bytes_to_hex(hash, SHA256_DIGEST_LENGTH, derived_serial, sizeof(derived_serial));
                        util_uppercase(derived_serial);
                        
                        // Override the dummy serial if it was the default
                        if (strcmp(g_config.tse_serial, CLOUDTSE_DEFAULT_TSE_SERIAL) == 0) {
                            util_strlcpy(g_config.tse_serial, derived_serial, sizeof(g_config.tse_serial));
                        }
                    }
                    break;
                }
            }
        }
    }
}

int config_is_client_allowed(const char *client_serial) {
    const char *list = g_config.allowed_client_serial;
    if (!list[0]) {
        return 1; /* empty allowlist => open registration */
    }
    if (!client_serial || !client_serial[0]) {
        return 0;
    }

    size_t want_len = strlen(client_serial);
    const char *p = list;
    while (*p) {
        while (*p == ' ' || *p == '\t') {
            p++;
        }
        const char *start = p;
        while (*p && *p != ',') {
            p++;
        }
        const char *end = p;
        while (end > start && (end[-1] == ' ' || end[-1] == '\t')) {
            end--;
        }
        size_t len = (size_t)(end - start);
        if (len == want_len && memcmp(start, client_serial, len) == 0) {
            return 1;
        }
        if (*p == ',') {
            p++;
        }
    }
    return 0;
}
