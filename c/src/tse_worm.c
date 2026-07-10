#include "tse_worm.h"

#include "config.h"
#include "db.h"
#include "log.h"
#include "tse_block.h"
#include "util.h"

#include <ctype.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define WORM_ERROR_NOERROR 0
#define WORM_USER_ADMIN 1
#define WORM_USER_TIME_ADMIN 2
#define WORM_INIT_UNINITIALIZED 0

typedef intptr_t worm_handle;

typedef worm_handle (*worm_store_new_fn)(const char *path);
typedef void (*worm_store_free_fn)(worm_handle ctx);
typedef int (*worm_init_fn)(worm_handle *out, const char *path);
typedef int (*worm_cleanup_fn)(worm_handle ctx);
typedef int (*worm_init_callbacks_fn)(worm_handle *out, void *userdata, void *read_info,
                                        void *read_comm, void *write_comm, void *read_store,
                                        void *write_store, void *open_keepalive,
                                        void *close_keepalive, void *read_keepalive);
typedef worm_handle (*worm_info_new_fn)(worm_handle store);
typedef void (*worm_info_free_fn)(worm_handle info);
typedef int (*worm_info_read_fn)(worm_handle info);
typedef worm_handle (*worm_transaction_response_new_fn)(worm_handle store);
typedef void (*worm_transaction_response_free_fn)(worm_handle response);
typedef int (*worm_transaction_start_fn)(worm_handle store, const char *client_id,
                                         const unsigned char *process_data,
                                         unsigned int process_data_length,
                                         const char *process_type,
                                         worm_handle response);
typedef int (*worm_transaction_finish_fn)(worm_handle store, const char *client_id,
                                          unsigned long long transaction_number,
                                          const unsigned char *process_data,
                                          unsigned int process_data_length,
                                          const char *process_type,
                                          worm_handle response);
typedef unsigned long long (*worm_tx_resp_u64_fn)(worm_handle response);
typedef const unsigned char *(*worm_tx_resp_bytes_fn)(worm_handle response, int *size);
typedef int (*worm_tse_register_client_fn)(worm_handle store, const char *client_id);
typedef int (*worm_tse_run_self_test_fn)(worm_handle store, const char *client_id);
typedef int (*worm_tse_update_time_fn)(worm_handle store, unsigned long long unix_time);
typedef int (*worm_user_login_fn)(worm_handle store, int user_id, const char *pin);
typedef int (*worm_user_logout_fn)(worm_handle store, int user_id);
typedef const unsigned char *(*worm_info_bytes_fn)(worm_handle info, int *size);
typedef void (*worm_info_bytes_out_fn)(worm_handle info, unsigned char **out, unsigned int *len);
typedef void (*worm_tx_resp_sig_legacy_fn)(worm_handle response, unsigned char **out_ptr,
                                            unsigned long long *out_len);
typedef worm_handle (*worm_store_internal_new_fn)(worm_handle reader_writer);
typedef worm_handle (*worm_tse_reader_writer_new_fn)(void);
typedef void (*worm_tse_reader_writer_director_connect_fn)(worm_handle rw, worm_handle self,
                                                           int imclass, int cmemown);
typedef unsigned long long (*worm_info_u64_fn)(worm_handle info);
typedef int (*worm_get_log_message_certificate_fn)(worm_handle store, unsigned char *out,
                                                    uint32_t *inout_len);
typedef int (*worm_tse_setup_fn)(worm_handle store, const char *seed, int seed_len,
                                   const char *admin_puk, int admin_puk_len,
                                   const char *admin_pin, int admin_pin_len,
                                   const char *time_admin_pin, int time_admin_pin_len,
                                   const char *client_id);
typedef int (*worm_export_tar_cb_fn)(const unsigned char *data, size_t len, void *ctx);
typedef int (*worm_export_tar_fn)(worm_handle store, worm_export_tar_cb_fn cb, void *ctx);
typedef const char *(*worm_get_version_fn)(void);

static bool g_legacy_api;
static void *g_lib;
static pthread_mutex_t g_worm_mu = PTHREAD_MUTEX_INITIALIZER;
static bool g_active;
static worm_handle g_store;
static tse_block_t g_block;
static char g_serial[128];
static char g_public_key_hex[256];
static char g_certificate_base64[6144];
static char g_store_path[512];

/*
 * The physical TSE persists client registrations independently of this
 * process' state (oauth tokens, DB rows, etc). A client that previously
 * received a bearer token may never have been registered against *this*
 * TSE (e.g. after a hardware swap/reset, or when the token was minted
 * while running in simulator mode). worm_transaction_start fails hard if
 * the client isn't registered, so we track which client ids we've
 * confirmed as registered this run and register on demand before
 * starting a transaction.
 */
#define WORM_REGISTERED_CACHE_MAX 64
static char g_registered_clients[WORM_REGISTERED_CACHE_MAX][256];
static int g_registered_clients_count;

static bool worm_client_is_cached_registered(const char *client_id) {
    for (int i = 0; i < g_registered_clients_count; i++) {
        if (strcmp(g_registered_clients[i], client_id) == 0) {
            return true;
        }
    }
    return false;
}

static void worm_client_mark_registered(const char *client_id) {
    if (worm_client_is_cached_registered(client_id)) {
        return;
    }
    if (g_registered_clients_count < WORM_REGISTERED_CACHE_MAX) {
        util_strlcpy(g_registered_clients[g_registered_clients_count++], client_id,
                     sizeof(g_registered_clients[0]));
    }
}

/*
 * The TSE's registered-client table stores fixed-size 31-byte (incl. NUL)
 * slots (see worm_tse_listRegisteredClients), i.e. client ids longer than
 * 30 bytes are rejected outright with WORM_ERROR_TSE_INVALID_PARAMETER by
 * worm_tse_registerClient / worm_transaction_start. POS systems sometimes
 * send full UUIDs (or longer) as clientId, so map anything over the limit
 * to a short, stable, collision-resistant id before it ever reaches the
 * WormAPI. The original id is still used everywhere else (DB, responses).
 */
#define WORM_CLIENT_ID_MAX_LEN 30

static uint64_t worm_fnv1a64(const char *s) {
    uint64_t h = 14695981039346656037ULL;
    for (; *s; s++) {
        h ^= (unsigned char)*s;
        h *= 1099511628211ULL;
    }
    return h;
}

/* out must be at least WORM_CLIENT_ID_MAX_LEN + 1 bytes. */
static void worm_safe_client_id(const char *client_id, char *out, size_t outlen) {
    if (!client_id || !client_id[0]) {
        util_strlcpy(out, "default", outlen);
        return;
    }
    size_t len = strlen(client_id);
    if (len <= WORM_CLIENT_ID_MAX_LEN) {
        util_strlcpy(out, client_id, outlen);
        return;
    }
    uint64_t h = worm_fnv1a64(client_id);
    char hash_hex[17];
    snprintf(hash_hex, sizeof(hash_hex), "%016llx", (unsigned long long)h);
    size_t prefix_len = WORM_CLIENT_ID_MAX_LEN - 1 - strlen(hash_hex); /* '-' + hash */
    if (prefix_len > len) {
        prefix_len = len;
    }
    char safe[WORM_CLIENT_ID_MAX_LEN + 1];
    memcpy(safe, client_id, prefix_len);
    safe[prefix_len] = '-';
    util_strlcpy(safe + prefix_len + 1, hash_hex, sizeof(safe) - prefix_len - 1);
    util_strlcpy(out, safe, outlen);
    log_warn("clientId '%s' is %zu bytes, over the TSE's %d-byte limit; using '%s' on the TSE "
             "instead (stable per client)",
             client_id, len, WORM_CLIENT_ID_MAX_LEN, out);
}

static worm_store_new_fn p_worm_store_new;
static worm_store_free_fn p_worm_store_free;
static worm_init_fn p_worm_init;
static worm_cleanup_fn p_worm_cleanup;
static worm_init_callbacks_fn p_worm_init_callbacks;
static worm_info_new_fn p_worm_info_new;
static worm_info_free_fn p_worm_info_free;
static worm_info_read_fn p_worm_info_read;
static worm_transaction_response_new_fn p_worm_tx_resp_new;
static worm_transaction_response_free_fn p_worm_tx_resp_free;
static worm_transaction_start_fn p_worm_tx_start;
static worm_transaction_finish_fn p_worm_tx_finish;
static worm_tx_resp_u64_fn p_worm_tx_resp_tx_num;
static worm_tx_resp_u64_fn p_worm_tx_resp_sig_counter;
static worm_tx_resp_u64_fn p_worm_tx_resp_log_time;
static worm_tx_resp_bytes_fn p_worm_tx_resp_signature;
static worm_tse_register_client_fn p_worm_register_client;
static worm_tse_run_self_test_fn p_worm_run_self_test;
static worm_tse_update_time_fn p_worm_update_time;
static worm_user_login_fn p_worm_user_login;
static worm_user_logout_fn p_worm_user_logout;
static worm_info_bytes_fn p_worm_info_serial;
static worm_info_bytes_fn p_worm_info_pubkey;
static worm_info_bytes_out_fn p_worm_info_serial_out;
static worm_info_bytes_out_fn p_worm_info_pubkey_out;
static worm_tx_resp_sig_legacy_fn p_worm_tx_sig_legacy;
static worm_store_internal_new_fn p_worm_store_internal_new;
static worm_tse_reader_writer_new_fn p_worm_rw_new;
static worm_tse_reader_writer_director_connect_fn p_worm_rw_director_connect;

/* Optional diagnostic getters, resolved best-effort for troubleshooting. */
static worm_info_u64_fn p_worm_info_has_valid_time;
static worm_info_u64_fn p_worm_info_has_passed_self_test;
static worm_info_u64_fn p_worm_info_registered_clients;
static worm_info_u64_fn p_worm_info_max_registered_clients;
static worm_info_u64_fn p_worm_info_is_tx_in_progress;
static worm_info_u64_fn p_worm_info_started_transactions;
static worm_info_u64_fn p_worm_info_max_started_transactions;
static worm_info_u64_fn p_worm_info_created_signatures;
static worm_info_u64_fn p_worm_info_max_time_sync_delay;
static worm_info_u64_fn p_worm_info_has_changed_time_admin_pin;
static worm_info_u64_fn p_worm_info_init_state;
static worm_info_u64_fn p_worm_info_hardware_version;
static worm_info_u64_fn p_worm_info_firmware_version;
static worm_tse_setup_fn p_worm_tse_setup;
static worm_get_log_message_certificate_fn p_worm_get_log_message_certificate;
static worm_get_version_fn p_worm_get_version;
static worm_export_tar_fn p_worm_export_tar;

/*
 * In legacy/mounted mode (CLOUDTSE_WORM_PATH set to e.g. /mnt/tse), the
 * closed-source WormAPI talks to the physical TSE directly through the
 * mounted filesystem, completely bypassing tse_block.c. That means the
 * only place we can observe/time "requests to hardware" in that mode is
 * right here, at the boundary where we call into the vendor library.
 * Every call that reaches the physical device (info reads, transaction
 * start/finish, login/logout, self-test, time sync, registration,
 * certificate fetch, setup) goes through this helper so it's logged with
 * timing regardless of whether the underlying transport is the mount or
 * our own block I/O (tse_block.c logs that layer separately).
 */
#define WORM_HW_CALL(label, call_expr)                                              \
    ({                                                                              \
        double __t0 = util_monotonic_ms();                                          \
        long long __rc = (long long)(call_expr);                                    \
        log_debug("TSE HW CALL %-40s -> rc=%lld (%.3f ms)", (label), __rc,           \
                  util_monotonic_ms() - __t0);                                      \
        __rc;                                                                       \
    })

static void *resolve(void *lib, const char *primary, const char *alt) {
    void *p = dlsym(lib, primary);
    if (!p && alt) {
        p = dlsym(lib, alt);
    }
    return p;
}

static int require_sym(void *lib, const char *primary, const char *alt, void **out) {
    *out = resolve(lib, primary, alt);
    if (!*out) {
        log_error("missing symbol %s in %s", primary, g_config.worm_lib);
        return -1;
    }
    return 0;
}

static int worm_user_login_call(int user_id, const char *pin) {
    if (g_legacy_api) {
        typedef int (*legacy_fn)(worm_handle, unsigned char, const char *, unsigned int);
        legacy_fn login = (legacy_fn)(void *)p_worm_user_login;
        return (int)WORM_HW_CALL("worm_user_login",
                                  login(g_store, (unsigned char)user_id, pin,
                                        (unsigned int)strlen(pin)));
    }
    return (int)WORM_HW_CALL("worm_user_login", p_worm_user_login(g_store, user_id, pin));
}

static int worm_user_logout_call(int user_id) {
    return (int)WORM_HW_CALL("worm_user_logout", p_worm_user_logout(g_store, user_id));
}

static int open_store_legacy(const char *path, bool quiet) {
    worm_handle ctx = 0;
    int rc = (int)WORM_HW_CALL("worm_init", p_worm_init(&ctx, path));
    if (rc != WORM_ERROR_NOERROR || !ctx) {
        if (!quiet) {
            log_warn("worm_init(%s) failed (error %d)", path, rc);
        }
        return -1;
    }
    g_store = ctx;
    util_strlcpy(g_store_path, path, sizeof(g_store_path));
    return 0;
}

static int open_store_legacy_block(void) {
    if (!p_worm_init_callbacks) {
        return -1;
    }
    tse_worm_director_set_block(&g_block);
    worm_handle ctx = 0;
    int rc = (int)WORM_HW_CALL(
        "worm_init_with_communication_callbacks",
        p_worm_init_callbacks(&ctx, NULL, (void *)WormLegacy_readInfo,
                               (void *)WormLegacy_readComm, (void *)WormLegacy_writeComm,
                               (void *)WormLegacy_readStore, (void *)WormLegacy_writeStore,
                               (void *)WormLegacy_openKeepAlive,
                               (void *)WormLegacy_closeKeepAlive,
                               (void *)WormLegacy_readKeepAlive));
    if (rc != WORM_ERROR_NOERROR || !ctx) {
        log_error("worm_init_with_communication_callbacks failed (error %d)", rc);
        return -1;
    }
    g_store = ctx;
    snprintf(g_store_path, sizeof(g_store_path), "block:%s", g_block.device);
    return 0;
}

static int try_legacy_mount_paths(void) {
    static const char *paths[] = {"/mnt/tse", "/mnt/SWISSBIT", NULL};
    for (int i = 0; paths[i]; i++) {
        if (g_config.worm_path[0] && strcmp(g_config.worm_path, paths[i]) == 0) {
            continue;
        }
        if (open_store_legacy(paths[i], true) == 0) {
            return 0;
        }
    }
    return -1;
}

static bool is_block_dev_name(const char *name) {
    char letter;
    int n;
    /* whole disk or partition of a SCSI/SATA/USB disk */
    if (sscanf(name, "sd%c%d", &letter, &n) == 2 && letter >= 'a' && letter <= 'z')
        return true;
    if (sscanf(name, "sd%c", &letter) == 1 && letter >= 'a' && letter <= 'z')
        return true;
    /* SD/MMC cards (e.g. mmcblk0, mmcblk0p1) */
    if (sscanf(name, "mmcblk%d", &n) == 1)
        return true;
    /* NVMe namespaces (e.g. nvme0n1, nvme0n1p1) */
    if (strncmp(name, "nvme", 4) == 0)
        return true;
    return false;
}

/*
 * A TSE is a removable USB/SD device. We decide this from sysfs metadata
 * only — we never open a fixed system disk. /sys/block/<dev>/removable is
 * "1" for hot-plugged storage (USB sticks, SD readers) and "0" for built-in
 * disks/SSDs, so this excludes the boot disk without touching it.
 */
static bool sysfs_device_is_removable(const char *name) {
    char path[512];
    snprintf(path, sizeof(path), "/sys/block/%s/removable", name);
    FILE *f = fopen(path, "r");
    if (!f) {
        return false;
    }
    char buf[8];
    bool removable = false;
    if (fgets(buf, sizeof(buf), f) && buf[0] == '1') {
        removable = true;
    }
    fclose(f);
    return removable;
}

static int ensure_block_open(void) {
    char err[256];

    /*
     * The TSE is located by discovery, not guessing: enumerate /sys/block and
     * consider only removable devices. Each such device is then confirmed to
     * actually be a TSE via tse_block_probe (which validates the TSE offset
     * table). Fixed system disks are never opened.
     */
    char candidates[32][32];
    int n = 0;

    DIR *sys = opendir("/sys/block");
    if (!sys) {
        log_error("cannot enumerate /sys/block to locate the TSE device");
        return -1;
    }
    struct dirent *ent;
    while ((ent = readdir(sys)) != NULL &&
           n < (int)(sizeof(candidates) / sizeof(candidates[0]))) {
        if (!is_block_dev_name(ent->d_name)) {
            continue;
        }
        if (!sysfs_device_is_removable(ent->d_name)) {
            continue;
        }
        if (strlen(ent->d_name) + 6 > sizeof(candidates[n])) {
            continue;
        }
        snprintf(candidates[n], sizeof(candidates[n]), "/dev/%s", ent->d_name);
        n++;
    }
    closedir(sys);

    for (int i = 0; i < n; i++) {
        const char *dev = candidates[i];
        char fallback_buf[32];
        const char *fallback = NULL;
        size_t dl = strlen(dev);
        if (dl > 0 && isdigit((unsigned char)dev[dl - 1])) {
            util_strlcpy(fallback_buf, dev, sizeof(fallback_buf));
            fallback_buf[dl - 1] = '\0';
            fallback = fallback_buf;
        } else if (dl + 2 <= sizeof(fallback_buf)) {
            snprintf(fallback_buf, sizeof(fallback_buf), "%.*s1", (int)dl, dev);
            fallback = fallback_buf;
        }

        if (tse_block_probe(dev, err, sizeof(err)) == 0 &&
            tse_block_open(&g_block, dev) == 0) {
            util_strlcpy(g_config.tse_device, dev, sizeof(g_config.tse_device));
            return 0;
        }
        log_debug("TSE probe %s failed: %s", dev, err);

        if (fallback && tse_block_probe(fallback, err, sizeof(err)) == 0 &&
            tse_block_open(&g_block, fallback) == 0) {
            util_strlcpy(g_config.tse_device, fallback, sizeof(g_config.tse_device));
            return 0;
        }
        if (fallback) {
            log_debug("TSE probe %s failed: %s", fallback, err);
        }
    }

    if (n == 0) {
        log_error("no removable TSE device found — insert the TSE USB/SD device "
                  "(enumerated /sys/block, none were removable)");
    } else {
        log_error("no TSE device among %d removable candidate(s); last error: %s",
                  n, err);
    }
    return -1;
}

static int open_store(const char *path) {
    if (g_legacy_api) {
        return open_store_legacy(path, false);
    }
    g_store = p_worm_store_new(path);
    if (!g_store) {
        return -1;
    }
    util_strlcpy(g_store_path, path, sizeof(g_store_path));
    return 0;
}

static int open_store_with_block(void) {
    if (!p_worm_store_internal_new || !p_worm_rw_new || !p_worm_rw_director_connect) {
        return -1;
    }
    tse_worm_director_set_block(&g_block);
    worm_handle rw = p_worm_rw_new();
    if (!rw) {
        return -1;
    }
    p_worm_rw_director_connect(rw, rw, 1, 1);
    g_store = p_worm_store_internal_new(rw);
    if (!g_store) {
        return -1;
    }
    snprintf(g_store_path, sizeof(g_store_path), "block:%s", g_block.device);
    return 0;
}

static void refresh_certificate(void) {
    if (!g_store || !p_worm_get_log_message_certificate) {
        return;
    }
    uint32_t len = 0;
    int rc = (int)WORM_HW_CALL("worm_getLogMessageCertificate(size)",
                                p_worm_get_log_message_certificate(g_store, NULL, &len));
    if (rc != WORM_ERROR_NOERROR || len == 0 || len > 8192) {
        return;
    }
    unsigned char *buf = malloc(len);
    if (!buf) {
        return;
    }
    uint32_t out_len = len;
    rc = (int)WORM_HW_CALL("worm_getLogMessageCertificate(data)",
                            p_worm_get_log_message_certificate(g_store, buf, &out_len));
    if (rc == WORM_ERROR_NOERROR && out_len > 0) {
        util_base64_encode(buf, out_len, g_certificate_base64, sizeof(g_certificate_base64));
    }
    free(buf);
}

static void refresh_info_fields(void) {
    if (!g_store || !p_worm_info_new || !p_worm_info_read) {
        return;
    }
    worm_handle info = p_worm_info_new(g_store);
    if (!info) {
        return;
    }
    if (WORM_HW_CALL("worm_info_read", p_worm_info_read(info)) == WORM_ERROR_NOERROR) {
        if (g_legacy_api && p_worm_info_serial_out) {
            unsigned char *serial = NULL;
            unsigned int size = 0;
            p_worm_info_serial_out(info, &serial, &size);
            if (serial && size > 0) {
                util_bytes_to_hex(serial, (size_t)size, g_serial, sizeof(g_serial));
            }
        } else if (p_worm_info_serial) {
            int size = 0;
            const unsigned char *serial = p_worm_info_serial(info, &size);
            if (serial && size > 0) {
                util_bytes_to_hex(serial, (size_t)size, g_serial, sizeof(g_serial));
            }
        }
        if (g_legacy_api && p_worm_info_pubkey_out) {
            unsigned char *pk = NULL;
            unsigned int size = 0;
            p_worm_info_pubkey_out(info, &pk, &size);
            if (pk && size > 0) {
                util_bytes_to_hex(pk, (size_t)size, g_public_key_hex, sizeof(g_public_key_hex));
            }
        } else if (p_worm_info_pubkey) {
            int size = 0;
            const unsigned char *pk = p_worm_info_pubkey(info, &size);
            if (pk && size > 0) {
                util_bytes_to_hex(pk, (size_t)size, g_public_key_hex, sizeof(g_public_key_hex));
            }
        }
    }
    if (p_worm_info_free) {
        p_worm_info_free(info);
    }
}

static void log_worm_diagnostics(const char *context) {
    if (!g_store || !p_worm_info_new || !p_worm_info_read) {
        return;
    }
    worm_handle info = p_worm_info_new(g_store);
    if (!info) {
        return;
    }
    if (WORM_HW_CALL("worm_info_read", p_worm_info_read(info)) != WORM_ERROR_NOERROR) {
        if (p_worm_info_free) {
            p_worm_info_free(info);
        }
        return;
    }

    log_info("TSE diagnostics (%s):", context);
    if (p_worm_info_has_valid_time) {
        unsigned long long v = p_worm_info_has_valid_time(info);
        log_info("  hasValidTime:        %s%s", v ? "yes" : "NO",
                 v ? "" : "  <- set CLOUDTSE_WORM_TIME_ADMIN_PIN and restart, or run "
                          "worm_tse_updateTime as TimeAdmin");
    }
    if (p_worm_info_has_passed_self_test) {
        unsigned long long v = p_worm_info_has_passed_self_test(info);
        log_info("  hasPassedSelfTest:   %s", v ? "yes" : "NO");
    }
    if (p_worm_info_has_changed_time_admin_pin) {
        unsigned long long v = p_worm_info_has_changed_time_admin_pin(info);
        log_info("  hasChangedTimeAdminPin: %s%s", v ? "yes" : "NO",
                 v ? "" : "  <- TimeAdmin PIN is still the factory default; login/updateTime may "
                          "be rejected until it is changed");
    }
    if (p_worm_info_registered_clients && p_worm_info_max_registered_clients) {
        log_info("  registeredClients:   %llu / %llu", p_worm_info_registered_clients(info),
                 p_worm_info_max_registered_clients(info));
    }
    if (p_worm_info_started_transactions && p_worm_info_max_started_transactions) {
        log_info("  startedTransactions: %llu / %llu", p_worm_info_started_transactions(info),
                 p_worm_info_max_started_transactions(info));
    }
    if (p_worm_info_is_tx_in_progress) {
        log_info("  isTransactionInProgress: %s", p_worm_info_is_tx_in_progress(info) ? "yes" : "no");
    }
    if (p_worm_info_free) {
        p_worm_info_free(info);
    }
}

static void generate_random_digits(char *out, size_t outlen, size_t count) {
    if (count >= outlen) {
        count = outlen - 1;
    }
    uint8_t buf[16];
    if (count > sizeof(buf)) {
        count = sizeof(buf);
    }
    if (util_random_bytes(buf, count) != 0) {
        unsigned seed = (unsigned)time(NULL) ^ (unsigned)(intptr_t)out;
        for (size_t i = 0; i < count; i++) {
            seed = seed * 1103515245u + 12345u;
            buf[i] = (uint8_t)(seed >> 16);
        }
    }
    for (size_t i = 0; i < count; i++) {
        out[i] = (char)('0' + (buf[i] % 10));
    }
    out[count] = '\0';
}

/*
 * Admin/TimeAdmin PIN and PUK changes made via worm_tse_setup are permanent
 * on the physical TSE. If the operator hasn't configured them explicitly,
 * generate them once and persist to the local DB so subsequent restarts
 * (without the env vars set) keep using the same credentials the hardware
 * now actually expects.
 */
static void load_or_generate_credential(const char *db_key, const char *configured, char *out,
                                        size_t outlen, size_t digits) {
    if (configured && configured[0]) {
        util_strlcpy(out, configured, outlen);
        return;
    }
    char stored[32];
    if (db_get_setting(db_key, stored, sizeof(stored)) && stored[0]) {
        util_strlcpy(out, stored, outlen);
        return;
    }
    generate_random_digits(out, outlen, digits);
    db_set_setting(db_key, out);
}

static void ensure_tse_provisioned(void) {
    if (!p_worm_info_init_state || !p_worm_tse_setup || !p_worm_info_new || !p_worm_info_read) {
        return;
    }
    worm_handle info = p_worm_info_new(g_store);
    if (!info) {
        return;
    }
    unsigned long long state = 0;
    bool have_state = false;
    if (WORM_HW_CALL("worm_info_read", p_worm_info_read(info)) == WORM_ERROR_NOERROR) {
        state = p_worm_info_init_state(info);
        have_state = true;
    }
    if (p_worm_info_free) {
        p_worm_info_free(info);
    }
    if (!have_state || state != WORM_INIT_UNINITIALIZED) {
        return;
    }

    log_warn("TSE is uninitialized — running one-time provisioning via worm_tse_setup...");

    char admin_pin[16];
    char admin_puk[16];
    char time_admin_pin[16];
    load_or_generate_credential("worm_admin_pin", g_config.worm_admin_pin, admin_pin,
                                sizeof(admin_pin), 5);
    load_or_generate_credential("worm_admin_puk", g_config.worm_admin_puk, admin_puk,
                                sizeof(admin_puk), 6);
    load_or_generate_credential("worm_time_admin_pin", g_config.worm_time_admin_pin,
                                time_admin_pin, sizeof(time_admin_pin), 5);

    const char *seed =
        g_config.worm_credential_seed[0] ? g_config.worm_credential_seed : "SwissbitSwissbit";
    const char *bootstrap_client = "cloudtse-bootstrap";

    /* Required as the first command after worm_init; expected to fail on an
     * uninitialized TSE. Ignoring the result is by design. */
    if (p_worm_run_self_test) {
        (void)WORM_HW_CALL("worm_tse_runSelfTest",
                            p_worm_run_self_test(g_store, bootstrap_client));
    }

    int rc = (int)WORM_HW_CALL(
        "worm_tse_setup",
        p_worm_tse_setup(g_store, seed, (int)strlen(seed), admin_puk, (int)strlen(admin_puk),
                          admin_pin, (int)strlen(admin_pin), time_admin_pin,
                          (int)strlen(time_admin_pin), bootstrap_client));
    if (rc != WORM_ERROR_NOERROR) {
        log_error("worm_tse_setup failed (error %d). If this TSE was not sold directly by "
                  "Swissbit, set CLOUDTSE_WORM_CREDENTIAL_SEED to the seed provided by your "
                  "reseller and restart. Warning: 3 failed setup attempts with a wrong seed will "
                  "permanently lock the TSE.",
                  rc);
        return;
    }

    util_strlcpy(g_config.worm_admin_pin, admin_pin, sizeof(g_config.worm_admin_pin));
    util_strlcpy(g_config.worm_admin_puk, admin_puk, sizeof(g_config.worm_admin_puk));
    util_strlcpy(g_config.worm_time_admin_pin, time_admin_pin,
                 sizeof(g_config.worm_time_admin_pin));
    worm_client_mark_registered(bootstrap_client);

    log_info("TSE provisioning complete. Credentials cached in %s:", g_config.db_path);
    log_info("  Admin PIN:     %s", admin_pin);
    log_info("  Admin PUK:     %s", admin_puk);
    log_info("  TimeAdmin PIN: %s", time_admin_pin);
    log_info("  (set CLOUDTSE_WORM_ADMIN_PIN / CLOUDTSE_WORM_ADMIN_PUK / "
             "CLOUDTSE_WORM_TIME_ADMIN_PIN to override in the future)");

    if (p_worm_run_self_test) {
        (void)WORM_HW_CALL("worm_tse_runSelfTest",
                            p_worm_run_self_test(g_store, bootstrap_client));
    }
}

/*
 * hasPassedSelfTest is hardware state read from the TSE's own info block,
 * not per-process session state. As long as the physical device wasn't
 * actually power-cycled (unplugged/replugged, or the host machine
 * rebooted), a self-test that passed in a previous run of this process is
 * still recorded on the TSE itself.
 */
static bool worm_has_passed_self_test(void) {
    bool passed = false;
    if (g_store && p_worm_info_new && p_worm_info_read && p_worm_info_has_passed_self_test) {
        worm_handle info = p_worm_info_new(g_store);
        if (info) {
            if (WORM_HW_CALL("worm_info_read", p_worm_info_read(info)) == WORM_ERROR_NOERROR) {
                passed = p_worm_info_has_passed_self_test(info) != 0;
            }
            if (p_worm_info_free) {
                p_worm_info_free(info);
            }
        }
    }
    return passed;
}

/*
 * The TSE requires a self-test to pass after every actual power-cycle of
 * the physical device before it will accept logins, registration state
 * changes, or transactions (WORM_ERROR_WRONG_STATE_NEEDS_SELF_TEST).
 * hasPassedSelfTest is hardware state, so if the TSE stayed powered across
 * a restart of this process, it's already satisfied and rerunning the
 * self-test is a needless HW round trip. The self test itself requires a
 * client ID that was *already* registered on this physical TSE in a
 * previous session (registering a new client is one of the few operations
 * allowed even before self-test passes). We remember the last client ID
 * that worked in the local DB so restarts keep working without operator
 * input; if none is known yet (very first boot after provisioning) we
 * register one and retry.
 */
static void ensure_self_test_passed(void) {
    if (!p_worm_run_self_test) {
        return;
    }
    if (worm_has_passed_self_test()) {
        return;
    }

    char known[256] = {0};
    db_get_setting("worm_known_client", known, sizeof(known));
    const char *candidate = known[0] ? known : "cloudtse-startup";

    int rc = (int)WORM_HW_CALL("worm_tse_runSelfTest", p_worm_run_self_test(g_store, candidate));
    if (rc == WORM_ERROR_NOERROR) {
        db_set_setting("worm_known_client", candidate);
        return;
    }

    if (p_worm_register_client) {
        bool logged_in = false;
        if (g_config.worm_admin_pin[0] && p_worm_user_login && p_worm_user_logout) {
            logged_in = worm_user_login_call(WORM_USER_ADMIN, g_config.worm_admin_pin) ==
                        WORM_ERROR_NOERROR;
            if (!logged_in) {
                log_warn("Admin login failed (check CLOUDTSE_WORM_ADMIN_PIN) while trying to "
                         "register a client for self-test");
            }
        }
        int reg_rc = (int)WORM_HW_CALL("worm_tse_registerClient",
                                        p_worm_register_client(g_store, "cloudtse-startup"));
        if (logged_in) {
            worm_user_logout_call(WORM_USER_ADMIN);
        }
        if (reg_rc == WORM_ERROR_NOERROR) {
            rc = (int)WORM_HW_CALL("worm_tse_runSelfTest",
                                    p_worm_run_self_test(g_store, "cloudtse-startup"));
            if (rc == WORM_ERROR_NOERROR) {
                db_set_setting("worm_known_client", "cloudtse-startup");
                worm_client_mark_registered("cloudtse-startup");
                return;
            }
        } else {
            log_error("worm_tse_registerClient('cloudtse-startup') failed (error %d)", reg_rc);
        }
    }

    log_error("worm_tse_runSelfTest failed (error %d)", rc);
}

static bool worm_has_valid_time(void) {
    bool has_valid_time = true;
    if (g_store && p_worm_info_new && p_worm_info_read && p_worm_info_has_valid_time) {
        worm_handle info = p_worm_info_new(g_store);
        if (info) {
            if (WORM_HW_CALL("worm_info_read", p_worm_info_read(info)) == WORM_ERROR_NOERROR) {
                has_valid_time = p_worm_info_has_valid_time(info) != 0;
            }
            if (p_worm_info_free) {
                p_worm_info_free(info);
            }
        }
    }
    return has_valid_time;
}

/* Returns true if the TSE clock is (now) known to be valid. */
static bool perform_time_sync(void) {
    if (!g_config.worm_time_admin_pin[0]) {
        if (!worm_has_valid_time()) {
            log_warn("TSE has no valid time set and CLOUDTSE_WORM_TIME_ADMIN_PIN is not "
                     "configured. Transactions will fail until the TSE clock is synchronized "
                     "(log in as TimeAdmin and call worm_tse_updateTime, or set "
                     "CLOUDTSE_WORM_TIME_ADMIN_PIN and restart).");
            return false;
        }
        return true;
    }
    if (!p_worm_user_login || !p_worm_update_time || !p_worm_user_logout) {
        return worm_has_valid_time();
    }
    int login_rc = worm_user_login_call(WORM_USER_TIME_ADMIN, g_config.worm_time_admin_pin);
    if (login_rc != WORM_ERROR_NOERROR) {
        log_warn("TimeAdmin login failed (error %d) — check CLOUDTSE_WORM_TIME_ADMIN_PIN. Note: "
                 "3 consecutive wrong PIN attempts lock the TimeAdmin role until unblocked with "
                 "the TimeAdmin PUK.",
                 login_rc);
        return false;
    }
    unsigned long long now = (unsigned long long)time(NULL);
    bool ok =
        WORM_HW_CALL("worm_tse_updateTime", p_worm_update_time(g_store, now)) ==
        WORM_ERROR_NOERROR;
    if (!ok) {
        log_error("tse_updateTime failed");
    }
    worm_user_logout_call(WORM_USER_TIME_ADMIN);
    return ok;
}

/*
 * The TSE only considers its clock "valid" for a limited window
 * (worm_info_maxTimeSynchronizationDelay) after the last worm_tse_updateTime
 * call, after which every transaction start/finish fails with
 * WORM_ERROR_NO_TIME_SET until it is refreshed. A single sync at startup is
 * not enough for a long-running server, so keep checking periodically in
 * the background for as long as the process runs, at half the allowed
 * window for headroom. Each check is a cheap read-only info query; the
 * actual login+updateTime+logout resync (3 signed log messages, i.e. 3
 * signature-counter increments on the device) only runs when the clock has
 * actually gone invalid, not on every wakeup.
 */
static void *time_sync_thread_main(void *arg) {
    (void)arg;
    for (;;) {
        unsigned long long interval_sec = 300; /* conservative default: 5 min */

        pthread_mutex_lock(&g_worm_mu);
        if (!g_active) {
            pthread_mutex_unlock(&g_worm_mu);
            return NULL;
        }
        if (g_store && p_worm_info_new && p_worm_info_read && p_worm_info_max_time_sync_delay) {
            worm_handle info = p_worm_info_new(g_store);
            if (info) {
                if (WORM_HW_CALL("worm_info_read", p_worm_info_read(info)) == WORM_ERROR_NOERROR) {
                    unsigned long long delay = p_worm_info_max_time_sync_delay(info);
                    if (delay > 10) {
                        /* resync at half the allowed window for headroom */
                        interval_sec = delay / 2;
                    }
                }
                if (p_worm_info_free) {
                    p_worm_info_free(info);
                }
            }
        }
        pthread_mutex_unlock(&g_worm_mu);

        sleep((unsigned int)(interval_sec > 0 ? interval_sec : 300));

        pthread_mutex_lock(&g_worm_mu);
        if (g_active) {
            /*
             * login + updateTime + logout are each their own signed log
             * message on the TSE, so each burns 3 entries off the device's
             * finite signature counter. Skip the round trip entirely when
             * the clock is already valid instead of unconditionally
             * resyncing every cycle.
             */
            if (!worm_has_valid_time()) {
                (void)perform_time_sync();
            }
        }
        pthread_mutex_unlock(&g_worm_mu);
        if (!g_active) {
            return NULL;
        }
    }
    return NULL;
}

static void start_time_sync_thread(void) {
    pthread_t tid;
    if (pthread_create(&tid, NULL, time_sync_thread_main, NULL) == 0) {
        pthread_detach(tid);
    }
}

static void fill_tx_from_response(worm_handle response, tse_transaction_t *out) {
    memset(out, 0, sizeof(*out));
    if (p_worm_tx_resp_tx_num) {
        out->transaction_number = (int64_t)p_worm_tx_resp_tx_num(response);
    }
    if (p_worm_tx_resp_sig_counter) {
        out->signature_counter = (int64_t)p_worm_tx_resp_sig_counter(response);
    }
    if (p_worm_tx_resp_log_time) {
        unsigned long long log_time = p_worm_tx_resp_log_time(response);
        time_t t = (time_t)log_time;
        struct tm tm;
        gmtime_r(&t, &tm);
        strftime(out->time_start, sizeof(out->time_start), "%Y-%m-%dT%H:%M:%S.000Z", &tm);
        util_strlcpy(out->time_end, out->time_start, sizeof(out->time_end));
    }
    if ((g_legacy_api && p_worm_tx_sig_legacy) || p_worm_tx_resp_signature) {
        int sig_len = 0;
        const unsigned char *sig = NULL;
        if (g_legacy_api && p_worm_tx_sig_legacy) {
            unsigned char *sig_buf = NULL;
            unsigned long long sig_u64 = 0;
            p_worm_tx_sig_legacy(response, &sig_buf, &sig_u64);
            sig = sig_buf;
            sig_len = (int)sig_u64;
        } else if (p_worm_tx_resp_signature) {
            sig = p_worm_tx_resp_signature(response, &sig_len);
        }
        if (sig && sig_len > 0) {
            if (util_base64_encode(sig, (size_t)sig_len, out->signature_value,
                                   sizeof(out->signature_value)) != 0) {
                log_error("signature (%d bytes) didn't fit in the %zu-byte signature_value "
                          "buffer; leaving it empty",
                          sig_len, sizeof(out->signature_value));
            }
        } else {
            log_warn("TSE returned no signature bytes for this transaction response");
        }
    }
    if (g_serial[0]) {
        util_strlcpy(out->serial_number, g_serial, sizeof(out->serial_number));
    } else {
        util_strlcpy(out->serial_number, g_config.tse_serial, sizeof(out->serial_number));
    }
}

bool tse_worm_is_active(void) {
    return g_active;
}

const char *tse_worm_public_key_hex(void) {
    return g_public_key_hex[0] ? g_public_key_hex : g_config.tse_serial;
}

const char *tse_worm_certificate_base64(void) {
    return g_certificate_base64[0] ? g_certificate_base64 : NULL;
}

int tse_worm_init(void) {
    memset(&g_block, 0, sizeof(g_block));
    g_block.fd = -1;

    g_lib = dlopen(g_config.worm_lib, RTLD_NOW | RTLD_LOCAL);
    if (!g_lib) {
        log_error("cannot load %s: %s", g_config.worm_lib, dlerror());
        return -1;
    }

    p_worm_store_new = resolve(g_lib, "worm_store_new", "WormStore_new");
    if (p_worm_store_new) {
        if (require_sym(g_lib, "worm_store_free", "delete_WormStore", (void **)&p_worm_store_free) !=
                0 ||
            require_sym(g_lib, "worm_info_new", "WormInformation_new", (void **)&p_worm_info_new) !=
                0 ||
            require_sym(g_lib, "worm_info_free", "delete_WormInformation",
                        (void **)&p_worm_info_free) != 0 ||
            require_sym(g_lib, "worm_info_read", "WormInformation_read", (void **)&p_worm_info_read) !=
                0 ||
            require_sym(g_lib, "worm_transaction_response_new", NULL,
                        (void **)&p_worm_tx_resp_new) != 0 ||
            require_sym(g_lib, "worm_transaction_response_free", NULL,
                        (void **)&p_worm_tx_resp_free) != 0 ||
            require_sym(g_lib, "worm_transaction_start", NULL, (void **)&p_worm_tx_start) != 0 ||
            require_sym(g_lib, "worm_transaction_finish", NULL, (void **)&p_worm_tx_finish) != 0 ||
            require_sym(g_lib, "worm_transaction_response_transactionNumber", NULL,
                        (void **)&p_worm_tx_resp_tx_num) != 0 ||
            require_sym(g_lib, "worm_transaction_response_signatureCounter", NULL,
                        (void **)&p_worm_tx_resp_sig_counter) != 0 ||
            require_sym(g_lib, "worm_transaction_response_logTime", NULL,
                        (void **)&p_worm_tx_resp_log_time) != 0 ||
            require_sym(g_lib, "worm_transaction_response_signature", NULL,
                        (void **)&p_worm_tx_resp_signature) != 0) {
            dlclose(g_lib);
            g_lib = NULL;
            tse_block_close(&g_block);
            return -1;
        }
        p_worm_info_serial =
            resolve(g_lib, "worm_info_tseSerialNumber", "WormInformation_tseSerialNumber");
        p_worm_info_pubkey =
            resolve(g_lib, "worm_info_tsePublicKey", "WormInformation_tsePublicKey");
        p_worm_store_internal_new =
            resolve(g_lib, "worm_store_internal_new", "new_WormStoreInternal");
        p_worm_rw_new = resolve(g_lib, "new_WormTSEReaderWriter", NULL);
        p_worm_rw_director_connect =
            resolve(g_lib, "WormTSEReaderWriter_director_connect", NULL);
    } else {
        g_legacy_api = true;
        if (require_sym(g_lib, "worm_init", NULL, (void **)&p_worm_init) != 0 ||
            require_sym(g_lib, "worm_cleanup", NULL, (void **)&p_worm_cleanup) != 0 ||
            require_sym(g_lib, "worm_info_new", NULL, (void **)&p_worm_info_new) != 0 ||
            require_sym(g_lib, "worm_info_free", NULL, (void **)&p_worm_info_free) != 0 ||
            require_sym(g_lib, "worm_info_read", NULL, (void **)&p_worm_info_read) != 0 ||
            require_sym(g_lib, "worm_transaction_response_new", NULL,
                        (void **)&p_worm_tx_resp_new) != 0 ||
            require_sym(g_lib, "worm_transaction_response_free", NULL,
                        (void **)&p_worm_tx_resp_free) != 0 ||
            require_sym(g_lib, "worm_transaction_start", NULL, (void **)&p_worm_tx_start) != 0 ||
            require_sym(g_lib, "worm_transaction_finish", NULL, (void **)&p_worm_tx_finish) != 0 ||
            require_sym(g_lib, "worm_transaction_response_transactionNumber", NULL,
                        (void **)&p_worm_tx_resp_tx_num) != 0 ||
            require_sym(g_lib, "worm_transaction_response_signatureCounter", NULL,
                        (void **)&p_worm_tx_resp_sig_counter) != 0 ||
            require_sym(g_lib, "worm_transaction_response_logTime", NULL,
                        (void **)&p_worm_tx_resp_log_time) != 0 ||
            require_sym(g_lib, "worm_transaction_response_signature", NULL,
                        (void **)&p_worm_tx_sig_legacy) != 0) {
            dlclose(g_lib);
            g_lib = NULL;
            tse_block_close(&g_block);
            return -1;
        }
        p_worm_info_serial_out = resolve(g_lib, "worm_info_tseSerialNumber", NULL);
        p_worm_info_pubkey_out = resolve(g_lib, "worm_info_tsePublicKey", NULL);
        p_worm_init_callbacks =
            resolve(g_lib, "worm_init_with_communication_callbacks", NULL);
    }

    p_worm_register_client =
        resolve(g_lib, "worm_tse_registerClient", "WormStore_tse_registerClient");
    p_worm_run_self_test = resolve(g_lib, "worm_tse_runSelfTest", "WormStore_tse_runSelfTest");
    p_worm_update_time = resolve(g_lib, "worm_tse_updateTime", "WormStore_tse_updateTime");
    p_worm_user_login = resolve(g_lib, "worm_user_login", "WormStore_user_login");
    p_worm_user_logout = resolve(g_lib, "worm_user_logout", "WormStore_user_logout");
    if (!g_legacy_api) {
        p_worm_info_serial =
            resolve(g_lib, "worm_info_tseSerialNumber", "WormInformation_tseSerialNumber");
        p_worm_info_pubkey =
            resolve(g_lib, "worm_info_tsePublicKey", "WormInformation_tsePublicKey");
    }

    p_worm_info_has_valid_time = resolve(g_lib, "worm_info_hasValidTime", NULL);
    p_worm_info_has_passed_self_test = resolve(g_lib, "worm_info_hasPassedSelfTest", NULL);
    p_worm_info_registered_clients = resolve(g_lib, "worm_info_registeredClients", NULL);
    p_worm_info_max_registered_clients = resolve(g_lib, "worm_info_maxRegisteredClients", NULL);
    p_worm_info_is_tx_in_progress = resolve(g_lib, "worm_info_isTransactionInProgress", NULL);
    p_worm_info_started_transactions = resolve(g_lib, "worm_info_startedTransactions", NULL);
    p_worm_info_max_started_transactions =
        resolve(g_lib, "worm_info_maxStartedTransactions", NULL);
    p_worm_info_created_signatures = resolve(g_lib, "worm_info_createdSignatures", NULL);
    p_worm_info_max_time_sync_delay =
        resolve(g_lib, "worm_info_maxTimeSynchronizationDelay", NULL);
    p_worm_info_has_changed_time_admin_pin =
        resolve(g_lib, "worm_info_hasChangedTimeAdminPin", NULL);
    p_worm_info_init_state = resolve(g_lib, "worm_info_initializationState", NULL);
    p_worm_info_hardware_version = resolve(g_lib, "worm_info_hardwareVersion", NULL);
    p_worm_info_firmware_version = resolve(g_lib, "worm_info_firmwareVersion", NULL);
    p_worm_tse_setup = resolve(g_lib, "worm_tse_setup", NULL);
    p_worm_get_log_message_certificate =
        resolve(g_lib, "worm_getLogMessageCertificate", NULL);
    p_worm_get_version = resolve(g_lib, "worm_getVersion", NULL);
    p_worm_export_tar = resolve(g_lib, "worm_export_tar", NULL);

    int opened = -1;
    if (g_legacy_api) {
        if (g_config.worm_path[0]) {
            opened = open_store(g_config.worm_path);
        }
        if (opened != 0) {
            opened = try_legacy_mount_paths();
        }
        if (opened != 0 && ensure_block_open() == 0) {
            opened = open_store_legacy_block();
            if (opened == 0 && g_config.worm_path[0]) {
                log_warn("using block I/O on %s (mount at %s is read-only or unavailable)",
                         g_block.device, g_config.worm_path);
            }
        }
    } else {
        if (ensure_block_open() != 0) {
            dlclose(g_lib);
            g_lib = NULL;
            return -1;
        }
        if (g_config.worm_path[0]) {
            opened = open_store(g_config.worm_path);
        }
        if (opened != 0) {
            opened = open_store(g_block.device);
        }
        if (opened != 0) {
            opened = open_store_with_block();
        }
    }
    if (opened != 0) {
        log_error("worm init failed. The TSE was not found on any removable device — "
                  "ensure the TSE USB/SD device is inserted and accessible.");
        dlclose(g_lib);
        g_lib = NULL;
        tse_block_close(&g_block);
        return -1;
    }

    refresh_info_fields();
    refresh_certificate();
    ensure_tse_provisioned();
    ensure_self_test_passed();
    /*
     * The TSE remembers whether it has valid time independently of this
     * process (it's fiscal state on the device, not in-memory). A
     * TimeAdmin login + updateTime + logout round trip costs ~2x the USB
     * command latency (seen: ~400ms combined) even when nothing needs to
     * change, so skip it at startup if the clock is already valid — the
     * background thread (time_sync_thread_main) will keep it that way and
     * resync proactively well before it would expire.
     */
    if (!worm_has_valid_time()) {
        perform_time_sync();
    }
    log_worm_diagnostics("startup");

    if (g_serial[0]) {
        util_strlcpy(g_config.tse_serial, g_serial, sizeof(g_config.tse_serial));
    }

    g_active = true;
    start_time_sync_thread();
    log_info("TSE mode:   hardware");
    if (g_block.offsets_valid) {
        log_info("TSE device: %s (info LBA %u)", g_block.device, g_block.lba_info);
    } else {
        log_info("TSE device: %s (mounted)", g_config.tse_device);
    }
    log_info("Worm path:  %s", g_store_path);
    log_info("WormAPI:    %s (%s)", g_config.worm_lib, g_legacy_api ? "legacy C API" : "store API");
    if (g_serial[0]) {
        log_info("TSE serial: %s", g_serial);
    }
    return 0;
}

void tse_worm_shutdown(void) {
    pthread_mutex_lock(&g_worm_mu);
    if (g_store) {
        if (g_legacy_api && p_worm_cleanup) {
            p_worm_cleanup(g_store);
        } else if (p_worm_store_free) {
            p_worm_store_free(g_store);
        }
        g_store = 0;
    }
    if (g_lib) {
        dlclose(g_lib);
        g_lib = NULL;
    }
    tse_block_close(&g_block);
    g_active = false;
    pthread_mutex_unlock(&g_worm_mu);
}

int tse_worm_register_client(const char *client_id) {
    if (!g_active || !p_worm_register_client) {
        return 0;
    }
    char safe_id[40];
    worm_safe_client_id(client_id, safe_id, sizeof(safe_id));

    pthread_mutex_lock(&g_worm_mu);
    bool logged_in = false;
    if (g_config.worm_admin_pin[0] && p_worm_user_login && p_worm_user_logout) {
        logged_in =
            worm_user_login_call(WORM_USER_ADMIN, g_config.worm_admin_pin) == WORM_ERROR_NOERROR;
        if (!logged_in) {
            log_warn("Admin login failed (check CLOUDTSE_WORM_ADMIN_PIN)");
        }
    }
    int rc = (int)WORM_HW_CALL("worm_tse_registerClient",
                                p_worm_register_client(g_store, safe_id));
    if (rc == WORM_ERROR_NOERROR && p_worm_run_self_test) {
        (void)WORM_HW_CALL("worm_tse_runSelfTest", p_worm_run_self_test(g_store, safe_id));
    }
    if (logged_in) {
        worm_user_logout_call(WORM_USER_ADMIN);
    }
    pthread_mutex_unlock(&g_worm_mu);
    if (rc != WORM_ERROR_NOERROR) {
        log_error("worm_tse_registerClient('%s') failed (error %d)", safe_id, rc);
    }
    if (rc == WORM_ERROR_NOERROR) {
        worm_client_mark_registered(client_id);
        db_set_setting("worm_known_client", safe_id);
    }
    return rc == WORM_ERROR_NOERROR ? 0 : -1;
}

static void ensure_client_registered(const char *client_id) {
    if (!client_id || !client_id[0] || worm_client_is_cached_registered(client_id)) {
        return;
    }
    /*
     * If the client is already registered on the TSE, this typically
     * errors out too, and either way the subsequent transaction_start call
     * is the authoritative check. We only want to avoid the common case
     * where a client obtained a bearer token but was never registered
     * against this physical TSE. Log the outcome so a genuine registration
     * failure (as opposed to "already registered") is visible.
     */
    int rc = tse_worm_register_client(client_id);
    if (rc != 0) {
        log_debug("auto-register of client '%s' returned an error (likely already registered; "
                  "ignoring)",
                  client_id);
    }
    worm_client_mark_registered(client_id);
}

int tse_worm_start_transaction(const char *client_id, const char *process_type,
                               const char *process_data, tse_transaction_t *out, char *err_msg,
                               size_t err_msg_len) {
    (void)process_data;
    if (!g_active) {
        return -1;
    }

    ensure_client_registered(client_id);
    char safe_id[40];
    worm_safe_client_id(client_id, safe_id, sizeof(safe_id));

    pthread_mutex_lock(&g_worm_mu);
    if (!worm_has_valid_time()) {
        (void)perform_time_sync();
    }
    worm_handle response = p_worm_tx_resp_new(g_store);
    if (!response) {
        pthread_mutex_unlock(&g_worm_mu);
        snprintf(err_msg, err_msg_len, "worm_transaction_response_new failed");
        return -1;
    }

    const char *ptype = (process_type && process_type[0]) ? process_type : "Kassenbeleg";
    /*
     * Some WormAPI builds validate process_data as a real (non-NULL)
     * pointer even when its length is 0 and reject NULL with
     * WORM_ERROR_TSE_INVALID_PARAMETER. Pass a valid empty buffer instead.
     */
    int rc = (int)WORM_HW_CALL(
        "worm_transaction_start",
        p_worm_tx_start(g_store, safe_id, (const unsigned char *)"", 0, ptype, response));
    if (rc != WORM_ERROR_NOERROR) {
        p_worm_tx_resp_free(response);
        log_worm_diagnostics("transaction_start failed");
        pthread_mutex_unlock(&g_worm_mu);
        snprintf(err_msg, err_msg_len, "worm_transaction_start failed (error %d)", rc);
        return -1;
    }

    fill_tx_from_response(response, out);
    strncpy(out->process_type, ptype, sizeof(out->process_type) - 1);
    strncpy(out->client_id, client_id, sizeof(out->client_id) - 1);
    strncpy(out->state, "ACTIVE", sizeof(out->state) - 1);

    p_worm_tx_resp_free(response);
    pthread_mutex_unlock(&g_worm_mu);
    return 0;
}

int tse_worm_finish_transaction(const char *client_id, int64_t transaction_number,
                                const char *process_type, const char *process_data,
                                tse_transaction_t *out, char *err_code, size_t err_code_len,
                                char *err_msg, size_t err_msg_len) {
    if (!g_active) {
        return -1;
    }

    char safe_id[40];
    worm_safe_client_id(client_id, safe_id, sizeof(safe_id));

    pthread_mutex_lock(&g_worm_mu);
    /*
     * A transaction can stay open for an arbitrary amount of time between
     * start and finish, so the clock that was valid at start_transaction
     * time isn't guaranteed to still be valid here. Check and proactively
     * resync before finishing too, matching start_transaction, instead of
     * just letting worm_transaction_finish fail with
     * WORM_ERROR_NO_TIME_SET.
     */
    if (!worm_has_valid_time()) {
        (void)perform_time_sync();
    }
    worm_handle response = p_worm_tx_resp_new(g_store);
    if (!response) {
        pthread_mutex_unlock(&g_worm_mu);
        snprintf(err_msg, err_msg_len, "worm_transaction_response_new failed");
        return -1;
    }

    const char *ptype = (process_type && process_type[0]) ? process_type : "Kassenbeleg";
    /* See tse_worm_start_transaction: pass a valid empty buffer, never NULL. */
    const unsigned char *pdata = (const unsigned char *)"";
    unsigned int pdlen = 0;
    uint8_t decoded[4096];
    if (process_data && process_data[0]) {
        int n = util_base64_decode(process_data, (char *)decoded, sizeof(decoded));
        if (n > 0) {
            pdata = decoded;
            pdlen = (unsigned int)n;
        } else {
            pdata = (const unsigned char *)process_data;
            pdlen = (unsigned int)strlen(process_data);
        }
    }

    int rc = (int)WORM_HW_CALL(
        "worm_transaction_finish",
        p_worm_tx_finish(g_store, safe_id, (unsigned long long)transaction_number, pdata, pdlen,
                          ptype, response));
    if (rc != WORM_ERROR_NOERROR) {
        p_worm_tx_resp_free(response);
        log_worm_diagnostics("transaction_finish failed");
        pthread_mutex_unlock(&g_worm_mu);
        strncpy(err_code, "ErrorNoTransaction", err_code_len);
        snprintf(err_msg, err_msg_len, "worm_transaction_finish failed (error %d)", rc);
        return -1;
    }

    fill_tx_from_response(response, out);
    strncpy(out->client_id, client_id, sizeof(out->client_id) - 1);
    strncpy(out->process_type, ptype, sizeof(out->process_type) - 1);
    strncpy(out->state, "FINISHED", sizeof(out->state) - 1);
    out->transaction_number = transaction_number;

    p_worm_tx_resp_free(response);
    pthread_mutex_unlock(&g_worm_mu);
    return 0;
}

void tse_worm_fill_info(tse_info_t *info) {
    if (!info) {
        return;
    }
    if (g_serial[0]) {
        util_strlcpy(info->serial_number, g_serial, sizeof(info->serial_number));
    }
    if (g_store && p_worm_info_new && p_worm_info_read) {
        worm_handle wi = p_worm_info_new(g_store);
        if (wi) {
            if (WORM_HW_CALL("worm_info_read", p_worm_info_read(wi)) == WORM_ERROR_NOERROR) {
                if (p_worm_info_registered_clients) {
                    info->registered_clients = (int64_t)p_worm_info_registered_clients(wi);
                }
                if (p_worm_info_max_registered_clients) {
                    info->max_registered_clients = (int64_t)p_worm_info_max_registered_clients(wi);
                }
                if (p_worm_info_started_transactions) {
                    info->transaction_counter = (int64_t)p_worm_info_started_transactions(wi);
                }
                if (p_worm_info_max_started_transactions) {
                    info->max_started_transactions =
                        (int64_t)p_worm_info_max_started_transactions(wi);
                }
                if (p_worm_info_created_signatures) {
                    info->signature_counter = (int64_t)p_worm_info_created_signatures(wi);
                }
                if (p_worm_info_hardware_version) {
                    snprintf(info->hardware_version, sizeof(info->hardware_version), "%llu",
                             (unsigned long long)p_worm_info_hardware_version(wi));
                }
                if (p_worm_info_firmware_version) {
                    snprintf(info->firmware_version, sizeof(info->firmware_version), "%llu",
                             (unsigned long long)p_worm_info_firmware_version(wi));
                }
            }
            if (p_worm_info_free) {
                p_worm_info_free(wi);
            }
        }
    }
    if (p_worm_get_version) {
        const char *v = p_worm_get_version();
        if (v) {
            util_strlcpy(info->worm_api_version, v, sizeof(info->worm_api_version));
        }
    }
}

int tse_worm_export_prepare(void) {
    if (!g_active || !p_worm_export_tar) {
        return -1;
    }
    /*
     * worm_export_tar itself requires the TSE to have passed self-test and to
     * have valid time (the library returns WORM_ERROR_WRONG_STATE_NEEDS_SELF_TEST
     * / WORM_ERROR_NO_TIME_SET otherwise). Do that gatekeeping up front, while we
     * can still return a clean JSON error, instead of partway through a streamed
     * response whose headers have already been sent.
     */
    pthread_mutex_lock(&g_worm_mu);
    ensure_self_test_passed();
    if (!worm_has_valid_time()) {
        (void)perform_time_sync();
    }
    int ready = worm_has_passed_self_test() && worm_has_valid_time();
    pthread_mutex_unlock(&g_worm_mu);
    return ready ? 0 : -1;
}

int tse_worm_export_tar(tse_worm_export_cb cb, void *ctx) {
    if (!g_active || !p_worm_export_tar) {
        return -1;
    }
    pthread_mutex_lock(&g_worm_mu);
    ensure_self_test_passed();
    if (!worm_has_valid_time()) {
        (void)perform_time_sync();
    }
    /*
     * The export callback walks the whole TSE log and may take a while; hold
     * the lock so no other thread mutates TSE state mid-export. The callback
     * only writes to the socket (no TSE calls), so the TSE stays idle while it
     * streams.
     */
    long long rc = WORM_HW_CALL("worm_export_tar",
                                 p_worm_export_tar(g_store, cb, ctx));
    pthread_mutex_unlock(&g_worm_mu);
    return rc == WORM_ERROR_NOERROR ? 0 : -1;
}
