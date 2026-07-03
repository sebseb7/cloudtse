#include "tse_worm.h"

#include "config.h"
#include "tse_block.h"
#include "util.h"

#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define WORM_ERROR_NOERROR 0
#define WORM_USER_TIME_ADMIN 2

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

static bool g_legacy_api;
static void *g_lib;
static pthread_mutex_t g_worm_mu = PTHREAD_MUTEX_INITIALIZER;
static bool g_active;
static worm_handle g_store;
static tse_block_t g_block;
static char g_serial[128];
static char g_public_key_hex[256];
static char g_store_path[512];

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
        fprintf(stderr, "cloudtse: missing symbol %s in %s\n", primary, g_config.worm_lib);
        return -1;
    }
    return 0;
}

static int worm_user_login_call(int user_id, const char *pin) {
    if (g_legacy_api) {
        typedef int (*legacy_fn)(worm_handle, unsigned char, const char *, unsigned int);
        legacy_fn login = (legacy_fn)(void *)p_worm_user_login;
        return login(g_store, (unsigned char)user_id, pin, (unsigned int)strlen(pin));
    }
    return p_worm_user_login(g_store, user_id, pin);
}

static int open_store_legacy(const char *path, bool quiet) {
    worm_handle ctx = 0;
    int rc = p_worm_init(&ctx, path);
    if (rc != WORM_ERROR_NOERROR || !ctx) {
        if (!quiet) {
            fprintf(stderr, "cloudtse: worm_init(%s) failed (error %d)\n", path, rc);
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
    int rc = p_worm_init_callbacks(
        &ctx, NULL, (void *)WormLegacy_readInfo, (void *)WormLegacy_readComm,
        (void *)WormLegacy_writeComm, (void *)WormLegacy_readStore, (void *)WormLegacy_writeStore,
        (void *)WormLegacy_openKeepAlive, (void *)WormLegacy_closeKeepAlive,
        (void *)WormLegacy_readKeepAlive);
    if (rc != WORM_ERROR_NOERROR || !ctx) {
        fprintf(stderr, "cloudtse: worm_init_with_communication_callbacks failed (error %d)\n",
                rc);
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

static int ensure_block_open(void) {
    char err[256];
    const char *primary = g_config.tse_device;
    const char *fallback = NULL;

    if (strcmp(primary, "/dev/sda1") == 0 || strcmp(primary, "/dev/sda") == 0) {
        fallback = strcmp(primary, "/dev/sda1") == 0 ? "/dev/sda" : "/dev/sda1";
    }

    if (tse_block_probe(primary, err, sizeof(err)) == 0 &&
        tse_block_open(&g_block, primary) == 0) {
        return 0;
    }
    if (fallback && tse_block_probe(fallback, err, sizeof(err)) == 0 &&
        tse_block_open(&g_block, fallback) == 0) {
        return 0;
    }

    fprintf(stderr, "cloudtse: TSE block open failed for %s", primary);
    if (fallback) {
        fprintf(stderr, " and %s", fallback);
    }
    fprintf(stderr, ": %s\n", err);
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
    snprintf(g_store_path, sizeof(g_store_path), "block:%s", g_config.tse_device);
    return 0;
}

static void refresh_info_fields(void) {
    if (!g_store || !p_worm_info_new || !p_worm_info_read) {
        return;
    }
    worm_handle info = p_worm_info_new(g_store);
    if (!info) {
        return;
    }
    if (p_worm_info_read(info) == WORM_ERROR_NOERROR) {
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

static void sync_time_if_configured(void) {
    if (!g_config.worm_time_admin_pin[0] || !p_worm_user_login || !p_worm_update_time ||
        !p_worm_user_logout) {
        return;
    }
    if (worm_user_login_call(WORM_USER_TIME_ADMIN, g_config.worm_time_admin_pin) !=
        WORM_ERROR_NOERROR) {
        fprintf(stderr, "cloudtse: TimeAdmin login failed (check CLOUDTSE_WORM_TIME_ADMIN_PIN)\n");
        return;
    }
    unsigned long long now = (unsigned long long)time(NULL);
    if (p_worm_update_time(g_store, now) != WORM_ERROR_NOERROR) {
        fprintf(stderr, "cloudtse: tse_updateTime failed\n");
    }
    p_worm_user_logout(g_store, WORM_USER_TIME_ADMIN);
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
            util_base64_encode(sig, (size_t)sig_len, out->signature_value,
                               sizeof(out->signature_value));
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

int tse_worm_init(void) {
    memset(&g_block, 0, sizeof(g_block));
    g_block.fd = -1;

    g_lib = dlopen(g_config.worm_lib, RTLD_NOW | RTLD_LOCAL);
    if (!g_lib) {
        fprintf(stderr, "cloudtse: cannot load %s: %s\n", g_config.worm_lib, dlerror());
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
                fprintf(stderr,
                        "cloudtse: using block I/O on %s (mount at %s is read-only or unavailable)\n",
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
            opened = open_store(g_config.tse_device);
        }
        if (opened != 0) {
            opened = open_store_with_block();
        }
    }
    if (opened != 0) {
        fprintf(stderr,
                "cloudtse: worm init failed. For legacy libWormAPI set CLOUDTSE_WORM_PATH to the "
                "mounted TSE (e.g. /mnt/tse) or ensure %s is accessible.\n",
                g_config.tse_device);
        dlclose(g_lib);
        g_lib = NULL;
        tse_block_close(&g_block);
        return -1;
    }

    refresh_info_fields();
    sync_time_if_configured();

    if (g_serial[0]) {
        util_strlcpy(g_config.tse_serial, g_serial, sizeof(g_config.tse_serial));
    }

    g_active = true;
    printf("  TSE mode:   hardware\n");
    if (g_block.offsets_valid) {
        printf("  TSE device: %s (info LBA %u)\n", g_block.device, g_block.lba_info);
    } else {
        printf("  TSE device: %s (mounted)\n", g_config.tse_device);
    }
    printf("  Worm path:  %s\n", g_store_path);
    printf("  WormAPI:    %s (%s)\n", g_config.worm_lib,
           g_legacy_api ? "legacy C API" : "store API");
    if (g_serial[0]) {
        printf("  TSE serial: %s\n", g_serial);
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
    pthread_mutex_lock(&g_worm_mu);
    int rc = p_worm_register_client(g_store, client_id);
    if (rc == WORM_ERROR_NOERROR && p_worm_run_self_test) {
        (void)p_worm_run_self_test(g_store, client_id);
    }
    pthread_mutex_unlock(&g_worm_mu);
    return rc == WORM_ERROR_NOERROR ? 0 : -1;
}

int tse_worm_start_transaction(const char *client_id, const char *process_type,
                               const char *process_data, tse_transaction_t *out, char *err_msg,
                               size_t err_msg_len) {
    (void)process_data;
    if (!g_active) {
        return -1;
    }

    pthread_mutex_lock(&g_worm_mu);
    worm_handle response = p_worm_tx_resp_new(g_store);
    if (!response) {
        pthread_mutex_unlock(&g_worm_mu);
        snprintf(err_msg, err_msg_len, "worm_transaction_response_new failed");
        return -1;
    }

    const char *ptype = (process_type && process_type[0]) ? process_type : "Kassenbeleg";
    int rc = p_worm_tx_start(g_store, client_id, NULL, 0, ptype, response);
    if (rc != WORM_ERROR_NOERROR) {
        p_worm_tx_resp_free(response);
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

    pthread_mutex_lock(&g_worm_mu);
    worm_handle response = p_worm_tx_resp_new(g_store);
    if (!response) {
        pthread_mutex_unlock(&g_worm_mu);
        snprintf(err_msg, err_msg_len, "worm_transaction_response_new failed");
        return -1;
    }

    const char *ptype = (process_type && process_type[0]) ? process_type : "Kassenbeleg";
    const unsigned char *pdata = NULL;
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

    int rc = p_worm_tx_finish(g_store, client_id, (unsigned long long)transaction_number, pdata,
                              pdlen, ptype, response);
    if (rc != WORM_ERROR_NOERROR) {
        p_worm_tx_resp_free(response);
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
}
