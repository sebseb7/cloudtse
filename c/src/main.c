#include "config.h"
#include "db.h"
#include "http.h"
#include "log.h"
#include "network.h"
#include "store.h"
#include "tse_worm.h"

#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static pthread_mutex_t g_log_mu = PTHREAD_MUTEX_INITIALIZER;

static void log_lock_fn(bool lock, void *udata) {
    (void)udata;
    if (lock) {
        pthread_mutex_lock(&g_log_mu);
    } else {
        pthread_mutex_unlock(&g_log_mu);
    }
}

static volatile sig_atomic_t g_running = 1;

static void on_signal(int sig) {
    (void)sig;
    g_running = 0;
    http_shutdown();
}

int main(void) {

    setvbuf(stdout, NULL, _IONBF, 0);

    /*
     * log.c (vendored in src/log.c) writes to stdout above and fflushes
     * after every call on top of that, so console output is guaranteed
     * visible immediately regardless of libc/terminal buffering behavior.
     * The background time-sync thread logs concurrently with the request
     * handler, so serialize output with a mutex to avoid interleaved lines.
     */
    log_set_lock(log_lock_fn, NULL);
    log_set_level(LOG_TRACE);

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGPIPE, SIG_IGN);

    config_load();

    if (db_open(g_config.db_path) != 0) {
        return 1;
    }
    if (db_init_schema() != 0) {
        db_close();
        return 1;
    }
    store_init();

    char public_ip[64] = {0};
    int have_public = (network_resolve_public_ip(public_ip, sizeof(public_ip)) == 0);
    char ips[8][64];
    int ip_count = network_local_ips(ips, 8);

    log_info("BSI TR-03153 cloud TSE — development only [C]");
    log_info("─────────────────────────────────────────────────────");
    log_info("Listening:  http://%s:%u", g_config.host, g_config.port);
    if (have_public) {
        log_info("Client IP:  %s", public_ip);
    } else {
        for (int i = 0; i < ip_count; i++) {
            log_info("Client IP:  %s  (private — set CLOUDTSE_PUBLIC_IP or allow outbound HTTPS)",
                      ips[i]);
        }
    }
    log_info("Port:       %u", g_config.port);
    log_info("EAS-Code:   %s", g_config.eas_code);
    log_info("TSE serial: %s", g_config.tse_serial);
    log_info("Database:   %s", g_config.db_path);
    if (g_config.tse_mode == TSE_MODE_HARDWARE) {
        log_info("TSE mode:   hardware (%s)", g_config.tse_device);
        if (tse_worm_is_active()) {
            log_info("WormAPI:    %s", g_config.worm_lib);
        } else {
            log_info("WormAPI:    not loaded (simulator fallback)");
        }
    } else {
        log_info("TSE mode:   simulator");
    }
    log_info("IP           = one of the addresses above");
    log_info("Port         = %u", g_config.port);
    log_info("Seriennummer = your Kassen-ID / EAS serial");
    log_info("EAS-Code     = %s", g_config.eas_code);

    if (!g_running) {
        store_shutdown();
        db_close();
        return 0;
    }

    int rc = http_serve(g_config.host, g_config.port, &g_running);
    store_shutdown();
    db_close();
    return rc == 0 ? 0 : 1;
}
