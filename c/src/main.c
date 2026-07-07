#include "config.h"
#include "db.h"
#include "http.h"
#include "network.h"
#include "store.h"
#include "tse_worm.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static volatile sig_atomic_t g_running = 1;

static void on_signal(int sig) {
    (void)sig;
    g_running = 0;
    http_shutdown();
}

int main(void) {
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

    printf("\n");
    printf("  BSI TR-03153 cloud TSE — development only [C]\n");
    printf("  ─────────────────────────────────────────────────────\n");
    printf("  Listening:  http://%s:%u\n", g_config.host, g_config.port);
    if (have_public) {
        printf("  Client IP:  %s\n", public_ip);
    } else {
        for (int i = 0; i < ip_count; i++) {
            printf("  Client IP:  %s  (private — set CLOUDTSE_PUBLIC_IP or allow outbound HTTPS)\n",
                   ips[i]);
        }
    }
    printf("  Port:       %u\n", g_config.port);
    printf("  EAS-Code:   %s\n", g_config.eas_code);
    printf("  TSE serial: %s\n", g_config.tse_serial);
    printf("  Database:   %s\n", g_config.db_path);
    if (g_config.tse_mode == TSE_MODE_HARDWARE) {
        printf("  TSE mode:   hardware (%s)\n", g_config.tse_device);
        if (tse_worm_is_active()) {
            printf("  WormAPI:    %s\n", g_config.worm_lib);
        } else {
            printf("  WormAPI:    not loaded (simulator fallback)\n");
        }
    } else {
        printf("  TSE mode:   simulator\n");
    }
    printf("\n");
    printf("    IP           = one of the addresses above\n");
    printf("    Port         = %u\n", g_config.port);
    printf("    Seriennummer = your Kassen-ID / EAS serial\n");
    printf("    EAS-Code     = %s\n", g_config.eas_code);
    printf("\n");

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
