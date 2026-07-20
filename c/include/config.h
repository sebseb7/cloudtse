#ifndef CLOUDTSE_CONFIG_H
#define CLOUDTSE_CONFIG_H

#include <stdbool.h>
#include <stdint.h>

#define CLOUDTSE_DEFAULT_PORT 20001
#define CLOUDTSE_DEFAULT_HOST "0.0.0.0"
#define CLOUDTSE_DEFAULT_EAS_CODE "12345678"
#define CLOUDTSE_DEFAULT_TSE_SERIAL \
    "A1B2C3D4E5F60718293A4B5C6D7E8F90123456789ABCDEF0123456789ABCDEF"
#define CLOUDTSE_DEFAULT_FCC_VERSION "4.4.0-sim"
#define CLOUDTSE_DEFAULT_FCC_VERSION_HW "4.4.0-hw"
#define CLOUDTSE_DEFAULT_DB_PATH "data/cloudtse.db"
#define CLOUDTSE_DEFAULT_TSE_DEVICE ""
#define CLOUDTSE_DEFAULT_WORM_LIB "libWormAPI.so"
#define CLOUDTSE_DEFAULT_WORM_CREDENTIAL_SEED "SwissbitSwissbit"

typedef enum {
    TSE_MODE_SIM = 0,
    TSE_MODE_HARDWARE = 1,
} tse_mode_t;

typedef struct {
    char host[64];
    uint16_t port;
    char public_ip[64];
    char eas_code[128];
    /* Comma-separated client_id allowlist. Empty = open self-registration. */
    char allowed_client_serial[1024];
    char tse_serial[128];
    char fcc_version[64];
    char db_path[512];
    bool log_requests;
    tse_mode_t tse_mode;
    char tse_device[256];
    char worm_path[512];
    char worm_lib[512];
    char worm_admin_pin[128];
    char worm_admin_puk[128];
    char worm_time_admin_pin[128];
    char worm_credential_seed[64];
    char leaf_certificate[6144];
    char tse_public_key_b64[256];
    /*
     * Daily local-time self-test schedule from CLOUDTSE_SELF_TEST_AT (HH:MM).
     * self_test_at_hour < 0 means disabled.
     */
    int self_test_at_hour;
    int self_test_at_minute;
} cloudtse_config_t;

extern cloudtse_config_t g_config;

void config_load(void);
/* 1 if allowlist is empty or client_serial is listed (comma-separated). */
int config_is_client_allowed(const char *client_serial);

#endif
