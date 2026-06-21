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
#define CLOUDTSE_DEFAULT_DB_PATH "data/cloudtse.db"

typedef struct {
    char host[64];
    uint16_t port;
    char public_ip[64];
    char eas_code[128];
    char tse_serial[128];
    char fcc_version[64];
    char db_path[512];
    bool log_requests;
} cloudtse_config_t;

extern cloudtse_config_t g_config;

void config_load(void);

#endif
