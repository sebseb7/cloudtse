#ifndef CLOUDTSE_STORE_H
#define CLOUDTSE_STORE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct {
    int64_t transaction_number;
    char client_id[256];
    char external_transaction_id[256];
    char process_type[512];
    char process_data[4096];
    char state[32];
    char time_start[64];
    char time_end[64];
    int64_t signature_counter;
    char signature_value[128];
    char serial_number[128];
} tse_transaction_t;

typedef struct {
    char serial_number[128];
    int64_t signature_counter;
    int64_t transaction_counter;
    int64_t registered_clients;
    bool initialized;
    char created_at[64];
    char fcc_version[64];
    char db_path[512];
} tse_info_t;

void store_init(void);
void store_normalize_serial(const char *value, char *out, size_t outlen);

int store_register_client(const char *serial_number);
int store_start_transaction(const char *client_id, const char *process_type,
                            const char *process_data, const char *external_tx_id,
                            tse_transaction_t *out);
int store_finish_transaction(const char *client_id, int64_t transaction_number,
                             const char *process_type, const char *process_data,
                             tse_transaction_t *out, char *err_code, size_t err_code_len,
                             char *err_msg, size_t err_msg_len);
void store_info(tse_info_t *info);

#endif
