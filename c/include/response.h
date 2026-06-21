#ifndef CLOUDTSE_RESPONSE_H
#define CLOUDTSE_RESPONSE_H

#include "store.h"
#include <stddef.h>

int response_start_transaction_json(const tse_transaction_t *tx, char *out, size_t outlen);
int response_finish_transaction_json(const tse_transaction_t *tx, char *out, size_t outlen);
int response_tss_details_json(const char *serial, char *out, size_t outlen);
int response_info_json(int64_t registered_clients, int64_t transaction_counter,
                       char *out, size_t outlen);
int response_health_json(const tse_info_t *info, char *out, size_t outlen);
int response_oauth_json(const char *access_token, char *out, size_t outlen);
int response_error_json(int status, const char *error, const char *description,
                        char *out, size_t outlen);
int response_tx_error_json(const char *code, const char *message, char *out, size_t outlen);
int response_not_found_json(const char *method, const char *path, char *out, size_t outlen);

#endif
