#include "response.h"
#include "config.h"
#include "json.h"
#include "util.h"

#include <stdio.h>
#include <string.h>

int response_start_transaction_json(const tse_transaction_t *tx, char *out, size_t outlen) {
    char log_time[64];
    char serial[128];
    store_normalize_serial(tx->serial_number, serial, sizeof(serial));
    util_fcc_log_time(tx->time_start, log_time, sizeof(log_time));
    return snprintf(out, outlen,
                    "{\"transactionNumber\":\"%lld\",\"signatureCounter\":\"%lld\","
                    "\"signatureValue\":\"%s\",\"logTime\":\"%s\",\"serialNumber\":\"%s\"}",
                    (long long)tx->transaction_number, (long long)tx->signature_counter,
                    tx->signature_value, log_time, serial) < (int)outlen ? 0 : -1;
}

int response_finish_transaction_json(const tse_transaction_t *tx, char *out, size_t outlen) {
    char log_time[64];
    const char *iso = tx->time_end[0] ? tx->time_end : tx->time_start;
    util_fcc_log_time(iso, log_time, sizeof(log_time));
    return snprintf(out, outlen,
                    "{\"signatureCounter\":\"%lld\",\"signatureValue\":\"%s\",\"logTime\":\"%s\"}",
                    (long long)tx->signature_counter, tx->signature_value, log_time) < (int)outlen
               ? 0
               : -1;
}

int response_tss_details_json(const char *serial, char *out, size_t outlen) {
    char norm[128];
    store_normalize_serial(serial, norm, sizeof(norm));
    return snprintf(out, outlen,
                    "{\"serial\":\"%s\",\"timeFormat\":\"yyyy-MM-dd'T'HH:mm:ssX\","
                    "\"encoding\":\"UTF-8\",\"publicKey\":\"%s\","
                    "\"algorithm\":\"ecdsa-plain-SHA256\",\"leafCertificate\":\"SIMULATOR\"}",
                    norm, norm) < (int)outlen
               ? 0
               : -1;
}

int response_info_json(int64_t registered_clients, int64_t transaction_counter, char *out,
                       size_t outlen) {
    return snprintf(out, outlen,
                    "{\"maxNumberClients\":\"100\",\"maxNumberTransactions\":\"500\","
                    "\"currentNumberOfTransactions\":\"%lld\",\"registeredClients\":\"%lld\"}",
                    (long long)transaction_counter, (long long)registered_clients) < (int)outlen
               ? 0
               : -1;
}

int response_health_json(const tse_info_t *info, char *out, size_t outlen) {
    char esc_path[1024];
    json_escape(info->db_path, esc_path, sizeof(esc_path));
    return snprintf(out, outlen,
                    "{\"status\":\"ok\",\"service\":\"cloudtse\","
                    "\"version\":\"%s\",\"serialNumber\":\"%s\","
                    "\"signatureCounter\":%lld,\"transactionCounter\":%lld,"
                    "\"registeredClients\":%lld,\"initialized\":true,"
                    "\"createdAt\":\"%s\",\"fccVersion\":\"%s\",\"dbPath\":\"%s\"}",
                    g_config.fcc_version, info->serial_number, (long long)info->signature_counter,
                    (long long)info->transaction_counter, (long long)info->registered_clients,
                    info->created_at, info->fcc_version, esc_path) < (int)outlen
               ? 0
               : -1;
}

int response_oauth_json(const char *access_token, char *out, size_t outlen) {
    return snprintf(out, outlen,
                    "{\"access_token\":\"%s\",\"token_type\":\"Bearer\","
                    "\"expires_in\":86400,\"scope\":\"tse\"}",
                    access_token) < (int)outlen
               ? 0
               : -1;
}

int response_error_json(int status, const char *error, const char *description, char *out,
                        size_t outlen) {
    (void)status;
    char esc[512];
    json_escape(description, esc, sizeof(esc));
    return snprintf(out, outlen,
                    "{\"error\":\"%s\",\"error_description\":\"%s\",\"message\":\"%s\"}", error,
                    esc, esc) < (int)outlen
               ? 0
               : -1;
}

int response_tx_error_json(const char *code, const char *message, char *out, size_t outlen) {
    char esc[512];
    json_escape(message, esc, sizeof(esc));
    return snprintf(out, outlen, "{\"code\":\"%s\",\"message\":\"%s\"}", code, esc) < (int)outlen
               ? 0
               : -1;
}

int response_not_found_json(const char *method, const char *path, char *out, size_t outlen) {
    char esc[512];
    char msg[256];
    snprintf(msg, sizeof(msg), "No handler for %s %s", method, path);
    json_escape(msg, esc, sizeof(esc));
    return snprintf(out, outlen, "{\"error\":\"not_found\",\"message\":\"%s\"}", esc) < (int)outlen
               ? 0
               : -1;
}
