#include "handlers.h"
#include "config.h"
#include "db.h"
#include "json.h"
#include "response.h"
#include "store.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int is_transaction_path(const char *path) {
    if (strcmp(path, "/transaction") == 0) {
        return 1;
    }
    if (strncmp(path, "/transaction/", 13) != 0) {
        return 0;
    }
    const char *id = path + 13;
    if (!id[0]) {
        return 0;
    }
    for (const char *p = id; *p; p++) {
        if (*p < '0' || *p > '9') {
            return 0;
        }
    }
    return 1;
}

static void log_field(const char *key, const char *value) {
    if (value && value[0]) {
        printf("    %s: %s\n", key, value);
    }
}

static void log_transaction_payload(const char *label, const http_request_t *req) {
    char client_id[256];
    char process_type[512];
    char process_data[4096];
    char external_id[256];
    client_id[0] = '\0';
    process_type[0] = '\0';
    process_data[0] = '\0';
    external_id[0] = '\0';

    json_get_string(req->body, "clientId", client_id, sizeof(client_id));
    json_get_string(req->body, "processType", process_type, sizeof(process_type));
    json_get_string(req->body, "processData", process_data, sizeof(process_data));
    json_get_string(req->body, "externalTransactionId", external_id, sizeof(external_id));

    printf("  %s:\n", label);
    log_field("clientId", client_id);
    log_field("processType", process_type);
    log_field("externalTransactionId", external_id);
    log_field("processData", process_data);

    if (process_data[0]) {
        char decoded[4096];
        if (util_base64_decode(process_data, decoded, sizeof(decoded)) > 0) {
            printf("    processData (decoded): %s\n", decoded);
        } else {
            printf("    processData (decoded): [not base64 UTF-8]\n");
        }
    }
}

static void log_request(const http_request_t *req, const char *path) {
    if (!g_config.log_requests) {
        return;
    }
    char now[64];
    util_now_iso(now, sizeof(now));
    printf("[%s] %s %s\n", now, req->method, path);
    const char *auth = http_get_header(req, "Authorization");
    if (auth) {
        printf("  authorization: %s\n", auth);
    }
    if (req->body_len > 0) {
        if (is_transaction_path(path)) {
            log_transaction_payload("transaction payload", req);
        } else {
            printf("  body: %s\n", req->body);
        }
    }
}

static void log_response(int status, const char *body) {
    if (!g_config.log_requests) {
        return;
    }
    printf("  → %d\n", status);
    if (body && body[0]) {
        printf("%s\n", body);
    }
}

static void set_json_response(http_response_t *res, int status, const char *json) {
    res->status = status;
    res->no_body = false;
    strncpy(res->body, json, sizeof(res->body) - 1);
    res->body[sizeof(res->body) - 1] = '\0';
    res->body_len = strlen(res->body);
}

static int validate_bearer(const http_request_t *req, http_response_t *res) {
    char token[128];
    if (http_parse_bearer(req, token, sizeof(token)) != 0) {
        char json[256];
        response_error_json(401, "unauthorized", "Invalid or missing Bearer token", json,
                            sizeof(json));
        set_json_response(res, 401, json);
        return -1;
    }
    char serial[256];
    if (db_load_oauth_token(token, serial, sizeof(serial)) != 0) {
        char json[256];
        response_error_json(401, "unauthorized", "Invalid or missing Bearer token", json,
                            sizeof(json));
        set_json_response(res, 401, json);
        return -1;
    }
    return 0;
}

static int get_bearer_client(const http_request_t *req, char *out, size_t outlen) {
    char token[128];
    if (http_parse_bearer(req, token, sizeof(token)) != 0) {
        return -1;
    }
    return db_load_oauth_token(token, out, outlen);
}

static void handle_oauth(http_request_t *req, http_response_t *res) {
    char client_id[256];
    char client_secret[256];
    if (http_parse_basic_auth(req, client_id, sizeof(client_id), client_secret,
                              sizeof(client_secret)) != 0) {
        char json[256];
        response_error_json(401, "unauthorized", "Missing Authorization: Basic header", json,
                            sizeof(json));
        set_json_response(res, 401, json);
        return;
    }

    int eas_ok = (strcmp(g_config.eas_code, "*") == 0) ||
                 (strcmp(client_secret, g_config.eas_code) == 0);
    if (!eas_ok) {
        char msg[128];
        snprintf(msg, sizeof(msg), "Invalid EAS code (got: %s)",
                 client_secret[0] ? "[present]" : "[missing]");
        char json[256];
        response_error_json(401, "unauthorized", msg, json, sizeof(json));
        set_json_response(res, 401, json);
        return;
    }

    const char *client_serial = client_id[0] ? client_id : "unknown";
    if (strcmp(client_serial, "unknown") != 0) {
        store_register_client(client_serial);
    }

    char token[64];
    if (util_random_hex(token, sizeof(token), 24) != 0) {
        char json[256];
        response_error_json(500, "internal_error", "token generation failed", json, sizeof(json));
        set_json_response(res, 500, json);
        return;
    }
    db_save_oauth_token(token, client_serial, 86400);

    char json[256];
    response_oauth_json(token, json, sizeof(json));
    set_json_response(res, 200, json);
}

static const char *pick_body_field(const http_request_t *req, const char *key, char *buf,
                                   size_t buflen) {
    if (json_get_string(req->body, key, buf, buflen) == 0 && buf[0]) {
        return buf;
    }
    return NULL;
}

static void resolve_client_id(const http_request_t *req, char *out, size_t outlen) {
    char tmp[256];
    if (pick_body_field(req, "clientId", tmp, sizeof(tmp))) {
        strncpy(out, tmp, outlen - 1);
        out[outlen - 1] = '\0';
        util_trim(out);
        return;
    }
    if (get_bearer_client(req, tmp, sizeof(tmp)) == 0 && tmp[0]) {
        strncpy(out, tmp, outlen - 1);
        out[outlen - 1] = '\0';
        util_trim(out);
        return;
    }
    strncpy(out, "default", outlen - 1);
}

static void handle_start_transaction(http_request_t *req, http_response_t *res) {
    if (validate_bearer(req, res) != 0) {
        return;
    }

    char client_id[256];
    char process_type[512];
    char process_data[4096];
    char external_id[256];
    process_type[0] = '\0';
    process_data[0] = '\0';
    external_id[0] = '\0';

    resolve_client_id(req, client_id, sizeof(client_id));
    pick_body_field(req, "processType", process_type, sizeof(process_type));
    pick_body_field(req, "processData", process_data, sizeof(process_data));
    pick_body_field(req, "externalTransactionId", external_id, sizeof(external_id));

    tse_transaction_t tx;
    if (store_start_transaction(client_id, process_type, process_data,
                                external_id[0] ? external_id : NULL, &tx) != 0) {
        char json[256];
        response_error_json(500, "internal_error", "transaction start failed", json, sizeof(json));
        set_json_response(res, 500, json);
        return;
    }

    char json[HTTP_MAX_BODY];
    response_start_transaction_json(&tx, json, sizeof(json));
    set_json_response(res, 200, json);
}

static void handle_finish_transaction(http_request_t *req, const char *tx_id,
                                      http_response_t *res) {
    if (validate_bearer(req, res) != 0) {
        return;
    }

    char client_id[256];
    char process_type[512];
    char process_data[4096];
    process_type[0] = '\0';
    process_data[0] = '\0';

    resolve_client_id(req, client_id, sizeof(client_id));
    pick_body_field(req, "processType", process_type, sizeof(process_type));
    pick_body_field(req, "processData", process_data, sizeof(process_data));

    tse_transaction_t tx;
    char err_code[64];
    char err_msg[256];
    int64_t tx_num = atoll(tx_id);
    if (store_finish_transaction(client_id, tx_num, process_type, process_data, &tx, err_code,
                                 sizeof(err_code), err_msg, sizeof(err_msg)) != 0) {
        char json[512];
        response_tx_error_json(err_code[0] ? err_code : "transaction_error", err_msg, json,
                               sizeof(json));
        set_json_response(res, 400, json);
        return;
    }

    char json[HTTP_MAX_BODY];
    response_finish_transaction_json(&tx, json, sizeof(json));
    set_json_response(res, 200, json);
}

static void handle_tss_details(http_request_t *req, http_response_t *res) {
    if (validate_bearer(req, res) != 0) {
        return;
    }
    tse_info_t info;
    store_info(&info);
    char json[8192];
    response_tss_details_json(info.serial_number, json, sizeof(json));
    set_json_response(res, 200, json);
}

static void handle_info(http_request_t *req, http_response_t *res) {
    if (validate_bearer(req, res) != 0) {
        return;
    }
    tse_info_t info;
    store_info(&info);
    char json[512];
    response_info_json(info.registered_clients, info.max_registered_clients,
                       info.transaction_counter, info.max_started_transactions, json,
                       sizeof(json));
    set_json_response(res, 200, json);
}

static void handle_list_transactions(http_request_t *req, http_response_t *res) {
    if (validate_bearer(req, res) != 0) {
        return;
    }
    tse_transaction_t txs[128];
    size_t count = 0;
    if (store_list_open_transactions(txs, sizeof(txs) / sizeof(txs[0]), &count) != 0) {
        char json[256];
        response_error_json(500, "internal_error", "failed to list open transactions", json,
                            sizeof(json));
        set_json_response(res, 500, json);
        return;
    }
    char json[HTTP_MAX_BODY];
    response_open_transactions_json(txs, count, json, sizeof(json));
    set_json_response(res, 200, json);
}

static void handle_health(http_response_t *res) {
    tse_info_t info;
    store_info(&info);
    char json[HTTP_MAX_BODY];
    response_health_json(&info, json, sizeof(json));
    set_json_response(res, 200, json);
}

static int match_tx_finish(const char *path, char *tx_id, size_t tx_id_len) {
    if (strncmp(path, "/transaction/", 13) != 0) {
        return 0;
    }
    const char *id = path + 13;
    if (!id[0]) {
        return 0;
    }
    for (const char *p = id; *p; p++) {
        if (*p < '0' || *p > '9') {
            return 0;
        }
    }
    if (strlen(id) >= tx_id_len) {
        return 0;
    }
    util_strlcpy(tx_id, id, tx_id_len);
    return 1;
}

void handlers_route(http_request_t *req, http_response_t *res) {
    char path[HTTP_MAX_PATH];
    http_normalize_path(req->path, path, sizeof(path));

    log_request(req, path);

    memset(res, 0, sizeof(*res));

    if (strcmp(req->method, "OPTIONS") == 0) {
        res->status = 204;
        res->no_body = true;
        log_response(204, NULL);
        return;
    }

    if (strcmp(req->method, "GET") == 0 || strcmp(req->method, "HEAD") == 0) {
        if (strcmp(path, "/tssdetails") == 0) {
            handle_tss_details(req, res);
        } else if (strcmp(path, "/info") == 0) {
            handle_info(req, res);
        } else if (strcmp(path, "/transactions") == 0) {
            handle_list_transactions(req, res);
        } else if (strcmp(path, "/") == 0 || strcmp(path, "/health") == 0) {
            handle_health(res);
        } else {
            char json[512];
            response_not_found_json(req->method, path, json, sizeof(json));
            set_json_response(res, 404, json);
        }
    } else {
        if (strcmp(req->method, "POST") == 0 && strcmp(path, "/oauth/token") == 0) {
            handle_oauth(req, res);
        } else if (strcmp(req->method, "POST") == 0 && strcmp(path, "/transaction") == 0) {
            handle_start_transaction(req, res);
        } else {
            char tx_id[32];
            if ((strcmp(req->method, "PUT") == 0 || strcmp(req->method, "PATCH") == 0) &&
                match_tx_finish(path, tx_id, sizeof(tx_id))) {
                handle_finish_transaction(req, tx_id, res);
            } else {
                char json[512];
                response_not_found_json(req->method, path, json, sizeof(json));
                set_json_response(res, 404, json);
            }
        }
    }

    if (!res->no_body) {
        log_response(res->status, res->body);
    }
}
