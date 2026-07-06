#include "store.h"
#include "config.h"
#include "db.h"
#include "tse_worm.h"
#include "util.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char g_created_at[64];

void store_normalize_serial(const char *value, char *out, size_t outlen) {
    char tmp[256];
    strncpy(tmp, value ? value : "", sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';
    util_trim(tmp);
    if (strlen(tmp) >= 32 && util_is_hex_serial(tmp)) {
        strncpy(out, tmp, outlen - 1);
        out[outlen - 1] = '\0';
        util_uppercase(out);
        return;
    }
    strncpy(out, CLOUDTSE_DEFAULT_TSE_SERIAL, outlen - 1);
    out[outlen - 1] = '\0';
}

static void load_transaction_row(sqlite3_stmt *stmt, tse_transaction_t *tx) {
    memset(tx, 0, sizeof(*tx));
    tx->transaction_number = sqlite3_column_int64(stmt, 0);
    const char *client_id = (const char *)sqlite3_column_text(stmt, 1);
    const char *ext = (const char *)sqlite3_column_text(stmt, 2);
    const char *ptype = (const char *)sqlite3_column_text(stmt, 3);
    const char *pdata = (const char *)sqlite3_column_text(stmt, 4);
    const char *state = (const char *)sqlite3_column_text(stmt, 5);
    const char *tstart = (const char *)sqlite3_column_text(stmt, 6);
    const char *tend = (const char *)sqlite3_column_text(stmt, 7);
    tx->signature_counter = sqlite3_column_int64(stmt, 8);
    const char *sig = (const char *)sqlite3_column_text(stmt, 9);

    if (client_id) {
        strncpy(tx->client_id, client_id, sizeof(tx->client_id) - 1);
    }
    if (ext) {
        strncpy(tx->external_transaction_id, ext, sizeof(tx->external_transaction_id) - 1);
    }
    if (ptype) {
        strncpy(tx->process_type, ptype, sizeof(tx->process_type) - 1);
    }
    if (pdata) {
        strncpy(tx->process_data, pdata, sizeof(tx->process_data) - 1);
    }
    if (state) {
        strncpy(tx->state, state, sizeof(tx->state) - 1);
    }
    if (tstart) {
        strncpy(tx->time_start, tstart, sizeof(tx->time_start) - 1);
    }
    if (tend) {
        strncpy(tx->time_end, tend, sizeof(tx->time_end) - 1);
    }
    if (sig) {
        strncpy(tx->signature_value, sig, sizeof(tx->signature_value) - 1);
    }
    char serial_buf[128];
    db_get_setting("tse_serial", serial_buf, sizeof(serial_buf));
    store_normalize_serial(serial_buf, tx->serial_number, sizeof(tx->serial_number));
}

void store_init(void) {
    char buf[128];
    if (g_config.tse_mode == TSE_MODE_HARDWARE) {
        if (tse_worm_init() != 0) {
            fprintf(stderr, "cloudtse: hardware TSE init failed — falling back to simulator\n");
        }
    }
    if (db_get_setting("created_at", g_created_at, sizeof(g_created_at))) {
        return;
    }
    util_now_iso(g_created_at, sizeof(g_created_at));
    store_normalize_serial(g_config.tse_serial, buf, sizeof(buf));
    (void)buf;
}

void store_shutdown(void) {
    if (tse_worm_is_active()) {
        tse_worm_shutdown();
    }
}

int store_register_client(const char *serial_number) {
    if (tse_worm_is_active()) {
        return tse_worm_register_client(serial_number);
    }
    char now[64];
    util_now_iso(now, sizeof(now));
    const char *sql =
        "INSERT INTO clients (serial_number, registered_at, state, type_of_system, meta_json) "
        "VALUES (?, ?, 'REGISTERED', NULL, NULL) "
        "ON CONFLICT(serial_number) DO UPDATE SET "
        "registered_at = excluded.registered_at, state = excluded.state;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_text(stmt, 1, serial_number, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, now, -1, SQLITE_STATIC);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? 0 : -1;
}

/*
 * The hardware TSE is the source of truth for signatures, but it only
 * exposes a *count* of started transactions (worm_info_startedTransactions),
 * not their identities. Mirror start/finish into the local `transactions`
 * table (state only, no re-signing) so GET /transactions can report which
 * transaction numbers are still open ("started" on the TSE, no matching
 * finish yet), even in hardware mode.
 */
static void record_transaction_open(const tse_transaction_t *tx, const char *external_tx_id) {
    const char *sql =
        "INSERT INTO transactions ("
        "transaction_number, client_id, external_transaction_id,"
        "process_type, process_data, state, time_start,"
        "signature_counter, signature_value"
        ") VALUES (?, ?, ?, ?, ?, 'ACTIVE', ?, ?, ?) "
        "ON CONFLICT(transaction_number) DO UPDATE SET "
        "client_id = excluded.client_id, external_transaction_id = excluded.external_transaction_id, "
        "process_type = excluded.process_type, state = 'ACTIVE';";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return;
    }
    char now[64];
    util_now_iso(now, sizeof(now));
    sqlite3_bind_int64(stmt, 1, tx->transaction_number);
    sqlite3_bind_text(stmt, 2, tx->client_id, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, external_tx_id && external_tx_id[0] ? external_tx_id : NULL, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, tx->process_type, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, "", -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 6, now, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 7, tx->signature_counter);
    sqlite3_bind_text(stmt, 8, tx->signature_value, -1, SQLITE_STATIC);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

static void record_transaction_finished(int64_t transaction_number) {
    const char *sql = "UPDATE transactions SET state = 'FINISHED', time_end = ? "
                      "WHERE transaction_number = ?;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return;
    }
    char now[64];
    util_now_iso(now, sizeof(now));
    sqlite3_bind_text(stmt, 1, now, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 2, transaction_number);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

int store_list_open_transactions(tse_transaction_t *out, size_t max, size_t *out_count) {
    *out_count = 0;
    const char *sql = "SELECT transaction_number, client_id, external_transaction_id, "
                      "process_type, process_data, state, time_start, time_end, "
                      "signature_counter, signature_value "
                      "FROM transactions WHERE state = 'ACTIVE' ORDER BY transaction_number;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return -1;
    }
    while (*out_count < max && sqlite3_step(stmt) == SQLITE_ROW) {
        load_transaction_row(stmt, &out[*out_count]);
        (*out_count)++;
    }
    sqlite3_finalize(stmt);
    return 0;
}

int store_start_transaction(const char *client_id, const char *process_type,
                            const char *process_data, const char *external_tx_id,
                            tse_transaction_t *out) {
    if (tse_worm_is_active()) {
        char err[256];
        if (tse_worm_start_transaction(client_id, process_type, process_data, out, err,
                                     sizeof(err)) != 0) {
            fprintf(stderr, "cloudtse: %s\n", err);
            return -1;
        }
        if (external_tx_id && external_tx_id[0]) {
            strncpy(out->external_transaction_id, external_tx_id,
                    sizeof(out->external_transaction_id) - 1);
        }
        record_transaction_open(out, external_tx_id);
        return 0;
    }
    int64_t tx_num = db_increment_counter("transaction_counter");
    int64_t sig_counter = db_increment_counter("signature_counter");
    char now[64];
    util_now_iso(now, sizeof(now));
    char sig[128];
    if (util_random_base64(sig, sizeof(sig), 32) != 0) {
        return -1;
    }

    const char *sql =
        "INSERT INTO transactions ("
        "transaction_number, client_id, external_transaction_id,"
        "process_type, process_data, state, time_start,"
        "signature_counter, signature_value"
        ") VALUES (?, ?, ?, ?, ?, 'ACTIVE', ?, ?, ?);";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_int64(stmt, 1, tx_num);
    sqlite3_bind_text(stmt, 2, client_id, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, external_tx_id && external_tx_id[0] ? external_tx_id : NULL, -1,
                      SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, process_type ? process_type : "", -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, process_data ? process_data : "", -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 6, now, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 7, sig_counter);
    sqlite3_bind_text(stmt, 8, sig, -1, SQLITE_STATIC);
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return -1;
    }
    sqlite3_finalize(stmt);

    const char *get_sql = "SELECT transaction_number, client_id, external_transaction_id, "
                          "process_type, process_data, state, time_start, time_end, "
                          "signature_counter, signature_value "
                          "FROM transactions WHERE transaction_number = ?;";
    if (sqlite3_prepare_v2(g_db, get_sql, -1, &stmt, NULL) != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_int64(stmt, 1, tx_num);
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        load_transaction_row(stmt, out);
    }
    sqlite3_finalize(stmt);
    return 0;
}

int store_finish_transaction(const char *client_id, int64_t transaction_number,
                             const char *process_type, const char *process_data,
                             tse_transaction_t *out, char *err_code, size_t err_code_len,
                             char *err_msg, size_t err_msg_len) {
    if (tse_worm_is_active()) {
        int rc = tse_worm_finish_transaction(client_id, transaction_number, process_type,
                                             process_data, out, err_code, err_code_len, err_msg,
                                             err_msg_len);
        if (rc == 0) {
            record_transaction_finished(transaction_number);
        }
        return rc;
    }
    (void)client_id;
    const char *get_sql = "SELECT transaction_number, client_id, external_transaction_id, "
                          "process_type, process_data, state, time_start, time_end, "
                          "signature_counter, signature_value "
                          "FROM transactions WHERE transaction_number = ?;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(g_db, get_sql, -1, &stmt, NULL) != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_int64(stmt, 1, transaction_number);
    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        strncpy(err_code, "ErrorNoTransaction", err_code_len);
        strncpy(err_msg, "No open transaction for this number", err_msg_len);
        return -1;
    }
    tse_transaction_t existing;
    load_transaction_row(stmt, &existing);
    sqlite3_finalize(stmt);

    if (strcmp(existing.state, "ACTIVE") != 0) {
        strncpy(err_code, "ErrorNoTransaction", err_code_len);
        strncpy(err_msg, "No open transaction for this number", err_msg_len);
        return -1;
    }

    int64_t sig_counter = db_increment_counter("signature_counter");
    char now[64];
    util_now_iso(now, sizeof(now));
    char sig[128];
    if (util_random_base64(sig, sizeof(sig), 32) != 0) {
        return -1;
    }

    const char *final_pt = (process_type && process_type[0]) ? process_type : existing.process_type;
    const char *final_pd = (process_data && process_data[0]) ? process_data : existing.process_data;

    const char *upd_sql =
        "UPDATE transactions SET process_type = ?, process_data = ?, state = 'FINISHED', "
        "time_end = ?, signature_counter = ?, signature_value = ? "
        "WHERE transaction_number = ?;";
    if (sqlite3_prepare_v2(g_db, upd_sql, -1, &stmt, NULL) != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_text(stmt, 1, final_pt, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, final_pd, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, now, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 4, sig_counter);
    sqlite3_bind_text(stmt, 5, sig, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 6, transaction_number);
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return -1;
    }
    sqlite3_finalize(stmt);

    if (sqlite3_prepare_v2(g_db, get_sql, -1, &stmt, NULL) != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_int64(stmt, 1, transaction_number);
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        load_transaction_row(stmt, out);
    }
    sqlite3_finalize(stmt);
    return 0;
}

void store_info(tse_info_t *info) {
    memset(info, 0, sizeof(*info));
    if (tse_worm_is_active()) {
        tse_worm_fill_info(info);
        util_strlcpy(info->fcc_version, g_config.fcc_version, sizeof(info->fcc_version));
        util_strlcpy(info->db_path, g_config.tse_device, sizeof(info->db_path));
        info->initialized = true;
        if (g_created_at[0]) {
            util_strlcpy(info->created_at, g_created_at, sizeof(info->created_at));
        } else {
            db_get_setting("created_at", info->created_at, sizeof(info->created_at));
        }
        return;
    }
    char buf[128];
    db_get_setting("tse_serial", buf, sizeof(buf));
    store_normalize_serial(buf, info->serial_number, sizeof(info->serial_number));
    db_get_setting("signature_counter", buf, sizeof(buf));
    info->signature_counter = atoll(buf);
    db_get_setting("transaction_counter", buf, sizeof(buf));
    info->transaction_counter = atoll(buf);
    if (g_created_at[0]) {
        util_strlcpy(info->created_at, g_created_at, sizeof(info->created_at));
    } else {
        db_get_setting("created_at", info->created_at, sizeof(info->created_at));
    }
    util_strlcpy(info->fcc_version, g_config.fcc_version, sizeof(info->fcc_version));
    util_strlcpy(info->db_path, g_config.db_path, sizeof(info->db_path));
    info->initialized = true;

    const char *sql = "SELECT COUNT(*) FROM clients;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            info->registered_clients = sqlite3_column_int64(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }
    /* Simulator has no real hardware limits; these match the values printed
     * in the swissbit dev-kit docs for a fresh TSE and are only used when
     * not running against real hardware (see tse_worm_fill_info for the
     * real values). */
    info->max_registered_clients = 100;
    info->max_started_transactions = 500;
}
