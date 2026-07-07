#include "db.h"
#include "config.h"
#include "log.h"
#include "store.h"
#include "util.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

sqlite3 *g_db = NULL;

static int ensure_parent_dir(const char *path) {
    char buf[512];
    strncpy(buf, path, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    char *slash = strrchr(buf, '/');
    if (!slash) {
        return 0;
    }
    *slash = '\0';
    if (buf[0] == '\0') {
        return 0;
    }
    struct stat st;
    if (stat(buf, &st) == 0) {
        return S_ISDIR(st.st_mode) ? 0 : -1;
    }
    return ensure_parent_dir(buf) == 0 ? mkdir(buf, 0755) : -1;
}

int db_open(const char *path) {
    if (ensure_parent_dir(path) != 0) {
        log_error("Failed to create database directory for %s", path);
        return -1;
    }
    if (sqlite3_open(path, &g_db) != SQLITE_OK) {
        log_error("sqlite3_open: %s", sqlite3_errmsg(g_db));
        return -1;
    }
    sqlite3_exec(g_db, "PRAGMA journal_mode = WAL;", NULL, NULL, NULL);
    sqlite3_exec(g_db, "PRAGMA foreign_keys = ON;", NULL, NULL, NULL);
    return 0;
}

void db_close(void) {
    if (g_db) {
        sqlite3_close(g_db);
        g_db = NULL;
    }
}

int db_init_schema(void) {
    const char *sql =
        "CREATE TABLE IF NOT EXISTS settings ("
        "  key TEXT PRIMARY KEY,"
        "  value TEXT NOT NULL"
        ");"
        "CREATE TABLE IF NOT EXISTS clients ("
        "  serial_number TEXT PRIMARY KEY,"
        "  registered_at TEXT NOT NULL,"
        "  state TEXT NOT NULL DEFAULT 'REGISTERED',"
        "  type_of_system TEXT,"
        "  meta_json TEXT"
        ");"
        "CREATE TABLE IF NOT EXISTS transactions ("
        "  transaction_number INTEGER PRIMARY KEY,"
        "  client_id TEXT NOT NULL,"
        "  external_transaction_id TEXT,"
        "  process_type TEXT NOT NULL DEFAULT '',"
        "  process_data TEXT NOT NULL DEFAULT '',"
        "  state TEXT NOT NULL,"
        "  time_start TEXT NOT NULL,"
        "  time_end TEXT,"
        "  signature_counter INTEGER NOT NULL,"
        "  signature_value TEXT NOT NULL"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_transactions_state ON transactions(state);"
        "CREATE INDEX IF NOT EXISTS idx_transactions_client ON transactions(client_id);"
        "CREATE TABLE IF NOT EXISTS oauth_tokens ("
        "  token TEXT PRIMARY KEY,"
        "  client_serial TEXT NOT NULL,"
        "  issued_at TEXT NOT NULL,"
        "  expires_at TEXT"
        ");";

    char *err = NULL;
    if (sqlite3_exec(g_db, sql, NULL, NULL, &err) != SQLITE_OK) {
        log_error("schema: %s", err);
        sqlite3_free(err);
        return -1;
    }

    char now[64];
    util_now_iso(now, sizeof(now));
    char serial[128];
    store_normalize_serial(g_config.tse_serial, serial, sizeof(serial));

    const char *upsert =
        "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO NOTHING;";
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(g_db, upsert, -1, &stmt, NULL);

    const char *keys[] = {"signature_counter", "transaction_counter", "created_at", "tse_serial"};
    const char *vals[] = {"0", "0", now, serial};
    for (int i = 0; i < 4; i++) {
        sqlite3_bind_text(stmt, 1, keys[i], -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, vals[i], -1, SQLITE_STATIC);
        sqlite3_step(stmt);
        sqlite3_reset(stmt);
    }
    sqlite3_finalize(stmt);

    char stored[128];
    if (db_get_setting("tse_serial", stored, sizeof(stored)) && !util_is_hex_serial(stored)) {
        db_set_setting("tse_serial", serial);
    }

    return 0;
}

char *db_get_setting(const char *key, char *buf, size_t buflen) {
    const char *sql = "SELECT value FROM settings WHERE key = ?;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return NULL;
    }
    sqlite3_bind_text(stmt, 1, key, -1, SQLITE_STATIC);
    char *result = NULL;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *val = (const char *)sqlite3_column_text(stmt, 0);
        if (val) {
            strncpy(buf, val, buflen - 1);
            buf[buflen - 1] = '\0';
            result = buf;
        }
    }
    sqlite3_finalize(stmt);
    return result;
}

int db_set_setting(const char *key, const char *value) {
    const char *sql =
        "INSERT INTO settings (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_text(stmt, 1, key, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, value, -1, SQLITE_STATIC);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? 0 : -1;
}

int64_t db_increment_counter(const char *key) {
    char buf[64];
    int64_t current = 0;
    if (db_get_setting(key, buf, sizeof(buf))) {
        current = atoll(buf);
    }
    int64_t next = current + 1;
    snprintf(buf, sizeof(buf), "%lld", (long long)next);
    db_set_setting(key, buf);
    return next;
}

int db_save_oauth_token(const char *token, const char *client_serial, int expires_in_seconds) {
    char issued[64];
    char expires[64];
    util_now_iso(issued, sizeof(issued));

    time_t now = time(NULL);
    struct tm tm;
    gmtime_r(&now, &tm);
    time_t exp = now + expires_in_seconds;
    gmtime_r(&exp, &tm);
    strftime(expires, sizeof(expires), "%Y-%m-%dT%H:%M:%S.000Z", &tm);

    const char *sql =
        "INSERT OR REPLACE INTO oauth_tokens (token, client_serial, issued_at, expires_at) "
        "VALUES (?, ?, ?, ?);";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_text(stmt, 1, token, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, client_serial ? client_serial : "unknown", -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, issued, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, expires, -1, SQLITE_STATIC);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? 0 : -1;
}

int db_load_oauth_token(const char *token, char *client_serial, size_t serial_len) {
    const char *sql =
        "SELECT client_serial, issued_at, expires_at FROM oauth_tokens WHERE token = ?;";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_text(stmt, 1, token, -1, SQLITE_STATIC);
    int found = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *serial = (const char *)sqlite3_column_text(stmt, 0);
        const char *expires = (const char *)sqlite3_column_text(stmt, 2);
        if (expires && expires[0]) {
            int y, mo, d, h, mi, s;
            if (sscanf(expires, "%d-%d-%dT%d:%d:%d", &y, &mo, &d, &h, &mi, &s) == 6) {
                struct tm tm = {0};
                tm.tm_year = y - 1900;
                tm.tm_mon = mo - 1;
                tm.tm_mday = d;
                tm.tm_hour = h;
                tm.tm_min = mi;
                tm.tm_sec = s;
                time_t exp_t = timegm(&tm);
                if (exp_t < time(NULL)) {
                    sqlite3_finalize(stmt);
                    return -1;
                }
            }
        }
        if (serial) {
            strncpy(client_serial, serial, serial_len - 1);
            client_serial[serial_len - 1] = '\0';
            found = 1;
        }
    }
    sqlite3_finalize(stmt);
    return found ? 0 : -1;
}
