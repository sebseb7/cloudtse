#ifndef CLOUDTSE_DB_H
#define CLOUDTSE_DB_H

#include <stddef.h>
#include <stdint.h>

typedef struct sqlite3 sqlite3;

extern sqlite3 *g_db;

int db_open(const char *path);
void db_close(void);
int db_init_schema(void);

char *db_get_setting(const char *key, char *buf, size_t buflen);
int db_set_setting(const char *key, const char *value);
int64_t db_increment_counter(const char *key);

int db_save_oauth_token(const char *token, const char *client_serial, int expires_in_seconds);
int db_load_oauth_token(const char *token, char *client_serial, size_t serial_len);

#endif
