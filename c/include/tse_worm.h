#ifndef CLOUDTSE_TSE_WORM_H
#define CLOUDTSE_TSE_WORM_H

#include "store.h"
#include "tse_block.h"
#include <stdbool.h>

bool tse_worm_is_active(void);
int tse_worm_init(void);
void tse_worm_shutdown(void);

int tse_worm_register_client(const char *client_id);
int tse_worm_start_transaction(const char *client_id, const char *process_type,
                               const char *process_data, tse_transaction_t *out,
                               char *err_msg, size_t err_msg_len);
int tse_worm_finish_transaction(const char *client_id, int64_t transaction_number,
                                const char *process_type, const char *process_data,
                                tse_transaction_t *out, char *err_code, size_t err_code_len,
                                char *err_msg, size_t err_msg_len);
void tse_worm_fill_info(tse_info_t *info);
const char *tse_worm_public_key_hex(void);
const char *tse_worm_public_key_b64(void);
const char *tse_worm_certificate_base64(void);
const char *tse_worm_log_time_format(void);

/*
 * TAR export. worm_export_tar hands the caller successive raw TAR chunks via
 * the callback (each chunk is a multiple of 512 bytes). The callback must
 * return 0 to continue or non-zero to abort the export. The cloud export
 * endpoint Base64-encodes each chunk onto its own line, exactly mirroring the
 * WormExportTarCallback.onNewData contract the POS app already parses.
 */
typedef int (*tse_worm_export_cb)(const unsigned char *chunk, size_t len, void *ctx);

/* Ensures the TSE has passed self-test and has valid time; returns 0 if it is
 * ready to export, non-zero otherwise. Call before streaming a response so any
 * failure can be reported as a normal JSON error instead of after the headers. */
int tse_worm_export_prepare(void);

/* Runs worm_export_tar, invoking cb for each chunk. Returns 0 on success. */
int tse_worm_export_tar(tse_worm_export_cb cb, void *ctx);

void tse_worm_director_set_block(tse_block_t *blk);

int WormLegacy_readInfo(void *ctx, unsigned char *buf);
int WormLegacy_readComm(void *ctx, unsigned char *buf);
int WormLegacy_writeComm(void *ctx, const unsigned char *buf);
int WormLegacy_readStore(void *ctx, unsigned long long offset, unsigned char *buf);
int WormLegacy_writeStore(void *ctx, unsigned long long offset, const unsigned char *buf);
int WormLegacy_openKeepAlive(void *ctx);
int WormLegacy_closeKeepAlive(void *ctx);
int WormLegacy_readKeepAlive(void *ctx, unsigned char *buf);

#endif
