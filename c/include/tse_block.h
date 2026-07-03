#ifndef CLOUDTSE_TSE_BLOCK_H
#define CLOUDTSE_TSE_BLOCK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TSE_BLOCK_SIZE 512
#define TSE_OFFSET_TABLE_LBA 8

typedef struct {
    int fd;
    char device[256];
    uint32_t lba_info;
    uint32_t lba_comm;
    uint32_t lba_store;
    bool offsets_valid;
} tse_block_t;

int tse_block_open(tse_block_t *blk, const char *device);
void tse_block_close(tse_block_t *blk);
int tse_block_load_offsets(tse_block_t *blk);
int tse_block_read_lba(const tse_block_t *blk, uint64_t lba, void *buf, size_t len);
int tse_block_write_lba(const tse_block_t *blk, uint64_t lba, const void *buf, size_t len);
int tse_block_read_info(const tse_block_t *blk, uint8_t buf[TSE_BLOCK_SIZE]);
int tse_block_read_comm(const tse_block_t *blk, uint8_t buf[TSE_BLOCK_SIZE]);
int tse_block_write_comm(const tse_block_t *blk, const uint8_t buf[TSE_BLOCK_SIZE]);
int tse_block_read_store(const tse_block_t *blk, uint64_t offset, void *buf, size_t len);
int tse_block_write_store(const tse_block_t *blk, uint64_t offset, const void *buf, size_t len);
int tse_block_probe(const char *device, char *err, size_t errlen);

#endif
