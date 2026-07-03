#include "tse_block.h"

#include <stdint.h>

static tse_block_t *g_rw_block;

void tse_worm_director_set_block(tse_block_t *blk) {
    g_rw_block = blk;
}

int SwigDirector_WormTSEReaderWriter_readInfo(void *self, unsigned char *buf) {
    (void)self;
    if (!g_rw_block || !buf) {
        return 1;
    }
    return tse_block_read_info(g_rw_block, buf) == 0 ? 0 : 1;
}

int SwigDirector_WormTSEReaderWriter_readComm(void *self, unsigned char *buf) {
    (void)self;
    if (!g_rw_block || !buf) {
        return 1;
    }
    return tse_block_read_comm(g_rw_block, buf) == 0 ? 0 : 1;
}

int SwigDirector_WormTSEReaderWriter_writeComm(void *self, const unsigned char *buf) {
    (void)self;
    if (!g_rw_block || !buf) {
        return 1;
    }
    return tse_block_write_comm(g_rw_block, (const uint8_t *)buf) == 0 ? 0 : 1;
}

int SwigDirector_WormTSEReaderWriter_readStore(void *self, unsigned long long offset,
                                               unsigned char *buf) {
    (void)self;
    if (!g_rw_block || !buf) {
        return 1;
    }
    return tse_block_read_store(g_rw_block, offset, buf, 512) == 0 ? 0 : 1;
}

int SwigDirector_WormTSEReaderWriter_writeStore(void *self, unsigned long long offset,
                                                const unsigned char *buf) {
    (void)self;
    if (!g_rw_block || !buf) {
        return 1;
    }
    return tse_block_write_store(g_rw_block, offset, buf, 512) == 0 ? 0 : 1;
}

int WormLegacy_readInfo(void *self, unsigned char *buf) {
    return SwigDirector_WormTSEReaderWriter_readInfo(self, buf);
}

int WormLegacy_readComm(void *self, unsigned char *buf) {
    return SwigDirector_WormTSEReaderWriter_readComm(self, buf);
}

int WormLegacy_writeComm(void *self, const unsigned char *buf) {
    return SwigDirector_WormTSEReaderWriter_writeComm(self, buf);
}

int WormLegacy_readStore(void *self, unsigned long long offset, unsigned char *buf) {
    return SwigDirector_WormTSEReaderWriter_readStore(self, offset, buf);
}

int WormLegacy_writeStore(void *self, unsigned long long offset, const unsigned char *buf) {
    return SwigDirector_WormTSEReaderWriter_writeStore(self, offset, buf);
}

int WormLegacy_openKeepAlive(void *ctx) {
    (void)ctx;
    return 0;
}

int WormLegacy_closeKeepAlive(void *ctx) {
    (void)ctx;
    return 0;
}

int WormLegacy_readKeepAlive(void *ctx, unsigned char *buf) {
    (void)ctx;
    (void)buf;
    return 1;
}
