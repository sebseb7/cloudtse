#include "tse_block.h"
#include "log.h"
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int read_exact(int fd, void *buf, size_t len, off_t offset) {
    uint8_t *p = buf;
    size_t remaining = len;
    while (remaining > 0) {
        ssize_t n = pread(fd, p, remaining, offset);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (n == 0) {
            return -1;
        }
        p += (size_t)n;
        offset += (off_t)n;
        remaining -= (size_t)n;
    }
    return 0;
}

static int write_exact(int fd, const void *buf, size_t len, off_t offset) {
    const uint8_t *p = buf;
    size_t remaining = len;
    while (remaining > 0) {
        ssize_t n = pwrite(fd, p, remaining, offset);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (n == 0) {
            return -1;
        }
        p += (size_t)n;
        offset += (off_t)n;
        remaining -= (size_t)n;
    }
    return 0;
}

int tse_block_open(tse_block_t *blk, const char *device) {
    memset(blk, 0, sizeof(*blk));
    blk->fd = -1;
    util_strlcpy(blk->device, device, sizeof(blk->device));

    int fd = open(device, O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        return -1;
    }
    blk->fd = fd;
    return tse_block_load_offsets(blk);
}

void tse_block_close(tse_block_t *blk) {
    if (blk->fd >= 0) {
        close(blk->fd);
        blk->fd = -1;
    }
    blk->offsets_valid = false;
}

int tse_block_load_offsets(tse_block_t *blk) {
    uint8_t sector[TSE_BLOCK_SIZE];
    if (tse_block_read_lba(blk, TSE_OFFSET_TABLE_LBA, sector, sizeof(sector)) != 0) {
        blk->offsets_valid = false;
        return -1;
    }
    blk->lba_info = ((uint32_t)sector[0] << 24) | ((uint32_t)sector[1] << 16) |
                    ((uint32_t)sector[2] << 8) | (uint32_t)sector[3];
    blk->lba_comm = ((uint32_t)sector[4] << 24) | ((uint32_t)sector[5] << 16) |
                    ((uint32_t)sector[6] << 8) | (uint32_t)sector[7];
    blk->lba_store = ((uint32_t)sector[8] << 24) | ((uint32_t)sector[9] << 16) |
                     ((uint32_t)sector[10] << 8) | (uint32_t)sector[11];
    if (blk->lba_info == 0 || blk->lba_comm == 0 || blk->lba_store == 0) {
        blk->offsets_valid = false;
        return -1;
    }
    blk->offsets_valid = true;
    return 0;
}

static const char *region_for_lba(const tse_block_t *blk, uint64_t lba, size_t len) {
    (void)len;
    if (lba == TSE_OFFSET_TABLE_LBA) {
        return "offset-table";
    }
    if (blk->offsets_valid) {
        if (lba == blk->lba_info) {
            return "info";
        }
        if (lba == blk->lba_comm) {
            return "comm";
        }
        if (lba >= blk->lba_store) {
            return "store";
        }
    }
    return "unknown";
}

int tse_block_read_lba(const tse_block_t *blk, uint64_t lba, void *buf, size_t len) {
    if (blk->fd < 0 || len == 0) {
        return -1;
    }
    if (len % TSE_BLOCK_SIZE != 0) {
        return -1;
    }
    double t0 = util_monotonic_ms();
    int rc = read_exact(blk->fd, buf, len, (off_t)(lba * TSE_BLOCK_SIZE));
    double elapsed_ms = util_monotonic_ms() - t0;
    log_debug("TSE HW READ  device=%s region=%-12s lba=%llu len=%zu -> %s (%.3f ms)", blk->device,
              region_for_lba(blk, lba, len), (unsigned long long)lba, len,
              rc == 0 ? "ok" : "FAILED", elapsed_ms);
    return rc;
}

int tse_block_write_lba(const tse_block_t *blk, uint64_t lba, const void *buf, size_t len) {
    if (blk->fd < 0 || len == 0) {
        return -1;
    }
    if (len % TSE_BLOCK_SIZE != 0) {
        return -1;
    }
    double t0 = util_monotonic_ms();
    int rc = write_exact(blk->fd, buf, len, (off_t)(lba * TSE_BLOCK_SIZE));
    double elapsed_ms = util_monotonic_ms() - t0;
    log_debug("TSE HW WRITE device=%s region=%-12s lba=%llu len=%zu -> %s (%.3f ms)", blk->device,
              region_for_lba(blk, lba, len), (unsigned long long)lba, len,
              rc == 0 ? "ok" : "FAILED", elapsed_ms);
    return rc;
}

int tse_block_read_info(const tse_block_t *blk, uint8_t buf[TSE_BLOCK_SIZE]) {
    if (!blk->offsets_valid) {
        return -1;
    }
    return tse_block_read_lba(blk, blk->lba_info, buf, TSE_BLOCK_SIZE);
}

int tse_block_read_comm(const tse_block_t *blk, uint8_t buf[TSE_BLOCK_SIZE]) {
    if (!blk->offsets_valid) {
        return -1;
    }
    return tse_block_read_lba(blk, blk->lba_comm, buf, TSE_BLOCK_SIZE);
}

int tse_block_write_comm(const tse_block_t *blk, const uint8_t buf[TSE_BLOCK_SIZE]) {
    if (!blk->offsets_valid) {
        return -1;
    }
    return tse_block_write_lba(blk, blk->lba_comm, buf, TSE_BLOCK_SIZE);
}

int tse_block_read_store(const tse_block_t *blk, uint64_t offset, void *buf, size_t len) {
    if (!blk->offsets_valid) {
        return -1;
    }
    if (len == 0) {
        return 0;
    }
    return tse_block_read_lba(blk, (uint64_t)blk->lba_store + offset, buf, len);
}

int tse_block_write_store(const tse_block_t *blk, uint64_t offset, const void *buf, size_t len) {
    if (!blk->offsets_valid) {
        return -1;
    }
    if (len == 0) {
        return 0;
    }
    return tse_block_write_lba(blk, (uint64_t)blk->lba_store + offset, buf, len);
}

int tse_block_probe(const char *device, char *err, size_t errlen) {
    tse_block_t blk;
    if (tse_block_open(&blk, device) != 0) {
        snprintf(err, errlen, "cannot open or read offset table from %s: %s", device,
                 strerror(errno));
        return -1;
    }

    uint8_t info[TSE_BLOCK_SIZE];
    if (tse_block_read_info(&blk, info) != 0) {
        tse_block_close(&blk);
        snprintf(err, errlen, "cannot read TSE info sector from %s", device);
        return -1;
    }
    if (memcmp(info, "GMISRLS", 7) != 0) {
        tse_block_close(&blk);
        snprintf(err, errlen, "device %s does not look like a Swissbit TSE (missing GMISRLS)",
                 device);
        return -1;
    }

    tse_block_close(&blk);
    if (errlen > 0) {
        err[0] = '\0';
    }
    return 0;
}
