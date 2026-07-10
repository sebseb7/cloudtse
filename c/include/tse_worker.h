#ifndef CLOUDTSE_TSE_WORKER_H
#define CLOUDTSE_TSE_WORKER_H

/*
 * tse_worker — serialised execution thread for blocking WORM hardware calls.
 *
 * All tse_worm_* operations that touch the physical block device are routed
 * through this single worker thread so that concurrent HTTP requests cannot
 * interleave at the hardware level.  Non-WORM paths (simulator mode, DB-only
 * reads, OAuth, health) never call tse_worker_run and are unaffected.
 *
 * Usage:
 *   1. Call tse_worker_init() once at startup (after tse_worm_init).
 *   2. From any thread: tse_worker_run(fn, arg) — posts the job and blocks
 *      until the worker thread has executed fn(arg).
 *   3. Call tse_worker_shutdown() once at teardown (before tse_worm_shutdown).
 */

typedef void (*tse_worker_fn_t)(void *arg);

/* Start the worker thread.  Returns 0 on success, errno value on failure. */
int tse_worker_init(void);

/* Drain any pending job, stop the worker thread, and join it. */
void tse_worker_shutdown(void);

/*
 * Post fn(arg) to the worker thread and block until it completes.
 * Safe to call from any thread.
 * Returns 0 on success, -1 if the worker is not running.
 */
int tse_worker_run(tse_worker_fn_t fn, void *arg);

#endif /* CLOUDTSE_TSE_WORKER_H */
