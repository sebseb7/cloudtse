#include "tse_worker.h"
#include "log.h"

#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>

/* ── per-job descriptor (stack-allocated by the caller) ────────────────── */

typedef struct {
    tse_worker_fn_t fn;
    void           *arg;
    bool            done;
    pthread_mutex_t mu;
    pthread_cond_t  cond;
} tse_job_t;

/* ── single-slot queue ─────────────────────────────────────────────────── */
/*
 * The HTTP server is single-threaded today, so at most one job is in flight
 * at a time.  The "wait for slot" logic in tse_worker_run is still present so
 * this remains correct if additional threads are added later.
 */

static pthread_mutex_t s_mu   = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  s_cond = PTHREAD_COND_INITIALIZER;
static tse_job_t      *s_pending = NULL;
static bool            s_running = false;
static pthread_t       s_thread;

/* ── worker thread ─────────────────────────────────────────────────────── */

static void *worker_thread(void *unused) {
    (void)unused;

    pthread_mutex_lock(&s_mu);
    while (s_running || s_pending) {
        /* Sleep until a job arrives or shutdown is requested. */
        while (s_running && !s_pending) {
            pthread_cond_wait(&s_cond, &s_mu);
        }
        if (!s_pending) {
            break; /* shutdown with empty queue */
        }

        tse_job_t *job = s_pending;
        s_pending = NULL;
        /* Signal tse_worker_run callers that the slot is free again. */
        pthread_cond_broadcast(&s_cond);
        pthread_mutex_unlock(&s_mu);

        /* Execute the blocking WORM operation outside the queue lock. */
        job->fn(job->arg);

        /* Wake the caller that posted this job. */
        pthread_mutex_lock(&job->mu);
        job->done = true;
        pthread_cond_signal(&job->cond);
        pthread_mutex_unlock(&job->mu);

        pthread_mutex_lock(&s_mu);
    }
    pthread_mutex_unlock(&s_mu);

    return NULL;
}

/* ── public API ────────────────────────────────────────────────────────── */

int tse_worker_init(void) {
    pthread_mutex_lock(&s_mu);
    s_running = true;
    s_pending = NULL;
    pthread_mutex_unlock(&s_mu);

    int rc = pthread_create(&s_thread, NULL, worker_thread, NULL);
    if (rc != 0) {
        log_error("tse_worker: pthread_create failed: %d", rc);
        s_running = false;
    }
    return rc;
}

void tse_worker_shutdown(void) {
    pthread_mutex_lock(&s_mu);
    s_running = false;
    pthread_cond_signal(&s_cond);
    pthread_mutex_unlock(&s_mu);

    pthread_join(s_thread, NULL);
}

int tse_worker_run(tse_worker_fn_t fn, void *arg) {
    tse_job_t job;
    job.fn   = fn;
    job.arg  = arg;
    job.done = false;
    pthread_mutex_init(&job.mu,   NULL);
    pthread_cond_init(&job.cond,  NULL);

    pthread_mutex_lock(&s_mu);
    if (!s_running) {
        pthread_mutex_unlock(&s_mu);
        pthread_mutex_destroy(&job.mu);
        pthread_cond_destroy(&job.cond);
        return -1;
    }
    /* Wait for any previous job to be picked up (future-proof). */
    while (s_pending) {
        pthread_cond_wait(&s_cond, &s_mu);
    }
    s_pending = &job;
    pthread_cond_signal(&s_cond);
    pthread_mutex_unlock(&s_mu);

    /* Block until the worker signals completion. */
    pthread_mutex_lock(&job.mu);
    while (!job.done) {
        pthread_cond_wait(&job.cond, &job.mu);
    }
    pthread_mutex_unlock(&job.mu);

    pthread_mutex_destroy(&job.mu);
    pthread_cond_destroy(&job.cond);
    return 0;
}
