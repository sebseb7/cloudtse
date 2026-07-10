#ifndef CLOUDTSE_HTTP_H
#define CLOUDTSE_HTTP_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <signal.h>

#define HTTP_SELECT_MS 250

#define HTTP_MAX_HEADERS 32
#define HTTP_HEADER_NAME_LEN 64
#define HTTP_HEADER_VALUE_LEN 2048
#define HTTP_MAX_BODY 65536
#define HTTP_MAX_PATH 512

typedef struct {
    char name[HTTP_HEADER_NAME_LEN];
    char value[HTTP_HEADER_VALUE_LEN];
} http_header_t;

typedef struct {
    char method[16];
    char path[HTTP_MAX_PATH];
    char query[512];
    int http_minor;
    http_header_t headers[HTTP_MAX_HEADERS];
    int header_count;
    char body[HTTP_MAX_BODY];
    size_t body_len;
} http_request_t;

/* Streaming response writer: invoked after the headers are sent so the
 * handler can write a body of arbitrary size (e.g. a TAR export) directly
 * to the socket. Must return 0 on success or non-zero on a write error. */
typedef int (*http_stream_fn)(int fd, void *ctx);

typedef struct {
    int status;
    char body[HTTP_MAX_BODY];
    size_t body_len;
    bool no_body;
    /* When set, the body is produced by stream_fn instead of body[].
     * The response is sent with "Connection: close" (no Content-Length). */
    bool stream;
    char stream_content_type[64];
    http_stream_fn stream_fn;
    void *stream_ctx;
} http_response_t;

int http_serve(const char *host, uint16_t port, volatile sig_atomic_t *running);
void http_shutdown(void);
int http_parse_request(const char *raw, size_t raw_len, http_request_t *req);
const char *http_get_header(const http_request_t *req, const char *name);
void http_send_response(int client_fd, const http_response_t *res, int keep_alive);
void http_send_json(int client_fd, int status, const char *json);
int http_write_all(int fd, const void *data, size_t len);
void http_normalize_path(const char *url_path, char *out, size_t outlen);
int http_parse_basic_auth(const http_request_t *req, char *client_id, size_t id_len,
                          char *client_secret, size_t secret_len);
int http_parse_bearer(const http_request_t *req, char *token, size_t token_len);
void http_parse_body(const char *raw, size_t raw_len, const char *content_type,
                     char *json_out, size_t json_outlen);

#endif
