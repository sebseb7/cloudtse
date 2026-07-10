#include "http.h"

#include "config.h"
#include "handlers.h"
#include "util.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#define HTTP_CLIENT_TIMEOUT_SEC 30

static volatile sig_atomic_t *s_running = NULL;
static int s_listen_fd = -1;

static int select_wait(int fd, int write_fd, int timeout_ms) {
    fd_set rfds;
    fd_set wfds;
    FD_ZERO(&rfds);
    FD_ZERO(&wfds);
    if (write_fd) {
        FD_SET(fd, &wfds);
    } else {
        FD_SET(fd, &rfds);
    }

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (suseconds_t)(timeout_ms % 1000) * 1000;

    return select(fd + 1, write_fd ? NULL : &rfds, write_fd ? &wfds : NULL, NULL, &tv);
}

static void configure_client_socket(int fd) {
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
}

int http_write_all(int fd, const void *data, size_t len) {
    const char *p = data;
    size_t left = len;

    while (left > 0) {
        if (s_running && !*s_running) {
            return -1;
        }
        if (select_wait(fd, 1, 10000) <= 0) {
            return -1;
        }
        ssize_t n = send(fd, p, left, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        p += n;
        left -= (size_t)n;
    }
    return 0;
}

static void drain_client(int fd) {
    char discard[512];
    struct timeval tv = {0, 250000};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    for (;;) {
        ssize_t n = read(fd, discard, sizeof(discard));
        if (n <= 0) {
            break;
        }
    }
}

static void close_client(int fd) {
    shutdown(fd, SHUT_WR);
    drain_client(fd);
    close(fd);
}

static const char *find_header_end(const char *buf, size_t total) {
    for (size_t i = 0; i + 3 < total; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n') {
            return buf + i;
        }
    }
    return NULL;
}

static int header_has_chunked(const char *buf, const char *hdr_end) {
    for (const char *p = buf; p < hdr_end; p++) {
        if (strncasecmp(p, "Transfer-Encoding:", 18) == 0) {
            const char *v = p + 18;
            while (*v == ' ') {
                v++;
            }
            if (strncasecmp(v, "chunked", 7) == 0) {
                return 1;
            }
        }
    }
    return 0;
}

static int chunked_body_complete(const char *buf, size_t total, size_t hdr_len) {
    const char *body = buf + hdr_len;
    size_t body_len = total - hdr_len;
    if (body_len < 5) {
        return 0;
    }
    for (size_t i = 0; i + 4 < body_len; i++) {
        if (body[i] == '0' && body[i + 1] == '\r' && body[i + 2] == '\n' &&
            body[i + 3] == '\r' && body[i + 4] == '\n') {
            return 1;
        }
    }
    return 0;
}

static int request_complete(const char *buf, size_t total, size_t *msg_len) {
    const char *hdr_end = find_header_end(buf, total);
    if (!hdr_end) {
        return 0;
    }

    size_t hdr_len = (size_t)(hdr_end - buf) + 4;
    size_t content_len = 0;
    int has_cl = 0;

    for (const char *p = buf; p < hdr_end; p++) {
        if (strncasecmp(p, "Content-Length:", 15) == 0) {
            const char *v = p + 15;
            while (*v == ' ') {
                v++;
            }
            content_len = (size_t)atoi(v);
            has_cl = 1;
            break;
        }
    }

    if (!has_cl && header_has_chunked(buf, hdr_end)) {
        if (!chunked_body_complete(buf, total, hdr_len)) {
            return 0;
        }
        *msg_len = total;
        return 1;
    }

    if (!has_cl) {
        *msg_len = hdr_len;
        return total >= hdr_len;
    }

    *msg_len = hdr_len + content_len;
    return total >= *msg_len;
}

static int fill_buffer(int client_fd, char *buf, size_t *total, size_t buflen) {
    while (*total < buflen - 1) {
        if (s_running && !*s_running) {
            return -1;
        }
        if (select_wait(client_fd, 0, HTTP_CLIENT_TIMEOUT_SEC * 1000) <= 0) {
            return -1;
        }

        ssize_t n = read(client_fd, buf + *total, buflen - 1 - *total);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (n == 0) {
            return (*total > 0) ? 0 : -1;
        }

        *total += (size_t)n;
        buf[*total] = '\0';
        return 0;
    }
    return -1;
}

static int should_keep_alive(const http_request_t *req) {
    const char *conn = http_get_header(req, "Connection");
    if (conn) {
        if (strcasecmp(conn, "close") == 0) {
            return 0;
        }
        if (strcasecmp(conn, "keep-alive") == 0) {
            return 1;
        }
    }
    return req->http_minor >= 1;
}

static void strtolower(char *s) {
    for (; *s; s++) {
        *s = (char)tolower((unsigned char)*s);
    }
}

const char *http_get_header(const http_request_t *req, const char *name) {
    for (int i = 0; i < req->header_count; i++) {
        if (strcasecmp(req->headers[i].name, name) == 0) {
            return req->headers[i].value;
        }
    }
    return NULL;
}

void http_normalize_path(const char *url_path, char *out, size_t outlen) {
    const char *path = url_path ? url_path : "/";
    const char *q = strchr(path, '?');
    size_t len = q ? (size_t)(q - path) : strlen(path);
    if (len >= outlen) {
        len = outlen - 1;
    }
    memcpy(out, path, len);
    out[len] = '\0';
    while (len > 1 && out[len - 1] == '/') {
        out[--len] = '\0';
    }
    if (out[0] == '\0') {
        strncpy(out, "/", outlen - 1);
    }
}

static int header_line(const char *line, http_header_t *hdr) {
    const char *colon = strchr(line, ':');
    if (!colon) {
        return -1;
    }
    size_t nlen = (size_t)(colon - line);
    if (nlen >= HTTP_HEADER_NAME_LEN) {
        nlen = HTTP_HEADER_NAME_LEN - 1;
    }
    memcpy(hdr->name, line, nlen);
    hdr->name[nlen] = '\0';
    const char *val = colon + 1;
    while (*val == ' ') {
        val++;
    }
    strncpy(hdr->value, val, HTTP_HEADER_VALUE_LEN - 1);
    hdr->value[HTTP_HEADER_VALUE_LEN - 1] = '\0';
    return 0;
}

static size_t decode_chunked_body(const char *raw, size_t raw_len, size_t body_off, char *out,
                                  size_t outlen) {
    size_t out_pos = 0;
    size_t pos = body_off;

    while (pos < raw_len) {
        size_t line_end = pos;
        while (line_end + 1 < raw_len && !(raw[line_end] == '\r' && raw[line_end + 1] == '\n')) {
            line_end++;
        }
        if (line_end + 1 >= raw_len) {
            break;
        }

        char size_buf[16];
        size_t size_len = line_end - pos;
        if (size_len == 0 || size_len >= sizeof(size_buf)) {
            break;
        }
        memcpy(size_buf, raw + pos, size_len);
        size_buf[size_len] = '\0';

        size_t chunk_size = (size_t)strtoul(size_buf, NULL, 16);
        pos = line_end + 2;
        if (chunk_size == 0) {
            break;
        }
        if (pos + chunk_size > raw_len) {
            break;
        }
        if (out_pos + chunk_size >= outlen) {
            break;
        }
        memcpy(out + out_pos, raw + pos, chunk_size);
        out_pos += chunk_size;
        pos += chunk_size;
        if (pos + 1 < raw_len && raw[pos] == '\r' && raw[pos + 1] == '\n') {
            pos += 2;
        }
    }

    if (out_pos < outlen) {
        out[out_pos] = '\0';
    }
    return out_pos;
}

int http_parse_request(const char *raw, size_t raw_len, http_request_t *req) {
    memset(req, 0, sizeof(*req));
    const char *hdr_end = find_header_end(raw, raw_len);
    if (!hdr_end) {
        return -1;
    }

    char first[1024];
    size_t first_len = (size_t)(hdr_end - raw);
    if (first_len >= sizeof(first)) {
        first_len = sizeof(first) - 1;
    }
    memcpy(first, raw, first_len);
    first[first_len] = '\0';

    char *save = NULL;
    char *line = strtok_r(first, "\r\n", &save);
    if (!line) {
        return -1;
    }
    char method[16], path[HTTP_MAX_PATH], version[16];
    if (sscanf(line, "%15s %511s %15s", method, path, version) < 2) {
        return -1;
    }
    util_strlcpy(req->method, method, sizeof(req->method));
    util_strlcpy(req->path, path, sizeof(req->path));
    req->http_minor = 0;
    if (sscanf(version, "HTTP/%*d.%d", &req->http_minor) != 1) {
        req->http_minor = 1;
    }

    while ((line = strtok_r(NULL, "\r\n", &save)) != NULL) {
        if (req->header_count >= HTTP_MAX_HEADERS) {
            break;
        }
        if (header_line(line, &req->headers[req->header_count]) == 0) {
            req->header_count++;
        }
    }

    size_t body_off = (size_t)(hdr_end - raw) + 4;
    if (body_off < raw_len) {
        size_t blen;
        if (header_has_chunked(raw, hdr_end)) {
            blen = decode_chunked_body(raw, raw_len, body_off, req->body, sizeof(req->body));
        } else {
            blen = raw_len - body_off;
            if (blen >= HTTP_MAX_BODY) {
                blen = HTTP_MAX_BODY - 1;
            }
            memcpy(req->body, raw + body_off, blen);
            req->body[blen] = '\0';
        }
        req->body_len = blen;
    }

    const char *cl = http_get_header(req, "Content-Length");
    if (cl) {
        size_t expected = (size_t)atoi(cl);
        if (expected > req->body_len && expected < HTTP_MAX_BODY) {
            /* body may be incomplete in buffer; best effort for small requests */
        }
    }
    return 0;
}

void http_parse_body(const char *raw, size_t raw_len, const char *content_type, char *json_out,
                     size_t json_outlen) {
    (void)raw_len;
    if (!raw || !raw[0]) {
        json_out[0] = '\0';
        return;
    }
    char ct[128];
    strncpy(ct, content_type ? content_type : "", sizeof(ct) - 1);
    strtolower(ct);

    if (strstr(ct, "application/json")) {
        strncpy(json_out, raw, json_outlen - 1);
        json_out[json_outlen - 1] = '\0';
        return;
    }
    if (strstr(ct, "application/x-www-form-urlencoded")) {
        json_out[0] = '{';
        json_out[1] = '\0';
        return;
    }
    strncpy(json_out, raw, json_outlen - 1);
    json_out[json_outlen - 1] = '\0';
}

int http_parse_basic_auth(const http_request_t *req, char *client_id, size_t id_len,
                          char *client_secret, size_t secret_len) {
    const char *auth = http_get_header(req, "Authorization");
    if (!auth || strncasecmp(auth, "Basic ", 6) != 0) {
        return -1;
    }
    char decoded[512];
    if (util_base64_decode(auth + 6, decoded, sizeof(decoded)) < 0) {
        return -1;
    }
    char *colon = strchr(decoded, ':');
    if (!colon) {
        strncpy(client_id, decoded, id_len - 1);
        client_id[id_len - 1] = '\0';
        client_secret[0] = '\0';
        return 0;
    }
    *colon = '\0';
    strncpy(client_id, decoded, id_len - 1);
    client_id[id_len - 1] = '\0';
    strncpy(client_secret, colon + 1, secret_len - 1);
    client_secret[secret_len - 1] = '\0';
    return 0;
}

int http_parse_bearer(const http_request_t *req, char *token, size_t token_len) {
    const char *auth = http_get_header(req, "Authorization");
    if (!auth || strncasecmp(auth, "Bearer ", 7) != 0) {
        return -1;
    }
    const char *t = auth + 7;
    while (*t == ' ') {
        t++;
    }
    strncpy(token, t, token_len - 1);
    token[token_len - 1] = '\0';
    return token[0] ? 0 : -1;
}

void http_send_response(int client_fd, const http_response_t *res, int keep_alive) {
    char header[1024];
    char combined[HTTP_MAX_BODY + 2048];
    size_t header_len;
    size_t total_len;
    const char *connection = keep_alive ? "keep-alive" : "close";

    if (res->no_body) {
        header_len = (size_t)snprintf(header, sizeof(header),
                                      "HTTP/1.1 %d No Content\r\n"
                                      "Access-Control-Allow-Origin: *\r\n"
                                      "Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS\r\n"
                                      "Access-Control-Allow-Headers: Content-Type, Authorization\r\n"
                                      "Connection: %s\r\n\r\n",
                                      res->status, connection);
        http_write_all(client_fd, header, header_len);
        return;
    }

    if (res->stream) {
        const char *ct = res->stream_content_type[0] ? res->stream_content_type
                                                         : "text/plain; charset=utf-8";
        header_len = (size_t)snprintf(
            header, sizeof(header),
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: %s\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS\r\n"
            "Access-Control-Allow-Headers: Content-Type, Authorization\r\n"
            "Connection: close\r\n\r\n",
            ct);
        http_write_all(client_fd, header, header_len);
        if (res->stream_fn) {
            res->stream_fn(client_fd, res->stream_ctx);
        }
        return;
    }

    const char *status_text = "OK";
    if (res->status == 400) {
        status_text = "Bad Request";
    } else if (res->status == 401) {
        status_text = "Unauthorized";
    } else if (res->status == 404) {
        status_text = "Not Found";
    } else if (res->status == 500) {
        status_text = "Internal Server Error";
    }

    header_len = (size_t)snprintf(header, sizeof(header),
                                  "HTTP/1.1 %d %s\r\n"
                                  "Content-Type: application/json; charset=utf-8\r\n"
                                  "Content-Length: %zu\r\n"
                                  "Access-Control-Allow-Origin: *\r\n"
                                  "Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS\r\n"
                                  "Access-Control-Allow-Headers: Content-Type, Authorization\r\n"
                                  "Connection: %s\r\n\r\n",
                                  res->status, status_text, res->body_len, connection);
    total_len = header_len + res->body_len;
    if (total_len <= sizeof(combined)) {
        memcpy(combined, header, header_len);
        if (res->body_len > 0) {
            memcpy(combined + header_len, res->body, res->body_len);
        }
        http_write_all(client_fd, combined, total_len);
        return;
    }

    http_write_all(client_fd, header, header_len);
    if (res->body_len > 0) {
        http_write_all(client_fd, res->body, res->body_len);
    }
}

void http_send_json(int client_fd, int status, const char *json) {
    http_response_t res = {0};
    res.status = status;
    res.body_len = strlen(json);
    strncpy(res.body, json, sizeof(res.body) - 1);
    http_send_response(client_fd, &res, 0);
}

static void handle_client(int client_fd) {
    char buf[HTTP_MAX_BODY + 16384];
    size_t total = 0;
    int keep_alive = 1;

    while (keep_alive) {
        size_t msg_len = 0;

        while (!request_complete(buf, total, &msg_len)) {
            if (total >= sizeof(buf) - 1) {
                close_client(client_fd);
                return;
            }
            if (fill_buffer(client_fd, buf, &total, sizeof(buf)) != 0) {
                close_client(client_fd);
                return;
            }
        }

        char req_raw[HTTP_MAX_BODY + 8192];
        if (msg_len >= sizeof(req_raw)) {
            msg_len = sizeof(req_raw) - 1;
        }
        memcpy(req_raw, buf, msg_len);
        if (total > msg_len) {
            memmove(buf, buf + msg_len, total - msg_len);
        }
        total -= msg_len;

        http_request_t req;
        if (http_parse_request(req_raw, msg_len, &req) != 0) {
            http_send_json(client_fd, 400,
                           "{\"error\":\"bad_request\",\"message\":\"Invalid HTTP request\"}");
            close_client(client_fd);
            return;
        }

        const char *ct = http_get_header(&req, "Content-Type");
        char parsed_body[HTTP_MAX_BODY];
        http_parse_body(req.body, req.body_len, ct ? ct : "", parsed_body, sizeof(parsed_body));
        if (parsed_body[0]) {
            util_strlcpy(req.body, parsed_body, sizeof(req.body));
            req.body_len = strlen(req.body);
        }

        http_response_t res;
        handlers_route(&req, &res);
        keep_alive = should_keep_alive(&req);
        http_send_response(client_fd, &res, keep_alive);
    }

    close_client(client_fd);
}

void http_shutdown(void) {
    if (s_listen_fd >= 0) {
        close(s_listen_fd);
        s_listen_fd = -1;
    }
}

int http_serve(const char *host, uint16_t port, volatile sig_atomic_t *running) {
    s_running = running;

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        return -1;
    }

    s_listen_fd = server_fd;

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
        addr.sin_addr.s_addr = INADDR_ANY;
    }

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(server_fd);
        s_listen_fd = -1;
        return -1;
    }

    if (listen(server_fd, 16) < 0) {
        perror("listen");
        close(server_fd);
        s_listen_fd = -1;
        return -1;
    }

    while (s_running && *s_running) {
        if (select_wait(server_fd, 0, HTTP_SELECT_MS) <= 0) {
            if (errno == EINTR) {
                continue;
            }
            if (s_running && !*s_running) {
                break;
            }
            continue;
        }

        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (s_running && !*s_running) {
                break;
            }
            perror("accept");
            break;
        }
        configure_client_socket(client_fd);
        handle_client(client_fd);
    }

    if (s_listen_fd >= 0) {
        close(s_listen_fd);
        s_listen_fd = -1;
    }
    return 0;
}
