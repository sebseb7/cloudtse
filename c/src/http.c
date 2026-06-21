#include "http.h"

#include "config.h"
#include "handlers.h"
#include "util.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

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

static int write_all(int fd, const void *data, size_t len) {
    const char *p = data;
    size_t left = len;

    while (left > 0) {
        if (s_running && !*s_running) {
            return -1;
        }
        if (select_wait(fd, 1, 10000) <= 0) {
            return -1;
        }
        ssize_t n = write(fd, p, left);
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

static int request_complete(const char *buf, size_t total, size_t *need_total) {
    const char *hdr_end = NULL;
    for (size_t i = 0; i + 3 < total; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n') {
            hdr_end = buf + i;
            break;
        }
    }
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

    if (!has_cl) {
        *need_total = hdr_len;
        return total >= hdr_len;
    }

    *need_total = hdr_len + content_len;
    return total >= *need_total;
}

static int read_request(int client_fd, char *buf, size_t buflen, size_t *total_out) {
    size_t total = 0;
    size_t need = 0;

    while (total < buflen - 1) {
        if (s_running && !*s_running) {
            return -1;
        }
        if (select_wait(client_fd, 0, HTTP_CLIENT_TIMEOUT_SEC * 1000) <= 0) {
            return -1;
        }

        ssize_t n = read(client_fd, buf + total, buflen - 1 - total);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (n == 0) {
            break;
        }

        total += (size_t)n;
        buf[total] = '\0';

        if (request_complete(buf, total, &need)) {
            break;
        }
        if (need > 0 && total >= need) {
            break;
        }
    }

    *total_out = total;
    return total > 0 ? 0 : -1;
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

int http_parse_request(const char *raw, size_t raw_len, http_request_t *req) {
    memset(req, 0, sizeof(*req));
    const char *hdr_end = NULL;
    for (size_t i = 0; i + 3 < raw_len; i++) {
        if (raw[i] == '\r' && raw[i + 1] == '\n' && raw[i + 2] == '\r' && raw[i + 3] == '\n') {
            hdr_end = raw + i;
            break;
        }
    }
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
        size_t blen = raw_len - body_off;
        if (blen >= HTTP_MAX_BODY) {
            blen = HTTP_MAX_BODY - 1;
        }
        memcpy(req->body, raw + body_off, blen);
        req->body[blen] = '\0';
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

void http_send_response(int client_fd, const http_response_t *res) {
    char header[1024];
    if (res->no_body) {
        snprintf(header, sizeof(header),
                 "HTTP/1.1 %d OK\r\n"
                 "Access-Control-Allow-Origin: *\r\n"
                 "Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS\r\n"
                 "Access-Control-Allow-Headers: Content-Type, Authorization\r\n"
                 "Connection: close\r\n\r\n",
                 res->status);
        write_all(client_fd, header, strlen(header));
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

    snprintf(header, sizeof(header),
             "HTTP/1.1 %d %s\r\n"
             "Content-Type: application/json; charset=utf-8\r\n"
             "Content-Length: %zu\r\n"
             "Access-Control-Allow-Origin: *\r\n"
             "Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS\r\n"
             "Access-Control-Allow-Headers: Content-Type, Authorization\r\n"
             "Connection: close\r\n\r\n",
             res->status, status_text, res->body_len);
    write_all(client_fd, header, strlen(header));
    if (res->body_len > 0) {
        write_all(client_fd, res->body, res->body_len);
    }
}

void http_send_json(int client_fd, int status, const char *json) {
  http_response_t res = {0};
  res.status = status;
  res.body_len = strlen(json);
  strncpy(res.body, json, sizeof(res.body) - 1);
  http_send_response(client_fd, &res);
}

static void handle_client(int client_fd) {
    char buf[HTTP_MAX_BODY + 8192];
    size_t total = 0;

    if (read_request(client_fd, buf, sizeof(buf), &total) != 0) {
        close(client_fd);
        return;
    }

    http_request_t req;
    if (http_parse_request(buf, total, &req) != 0) {
        http_send_json(client_fd, 400,
                       "{\"error\":\"bad_request\",\"message\":\"Invalid HTTP request\"}");
        close(client_fd);
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
    http_send_response(client_fd, &res);
    close(client_fd);
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
        handle_client(client_fd);
    }

    if (s_listen_fd >= 0) {
        close(s_listen_fd);
        s_listen_fd = -1;
    }
    return 0;
}
