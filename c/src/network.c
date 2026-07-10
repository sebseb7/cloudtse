#include "network.h"

#include "config.h"
#include "util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

static int select_wait_fd(int fd, int write_fd, int timeout_ms) {
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

static int read_fd(int fd, char *buf, size_t buflen, int timeout_ms) {
    if (select_wait_fd(fd, 0, timeout_ms) <= 0) {
        return -1;
    }
    ssize_t n = read(fd, buf, buflen - 1);
    if (n <= 0) {
        return -1;
    }
    buf[n] = '\0';
    return (int)n;
}

int network_local_ips(char ips[][64], int max_ips) {
    struct ifaddrs *ifaddr = NULL;
    int count = 0;
    if (getifaddrs(&ifaddr) != 0) {
        util_strlcpy(ips[0], "127.0.0.1", 64);
        return 1;
    }
    for (struct ifaddrs *ifa = ifaddr; ifa && count < max_ips; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET) {
            continue;
        }
        if (ifa->ifa_flags & IFF_LOOPBACK) {
            continue;
        }
        struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
        const char *ip = inet_ntoa(sa->sin_addr);
        if (ip) {
            util_strlcpy(ips[count], ip, 64);
            count++;
        }
    }
    freeifaddrs(ifaddr);
    if (count == 0) {
        util_strlcpy(ips[0], "127.0.0.1", 64);
        return 1;
    }
    return count;
}

static int fetch_ip_from_host(const char *host, const char *path, char *out, size_t outlen) {
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    char port[] = "80";
    if (getaddrinfo(host, port, &hints, &res) != 0) {
        return -1;
    }

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) {
        freeaddrinfo(res);
        return -1;
    }

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }

    int rc = connect(fd, res->ai_addr, res->ai_addrlen);
    if (rc < 0 && errno != EINPROGRESS) {
        close(fd);
        freeaddrinfo(res);
        return -1;
    }

    if (select_wait_fd(fd, 1, 3000) <= 0) {
        close(fd);
        freeaddrinfo(res);
        return -1;
    }

    int so_error = 0;
    socklen_t slen = sizeof(so_error);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_error, &slen) != 0 || so_error != 0) {
        close(fd);
        freeaddrinfo(res);
        return -1;
    }

    freeaddrinfo(res);

    char req[256];
    snprintf(req, sizeof(req), "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path,
             host);
    size_t req_len = strlen(req);
    size_t written = 0;
    while (written < req_len) {
        if (select_wait_fd(fd, 1, 3000) <= 0) {
            close(fd);
            return -1;
        }
        ssize_t n = write(fd, req + written, req_len - written);
        if (n < 0) {
            close(fd);
            return -1;
        }
        written += (size_t)n;
    }

    char buf[512];
    if (read_fd(fd, buf, sizeof(buf), 3000) < 0) {
        close(fd);
        return -1;
    }
    close(fd);

    char *body = strstr(buf, "\r\n\r\n");
    if (!body) {
        return -1;
    }
    body += 4;
    while (*body == '\r' || *body == '\n') {
        body++;
    }
    size_t len = strcspn(body, "\r\n ");
    if (len >= outlen) {
        return -1;
    }
    memcpy(out, body, len);
    out[len] = '\0';
    return 0;
}

int network_resolve_public_ip(char *out, size_t outlen) {
    if (g_config.public_ip[0]) {
        util_strlcpy(out, g_config.public_ip, outlen);
        return 0;
    }
    if (fetch_ip_from_host("checkip.amazonaws.com", "/", out, outlen) == 0) {
        return 0;
    }
    if (fetch_ip_from_host("api.ipify.org", "/", out, outlen) == 0) {
        return 0;
    }
    return -1;
}
