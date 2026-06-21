#ifndef CLOUDTSE_NETWORK_H
#define CLOUDTSE_NETWORK_H

#include <stddef.h>

int network_local_ips(char ips[][64], int max_ips);
int network_resolve_public_ip(char *out, size_t outlen);

#endif
