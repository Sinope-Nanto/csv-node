#ifndef ROUTER_H
#define ROUTER_H

#include <hv/HttpServer.h>

#define CMD_BUFFER_LEN 200

typedef struct _network_config{
    uint32_t listen_port;
    char soc_ip[20];
    uint32_t soc_port;
    char as_ip[20];
    uint32_t as_port;
    char kms_ip[20];
    uint32_t kms_port;
} network_config;

void router_init(HttpService* router);
void server_init();

#endif