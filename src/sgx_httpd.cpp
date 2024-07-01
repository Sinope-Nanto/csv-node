#include <hv/HttpServer.h>
#include <hv/hthread.h>
#include <hv/hasync.h>
#include "include/route.h"

network_config global_net_config = {
    8080, 
    "127.0.0.1", 
    1234,
    "127.0.0.1", 
    1234,
    "127.0.0.1", 
    1234
};

int main(){
    HttpService router;
    hv::HttpServer server;
    router_init(&router);
    server_init();

    server.service = &router;
    server.https_port = global_net_config.listen_port;
    
    hssl_ctx_opt_t param;
    memset(&param, 0, sizeof(param));
    param.crt_file = "../information/https_cert/server.crt";
    param.key_file = "../information/https_cert/server.key";
    param.endpoint = HSSL_SERVER;
    if (server.newSslCtx(&param) != 0) {
        fprintf(stderr, "new SSL_CTX failed!\n");
        return -20;
    }
    server.start();

    while (getchar() != '\n');
    hv::async::cleanup();
    return 0;
    return 0;
}
