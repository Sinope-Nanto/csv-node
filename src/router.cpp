#include <string>
#include <string.h>
#include <iostream>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>  
#include <stdlib.h>
#include <stdio.h>

#include "include/route.h"
#include <hv/json.hpp>

using json = nlohmann::json;

void router_init(HttpService* router){
    router->GET("/commands/ping", [](const HttpContextPtr& ctx) {
        json resp;
        resp["node_status"] = 0;
        std::cout << "Ping Response:" << resp.dump(2) << std::endl;
        return ctx->send(resp.dump(2));
    });
}