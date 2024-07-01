#include <string>
#include <string.h>
#include <iostream>
#include <fstream>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>  
#include <stdlib.h>
#include <stdio.h>

#include "include/route.h"
#include "include/action.h"
#include <hv/json.hpp>
#include "include/command_error.h"

extern network_config global_net_config;
using json = nlohmann::json;

void server_init(){
    std::ifstream f("../information/network_config.json");
    json json_data = json::parse(f);
    global_net_config.listen_port = json_data["listen_port"];
    global_net_config.soc_port = json_data["soc_port"];
    global_net_config.as_port = json_data["as_port"];
    global_net_config.kms_port = json_data["kms_port"];
    std::string str = json_data["soc_ip"].dump();
    str.erase(0, str.find_first_not_of("\""));
    str.erase(str.find_last_not_of("\"") + 1);
    strcpy(global_net_config.soc_ip, str.c_str());

    str = json_data["as_ip"].dump();
    str.erase(0, str.find_first_not_of("\""));
    str.erase(str.find_last_not_of("\"") + 1);
    strcpy(global_net_config.as_ip, str.c_str());

    str = json_data["kms_ip"].dump();
    str.erase(0, str.find_first_not_of("\""));
    str.erase(str.find_last_not_of("\"") + 1);
    strcpy(global_net_config.kms_ip, str.c_str());

    printf("Initialization Information:\n");
    printf("Listening Address: 0.0.0.0:%d\n", global_net_config.listen_port);
    printf("SOC Address: %s:%d\n", global_net_config.soc_ip, global_net_config.soc_port);
    printf("AS Address: %s:%d\n", global_net_config.as_ip, global_net_config.as_port);
    printf("KMS Address: %s:%d\n", global_net_config.kms_ip, global_net_config.kms_port);
    f.close();
}

void router_init(HttpService* router){
    printf("router init...\n");
    // router->GET("/ping", [](HttpContextPtr* ctx, HttpResponse* resp) {
    //     return resp->String("pong");
    // });

    router->GET("/ping", [](const HttpContextPtr& ctx) {
        std::string resp = "pong";
        // printf("Ping\n");
        return ctx->send(resp);
    });

    router->GET("/commands/register", [](const HttpContextPtr& ctx) {
        json resp;
        json node_dat;
        std::ifstream f;
        std::string id;
        json get_data = ctx->params();
        get_data["node_id"].get_to(id);
        int node_id = std::stoi(id);
        int ret = csv_node_register(global_net_config.soc_ip, global_net_config.soc_port, node_id);

        printf("Register\n");
        if(ret && ret != RC_REGISTER_NODE_REGISTER_SUCCEED){
            printf("Register error:%d\n", ret);
        }
        else{
            ret = RC_REGISTER_NODE_REGISTER_SUCCEED;
            f.open("../information/nodedat.json");
            node_dat = json::parse(f);
            resp["uuid"] = node_dat["uuid"];
            f.close();
        }
            
err:        
            resp["node_status"] = ret;
            return ctx->send(resp.dump(2));
        });

    router->GET("/commands/attestation", [](const HttpContextPtr& ctx) {
        json resp;

        int ret = csv_node_attestation(global_net_config.as_ip, global_net_config.as_port);

        if(ret){
            printf("Attestation error:%d\n", ret);
        }
        
        resp["node_attestation_status"] = ret;
        return ctx->send(resp.dump(2));
    });    

    router->GET("/commands/update/ms", [](const HttpContextPtr& ctx) {
        json resp;

        int ret = csv_node_update_ms(global_net_config.kms_ip, global_net_config.kms_port);

        if(ret){
            printf("Updata error:%d\n", ret);
            ret = RC_KMS_OPERATE_FAIL;
        }
err:
        resp["node_update_status"] = ret;
        return ctx->send(resp.dump(2));
    });

    router->GET("/commands/update/cert", [](const HttpContextPtr& ctx) {
        json resp;

        int ret = csv_node_update_cert(global_net_config.kms_ip, global_net_config.kms_port);

        if(ret){
             printf("Updata error:%d\n", ret);
            ret = RC_KMS_OPERATE_FAIL;
        }
err:
        resp["node_update_status"] = ret;
        return ctx->send(resp.dump(2));
    });
    printf("router init complete.\n");
}