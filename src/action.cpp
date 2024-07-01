#include "include/action.h"
#include "include/command_error.h"

#include <string>
#include <cstring>
#include <iostream>
#include <fstream>
#include <sys/time.h>
#include <sys/types.h>
#include <hv/json.hpp>
#include <hv/requests.h>
#include <unistd.h>  
#include <stdlib.h>
#include <stdio.h>

extern "C"{
    #include "include/attestation.h"
}

#define ADDRESS_BUFFER 200

using json = nlohmann::json;

void dump_buffer(uint8_t* buffer, int len){
    for(int i = 0; i < len; ++i){
        printf("%02x", buffer[i]);
        if(i % 100 == 99)
            printf("\n");
    }
    printf("\n");
}

void dump_buffer2str(uint8_t* buffer, char* dst, int len){
    for(int i = 0; i < len; ++i){
        sprintf(dst + 2 * i, "%02x", buffer[i]);
    }
    dst[2 * len] = 0;
}

int csv_node_register(char* ip, int port, int id){
    int ret = RC_SUCCESS;
    char soc_address[ADDRESS_BUFFER];
    json resp;
    json node_date;
    int node_status;
    std::ofstream outfile;
    std::ifstream inputfile;

    std::ifstream f("../information/platinfo.json");
    json register_data = json::parse(f);
    register_data["node_id"] = id;
    std::string request_data = register_data.dump(2);
    f.close();

    if(snprintf(soc_address, ADDRESS_BUFFER, "https://%s:%d/instances/agent/register", ip, port) >= ADDRESS_BUFFER){
        return RC_REGISTER_SGX_COLLECT_FAIL;
    }
    // std::cout << soc_address << std::endl;
    // std::cout << request_data << std::endl;

    http_headers headers;
    headers["Content-Type"] = "application/json";
    auto r = requests::post(soc_address, request_data, headers);
    if(r == NULL){
        printf("NULL!");
        ret = RC_REGISTER_NODE_CONNECT_SOC_FAIL;
        goto err;
    }

    try{
        printf("%d %s\r\n", r->status_code, r->status_message());
        std::cout << r->body << std::endl;
        resp = json::parse(r->body);
        resp["node_status"].get_to(node_status);
    }
    catch(...){
        ret = RC_REGISTER_NODE_CONNECT_SOC_FAIL;
        goto err;
    }
    
    if (node_status == RC_SUCCESS || node_status == RC_REGISTER_NODE_REGISTER_SUCCEED){
        node_date["uuid"] = resp["uuid"];
        node_date["ak_cert"] = resp["ak_cert"];
        node_date["ak_cert_size"] = resp["ak_cert_size"];
        node_date["master_secret"] = resp["master_secret"];
    }
    else{
        ret = node_status;
        inputfile.open("../information/nodedat.json");
        if(!inputfile.is_open()){
            ret = RC_REGISTER_NODE_EXECUTE_FAIL;
        }
        else{
            node_date = json::parse(inputfile);
            inputfile.close();
        }
    }
    node_date["node_status"] = node_status;
    node_date["node_id"] = id;
    outfile.open("../information/nodedat.json", std::ios::out | std::ios::trunc);
    outfile << node_date.dump(2) << std::endl;
    outfile.close();

err:
    // if(request_data)
    //     free(request_data);
    return ret;
};

int csv_node_attestation(char* ip, int port){

    char usr_data[GUEST_ATTESTATION_NONCE_SIZE << 1 + 1];
    char as_address[ADDRESS_BUFFER];
    std::string randnum, token, uuid;
    int randnum_len;
    int node_status, ret = RC_SUCCESS; 

    json resp;
    json request_data;
    json verify_data;
    json register_data;
    std::ofstream outfile;
    std::ifstream inputfile;

    unsigned char buffer[3000];
    char report_path[] = "report.cert";
    char pek_path[] = "../information/pek.cert";
    CSV_CERT_t pek_cert;
    ecc_pubkey_t ecc_pubkey;
    char usr_id_hex[HYGON_USER_ID_SIZE << 1 + 1];
    memset(usr_id_hex, 0, HYGON_USER_ID_SIZE << 1 + 1);
    char report_hex[6000];
    memset(report_hex, 0, 6000);

    FILE *pek_bin, *report_bin;

    int i;
    http_headers headers;
    headers["Content-Type"] = "application/json";
    
    inputfile.open("../information/nodedat.json");

    if(!inputfile.is_open())
        return RC_ATTEST_NODE_EXECUTE_FAIL;
    request_data = json::parse(inputfile);
    inputfile.close();

    request_data["uuid"].get_to(uuid);
    if(snprintf(as_address, ADDRESS_BUFFER, "https://%s:%d/attestation/challenge?type=%d&uuid=%s", ip, port, 4, uuid.c_str()) >= ADDRESS_BUFFER)
        return RC_ATTEST_NODE_EXECUTE_FAIL;
    
    auto r = requests::get(as_address);
    if(r == NULL){
        printf("NULL response when get random number\n");
        return RC_ATTEST_AS_DEAL_CHALLENGE_FAIL;
    }
    try{
        printf("%d %s\r\n", r->status_code, r->status_message());
        std::cout << r->body << std::endl;
        resp = json::parse(r->body);
        resp["as_exec_status"].get_to(node_status);
    }
    catch(...){
        return RC_ATTEST_AS_DEAL_CHALLENGE_FAIL;
    }

    if(node_status != RC_SUCCESS)
        return node_status;
    
    resp["nonce"].get_to(randnum);
    resp["nonce_size"].get_to(randnum_len);

    if(snprintf(as_address, ADDRESS_BUFFER, "./get_report %s", randnum.c_str()) >= ADDRESS_BUFFER)
        return RC_ATTEST_NODE_EXECUTE_FAIL;
    system(as_address);
    report_bin = fopen(report_path, "rb");
    memset(buffer, 0, 3000);
    fread(buffer, 1, 3000, report_bin);
    dump_buffer2str(buffer, report_hex, sizeof(struct csv_attestation_report));
    fclose(report_bin);

    verify_data["type"] = 4;
    verify_data["uuid"] = request_data["uuid"];
    verify_data["ak_cert"] = request_data["ak_cert"];
    verify_data["ak_cert_size"] = request_data["akcert_size"];
    
    inputfile.open("../information/platinfo.json");
    register_data = json::parse(inputfile);
    inputfile.close();
    verify_data["ak_pubkey"] = register_data["ak_pubkey"];
    verify_data["evidence"]["quote"] = report_hex;
    verify_data["evidence"]["quote_size"] = strlen(report_hex);

    memset(buffer, 0, 3000);
    pek_bin = fopen(pek_path, "rb"); 
    fread(buffer, 1, 3000, pek_bin);
    fclose(pek_bin);

    memcpy(&pek_cert, buffer, sizeof(CSV_CERT_t));
    ecc_pubkey = pek_cert.ecc_pubkey;
    dump_buffer2str((uint8_t*)(&ecc_pubkey.user_id), usr_id_hex, HYGON_USER_ID_SIZE);
    verify_data["ak_pubkey"]["user_id"] = usr_id_hex;


    memset(as_address, 0, ADDRESS_BUFFER);
    if(snprintf(as_address, ADDRESS_BUFFER, "https://%s:%d/attestation/quote", ip, port) >= ADDRESS_BUFFER)
        return RC_ATTEST_NODE_EXECUTE_FAIL;

    printf("send quote to as\n");
    auto r2 = requests::post(as_address, verify_data.dump(2), headers);
    if(r2 == NULL){
        printf("NULL response when verify quote\n");
        return RC_ATTEST_AS_VERIFY_FAIL;
    }
    try{
        printf("%d %s\r\n", r2->status_code, r2->status_message());
        std::cout << r2->body << std::endl;
        resp = json::parse(r2->body);
        resp["as_exec_status"].get_to(node_status);
    }
    catch(...){
        return RC_ATTEST_AS_VERIFY_FAIL;
    }

    if(node_status != RC_SUCCESS)
        return node_status;

    resp["token"].get_to(token);
    outfile.open("../information/token", std::ios::out | std::ios::trunc);
    if(!outfile.is_open())
        return RC_ATTEST_NODE_EXECUTE_FAIL;

    outfile << token << std::endl;
    outfile.close();
    
    return ret;
}

int csv_node_update_ms(char* ip, int port){
    std::ofstream outfile;
    std::ifstream inputfile;
    char kms_address[ADDRESS_BUFFER];
    int kms_status = RC_SUCCESS;
    std::string uuid;
    json resp;

    inputfile.open("../information/nodedat.json");
    if(!inputfile.is_open())
        return RC_ATTEST_NODE_EXECUTE_FAIL;
    json request_data = json::parse(inputfile);
    inputfile.close();
    request_data["uuid"].get_to(uuid);
    if(snprintf(kms_address, ADDRESS_BUFFER, "https://%s:%d/manage/update/master?uuid=%s", ip, port, uuid.c_str()) >= ADDRESS_BUFFER)
        return RC_KMS_OPERATE_FAIL;
    
    auto r = requests::get(kms_address);
    if(r == NULL)
        return RC_KMS_OPERATE_FAIL;

    try{
        resp = json::parse(r->body);
        resp["kms_exec_status"].get_to(kms_status);
    }
    catch(...){
        return RC_KMS_OPERATE_FAIL;
    }

    if(kms_status != RC_SUCCESS)
        return kms_status;

    request_data["master_secret"] = resp["master_secret"];

    outfile.open("../information/information.json", std::ios::out | std::ios::trunc);
    outfile << request_data.dump(2) << std::endl;
    outfile.close();

    return kms_status;
}

int csv_node_update_cert(char* ip, int port){
    std::ofstream outfile;
    std::ifstream inputfile;
    char kms_address[ADDRESS_BUFFER];
    int kms_status = RC_SUCCESS;
    std::string uuid;
    json resp;

    inputfile.open("../information/nodedat.json");
    if(!inputfile.is_open())
        return RC_ATTEST_NODE_EXECUTE_FAIL;
    json request_data = json::parse(inputfile);
    inputfile.close();
    request_data["uuid"].get_to(uuid);
    if(snprintf(kms_address, ADDRESS_BUFFER, "https://%s:%d/manage/update/cert?uuid=%s", ip, port, uuid.c_str()) >= ADDRESS_BUFFER)
        return RC_KMS_OPERATE_FAIL;
    
    auto r = requests::get(kms_address);

    if(r == NULL)
        return RC_KMS_OPERATE_FAIL;

    try{
        resp = json::parse(r->body);
        resp["kms_exec_status"].get_to(kms_status);
    }
    catch(...){
        return RC_KMS_OPERATE_FAIL;
    }

    if(kms_status != RC_SUCCESS)
        return kms_status;

    request_data["ak_cert"] = resp["cert"];
    request_data["ak_cert_size"] = resp["cert_size"];

    outfile.open("../information/nodedat.json", std::ios::out | std::ios::trunc);
    outfile << request_data.dump(2) << std::endl;
    outfile.close();

    return kms_status;
}