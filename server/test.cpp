extern "C" {
    #include "attestation.h"
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <stdint.h>

#define CSV_HASH_BLOCK_SIZE 32
#define CSV_CERT_SIZE 2084

void dump_buffer(uint8_t* buffer, int len){
    for(int i = 0; i < len; ++i){
        printf("%02x", buffer[i]);
        if(i % 100 == 99)
            printf("\n");
    }
    printf("\n");
}

uint8_t* hex2bin(const char* hexstr)
{
    size_t hexstrLen = strlen(hexstr);
    size_t bytesLen = hexstrLen / 2;
    uint8_t* bytes = (uint8_t*) malloc(bytesLen);
    int count = 0;
    const char* pos = hexstr;
    for(count = 0; count < bytesLen; count++) {
        sscanf(pos, "%2hhx", &bytes[count]);
        pos += 2;
    }
    return bytes;
}

void dump_buffer2str(uint8_t* buffer, char* dst, int len){
    for(int i = 0; i < len; ++i){
        sprintf(dst + 2 * i, "%02x", buffer[i]);
    }
    dst[2 * len] = 0;
}

// 报告结构
typedef struct __csv_attestation_report {
    uint8_t     user_pubkey_digest[CSV_HASH_BLOCK_SIZE];
    uint8_t     vm_id[VM_ID_SIZE];
    uint8_t     vm_version[VM_VERSION_SIZE];
    uint8_t     user_data[USER_DATA_SIZE];
    uint8_t     mnonce[GUEST_ATTESTATION_NONCE_SIZE];
    uint8_t     measure[CSV_HASH_BLOCK_SIZE];
    uint32_t    policy;
    uint32_t    sig_usage;
    uint32_t    sig_algo;
    uint32_t    anonce;
    uint32_t    sig1[ECC_POINT_SIZE*2/SIZE_INT32];
    uint8_t     pek_cert[CSV_CERT_SIZE];
    uint8_t     sn[SN_LEN];
    uint8_t     reserved2[32];
    uint8_t     mac[CSV_HASH_BLOCK_SIZE];
}csv_report;

// 解析函数，输入为node传入的16进制报告字符串
csv_report* get_csv_report_info(char* hex_csv_report){
    uint8_t* buffer = hex2bin(hex_csv_report);
    csv_report* ret = (csv_report*)malloc(sizeof(csv_report));
    memcpy(ret, buffer, sizeof(csv_report));

    int j = (sizeof(csv_report) - CSV_HASH_BLOCK_SIZE - 32)/ sizeof(uint32_t);
    for (int i = 0; i < j; i++)
         ((uint32_t *)ret)[i] = ((uint32_t *)buffer)[i] ^ ((struct csv_attestation_report*)buffer)->anonce;
    free(buffer);
    return ret;
}

int main(void){
    uint8_t buffer[3000];
    char char_buffer[6000];
    // char random_number_hex[] = "74a18b95e6d4f23a47a9ad1e99a043a5";
    char report_path[] = "report.cert";

    FILE* report_bin = fopen(report_path, "rb");
    
    memset(buffer, 0, 3000);

    fread(buffer, 1, 3000, report_bin);
    dump_buffer2str(buffer, char_buffer,sizeof(struct csv_attestation_report));
    
    csv_report* ret = get_csv_report_info(char_buffer);


    printf("%d\n", ret->policy);
    printf("%d\n", ret->sig_usage);
    printf("%d\n", ret->sig_algo);
    printf("%d\n", ret->anonce);

    free(ret);
    return 0;
}