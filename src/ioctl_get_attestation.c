#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h> 
#include <time.h>
#include <sys/time.h>

#include "include/attestation.h"
#include "csv_sdk/csv_sdk.h"
#include "openssl/rand.h"

void dump_buffer(uint8_t* buffer, int len){
    for(int i = 0; i < len; ++i){
        printf("%02x", buffer[i]);
        if(i % 100 == 99)
            printf("\n");
    }
    printf("\n");
}

void hex2bin(const char* hexstr, unsigned char* dst,int* size)
{   
    if(strlen(hexstr) < GUEST_ATTESTATION_NONCE_SIZE << 1){
        *size = 0;
        return;
    }
        
    
    // size_t hexstrLen = GUEST_ATTESTATION_NONCE_SIZE << 1;
    size_t bytesLen = GUEST_ATTESTATION_NONCE_SIZE;

    int count = 0;
    const char* pos = hexstr;

    for(count = 0; count < bytesLen; count++) {
        sscanf(pos, "%2hhx", &dst[count]);
        pos += 2;
    }

    if( size != NULL )
        *size = GUEST_ATTESTATION_NONCE_SIZE;

}

int main(int argc, char* argv[])
{
    int ret;
    unsigned int len = sizeof(struct csv_attestation_report) + 100;
    char random_seed[11];
    unsigned char* report_buf = (unsigned char*)malloc(len);
    unsigned char random_number[GUEST_ATTESTATION_NONCE_SIZE];
    memset(random_number, 0, GUEST_ATTESTATION_NONCE_SIZE);
    if(argc == 1){
        srand(time(NULL));
        sprintf(random_seed, "%010d", rand());
        RAND_seed(random_seed, 10);
        ret = RAND_bytes(random_number, GUEST_ATTESTATION_NONCE_SIZE);
    }
    else{
        hex2bin(argv[1], random_number, &ret);
        if(!ret)
            return 0;
    }

    struct timeval t1,t2;
    double timeuse;
    gettimeofday(&t1,NULL);

    ret = ioctl_get_attestation_report(report_buf, len, random_number, GUEST_ATTESTATION_NONCE_SIZE);
    gettimeofday(&t2,NULL);
    timeuse = (t2.tv_sec - t1.tv_sec) + (double)(t2.tv_usec - t1.tv_usec)/1000.0;
    printf("%lf ms\n", timeuse);

    if (ret) {
        printf("get report fail\n");
        free(report_buf);
        return -1;
    }
    // dump_buffer(report_buf, len);
    FILE* report_file = fopen("report.cert", "wb");
    fwrite(report_buf, sizeof(struct csv_attestation_report), 1, report_file);
    fclose(report_file);
    free(report_buf);
    return ret;
}
