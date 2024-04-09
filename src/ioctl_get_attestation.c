#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>

#include "include/attestation.h"
#include "csv_sdk/csv_sdk.h"

void dump_buffer(uint8_t* buffer, int len){
    for(int i = 0; i < len; ++i){
        printf("%02x", buffer[i]);
        if(i % 100 == 99)
            printf("\n");
    }
    printf("\n");
}

int main()
{
    int ret;
    unsigned int len = sizeof(struct csv_attestation_report);

    unsigned char* report_buf = (unsigned char*)malloc(len);
    unsigned char random_number[GUEST_ATTESTATION_NONCE_SIZE];
    memset(random_number, 0x1F, GUEST_ATTESTATION_NONCE_SIZE);

    ret = ioctl_get_attestation_report(report_buf, len, random_number, GUEST_ATTESTATION_NONCE_SIZE);
    if (ret) {
        printf("get report fail\n");
        free(report_buf);
        return -1;
    }
    dump_buffer(report_buf, len);
    printf("done\n");

    free(report_buf);
    return ret;
}
