#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/time.h>   //add by vonsky

#include "../include/attestation.h"

#include "openssl/sm3.h"

static uint8_t g_mnonce[GUEST_ATTESTATION_NONCE_SIZE];
struct csv_attestation_user_data {
    uint8_t data[GUEST_ATTESTATION_DATA_SIZE];
    uint8_t mnonce[GUEST_ATTESTATION_NONCE_SIZE];
    hash_block_u hash;
};

// static void gen_random_bytes(void *buf, uint32_t len)
// {
//     uint32_t i;
//     uint8_t *buf_byte = (uint8_t *)buf;

//     srand(time(NULL)); //add by vonsky

//     for (i = 0; i < len; i++) {
//         buf_byte[i] = rand() & 0xFF;
//     }
// }

static void csv_data_dump(const char* name, uint8_t *data, uint32_t len)
{
    printf("%s:\n", name);
    int i;
    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)data[i];
        printf("%02hhx", c);
    }
    printf("\n");
}

struct csv_guest_mem{
    unsigned long va;
    int size;
};


#define PAGE_SHIFT 12
#define PAGE_SIZE (1 << PAGE_SHIFT)

#define CSV_GUEST_IOC_TYPE     'D'
#define GET_ATTESTATION_REPORT _IOWR(CSV_GUEST_IOC_TYPE, 1, struct csv_guest_mem)

static int get_attestation_report(struct csv_attestation_report *report, uint8_t* random_number)
{
    struct csv_attestation_user_data *user_data;
    int user_data_len = PAGE_SIZE;
    long ret;
    int fd = 0;
    struct csv_guest_mem mem = {0};

    //add by vonsky
    struct timeval start_time;
    struct timeval end_time;
    double time_used = 0;

    if (!report) {
        printf("NULL pointer for report\n");
        return -1;
    }

    /* prepare user data */
    user_data = (struct csv_attestation_user_data *)malloc(user_data_len);
    if (user_data == NULL) {
        printf("allocate memory failed\n");
        return -1;
    }
    memset((void *)user_data, 0x0, user_data_len);
    // printf("user data: %p\n", user_data);

    snprintf((char *)user_data->data, GUEST_ATTESTATION_DATA_SIZE, "%s", "user data");
    // gen_random_bytes(user_data->mnonce, GUEST_ATTESTATION_NONCE_SIZE);
    memcpy(user_data->mnonce, random_number, GUEST_ATTESTATION_NONCE_SIZE);
    memcpy(g_mnonce, user_data->mnonce, GUEST_ATTESTATION_NONCE_SIZE);

    // compute hash and save to the private page
    sm3((const unsigned char *)user_data,
        GUEST_ATTESTATION_DATA_SIZE + GUEST_ATTESTATION_NONCE_SIZE,
        (unsigned char *)&user_data->hash);

    csv_data_dump("data", user_data->data, GUEST_ATTESTATION_DATA_SIZE);
    csv_data_dump("mnonce", user_data->mnonce, GUEST_ATTESTATION_NONCE_SIZE);
    csv_data_dump("hash", (unsigned char *)&user_data->hash, sizeof(hash_block_u));
    // printf("data: %s\n", user_data->data);

    fd = open("/dev/csv-guest",O_RDWR);
    if(fd < 0)
    {
        printf("open /dev/csv-guest failed\n");
        free(user_data);
        return -1;
    }
    mem.va = (uint64_t)user_data;
    // printf("mem.va: %lx\n", mem.va);
    mem.size = user_data_len;
    /*  get attestation report */

    gettimeofday(&start_time, NULL);  //add by vonsky
    ret = ioctl(fd,GET_ATTESTATION_REPORT,&mem);
    gettimeofday(&end_time, NULL); //add by vonsky
    time_used = end_time.tv_sec - start_time.tv_sec + (double)(end_time.tv_usec - start_time.tv_usec)/1000000; //add by vonsky
    printf("Time for get attestation report: %lf ms\n", 1000*time_used); //add by vonsky

    if(ret < 0)
    {
        printf("ioctl GET_ATTESTATION_REPORT fail: %ld\n", ret);
        goto error;
    }
    memcpy(report, user_data, sizeof(*report));

    ret = 0;
error:
    close(fd);
    free(user_data);
    return ret;
}

static int compute_session_mac_and_verify(struct csv_attestation_report *report)
{
    hash_block_u hmac = {0};

    sm3_hmac((const unsigned char*)(&report->pek_cert),
             sizeof(report->pek_cert) + SN_LEN + sizeof(report->reserved2),
             g_mnonce, GUEST_ATTESTATION_NONCE_SIZE,(unsigned char*)(hmac.block));

    if(memcmp(hmac.block, report->mac.block, sizeof(report->mac.block)) == 0){
        printf("mac verify success\n");
        return 0;
    }else{
        printf("mac verify failed\n");
        return -1;
    }
}

int ioctl_get_attestation_report(unsigned char* report_buf, unsigned int buf_len, uint8_t* random_number, unsigned int rn_len)
{
    int ret;
    struct csv_attestation_report report;

    if (buf_len < sizeof(report)){
        printf("The allocated length is too short to meet the generated report!\n");
        printf("The length should not be less than %ld \n", sizeof(report));
        return -1;
    }

    if (rn_len != GUEST_ATTESTATION_NONCE_SIZE){
        printf("The Random Number length is wrong to generate the generated report!\n");
        printf("The length should be %d \n", GUEST_ATTESTATION_NONCE_SIZE);
        return -1;
    }

    if (report_buf == NULL) {
        printf("allocate memory failed\n");
        return -1;
    }

    // printf("get attestation report & save to %s\n", ATTESTATION_REPORT_FILE);

    ret = get_attestation_report(&report, random_number);
    if (ret) {
        printf("get attestation report fail\n");
        return -1;
    }

    ret = compute_session_mac_and_verify(&report);
    if (ret) {
        printf("PEK cert and ChipId have been tampered with\n");
        return ret;
    } else {
        printf("check PEK cert and ChipId successfully\n");
    }

    memset(report.reserved2, 0, sizeof(report.reserved2));

    memcpy(report_buf, &report, sizeof(report));

    return 0;
}
