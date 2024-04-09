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

#include "../include/attestation.h"

#include "openssl/sm3.h"

static uint8_t g_mnonce[GUEST_ATTESTATION_NONCE_SIZE];
static uint8_t r_mnonce[GUEST_ATTESTATION_NONCE_SIZE];

struct csv_attestation_user_data {
    uint8_t data[GUEST_ATTESTATION_DATA_SIZE];
    uint8_t mnonce[GUEST_ATTESTATION_NONCE_SIZE];
    hash_block_u hash;
};

static void gen_random_bytes(void *buf, uint32_t len)
{
    uint32_t i;
    uint8_t *buf_byte = (uint8_t *)buf;

    for (i = 0; i < len; i++) {
        buf_byte[i] = rand() & 0xFF;
    }
}

static void print_data(const char* name, uint8_t *data, uint32_t len)
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

static int get_attestation_report(struct csv_attestation_report *report)
{
    struct csv_attestation_user_data *user_data;
    int user_data_len = PAGE_SIZE;
    long ret;
    int fd = 0;
    struct csv_guest_mem mem = {0};

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

    snprintf((char *)user_data->data, GUEST_ATTESTATION_DATA_SIZE, "%s", "user data");
    gen_random_bytes(user_data->mnonce, GUEST_ATTESTATION_NONCE_SIZE);
    memcpy(g_mnonce, user_data->mnonce, GUEST_ATTESTATION_NONCE_SIZE);

    // compute hash and save to the private page
    sm3((const unsigned char *)user_data,
        GUEST_ATTESTATION_DATA_SIZE + GUEST_ATTESTATION_NONCE_SIZE,
        (unsigned char *)&user_data->hash);

    fd = open("/dev/csv-guest",O_RDWR);
    if(fd < 0)
    {
        printf("open /dev/csv-guest failed\n");
        free(user_data);
        return -1;
    }
    mem.va = (uint64_t)user_data;
    printf("mem.va: %lx\n", mem.va);
    mem.size = user_data_len;
    /*  get attestation report */
    ret = ioctl(fd,GET_ATTESTATION_REPORT,&mem);
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

static int verify_hmac(struct csv_attestation_report *report)
{
    hash_block_u hmac = {0};

    sm3_hmac((const unsigned char*)(&report->pek_cert),
             sizeof(report->pek_cert) + SN_LEN + sizeof(report->reserved2),
             g_mnonce, GUEST_ATTESTATION_NONCE_SIZE,(unsigned char*)(hmac.block));

    if(memcmp(hmac.block, report->mac.block, sizeof(report->mac.block)) == 0){
        return 0;
    }else{
        printf("mac verify failed\n");
        return -1;
    }
}

int ioctl_get_sealing_key(unsigned char* key_buf, unsigned int buf_len)
{
    int ret, i, j;
    struct csv_attestation_report report;

    if (buf_len < sizeof(report.reserved2)){
        printf("The allocated length is too short to meet the sealing key!\n");
        printf("The length should not be less than %ld \n", sizeof(report.reserved2));
        return -1;
    }

    if (key_buf == NULL) {
        printf("allocate memory failed\n");
        return -1;
    }

    ret = get_attestation_report(&report);
    if (ret) {
        printf("get attestation report fail\n");
        return -1;
    }

    ret = verify_hmac(&report);
    if (ret) {
        printf("report hmac verify fail\n");
        return -1;
    }

    j = GUEST_ATTESTATION_NONCE_SIZE / sizeof(uint32_t);
    for (i = 0; i < j; i++)
         ((uint32_t *)r_mnonce)[i] = ((uint32_t *)report.mnonce)[i] ^ report.anonce;

    ret = memcmp(g_mnonce, r_mnonce, GUEST_ATTESTATION_NONCE_SIZE);
    if (ret) {
        printf("mnonce is different\n");
        print_data("g_mnonce", g_mnonce, GUEST_ATTESTATION_NONCE_SIZE);
        print_data("r_mnonce", r_mnonce, GUEST_ATTESTATION_NONCE_SIZE);
        return -1;
    }

    memcpy(key_buf, report.reserved2, sizeof(report.reserved2));

    return 0;
}
