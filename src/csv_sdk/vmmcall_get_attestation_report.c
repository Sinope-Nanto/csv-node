#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>

#include "../include/attestation.h"

#include "openssl/sm3.h"

#define PAGE_SHIFT 12
#define PAGE_SIZE (1 << PAGE_SHIFT)
#define PAGEMAP_LEN 8

static uint8_t g_mnonce[GUEST_ATTESTATION_NONCE_SIZE];
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

static uint64_t va_to_pa(uint64_t va)
{
    FILE *pagemap;
    uint64_t offset, pfn;

    pagemap = fopen("/proc/self/pagemap", "rb");
    if (!pagemap) {
        printf("open pagemap fail\n");
        return 0;
    }

    offset = va / PAGE_SIZE * PAGEMAP_LEN;
    if(fseek(pagemap, offset, SEEK_SET) != 0) {
        printf("seek pagemap fail\n");
        fclose(pagemap);
        return 0;
    }

    if (fread(&pfn, 1, PAGEMAP_LEN - 1, pagemap) != PAGEMAP_LEN - 1) {
        printf("read pagemap fail\n");
        fclose(pagemap);
        return 0;
    }

    pfn &= 0x7FFFFFFFFFFFFF;

    return pfn << PAGE_SHIFT;
}

static long hypercall(unsigned int nr, unsigned long p1, unsigned int len)
{
    long ret = 0;

    asm volatile("vmmcall"
             : "=a"(ret)
             : "a"(nr), "b"(p1), "c"(len)
             : "memory");
    return ret;
}

static int get_attestation_report(struct csv_attestation_report *report)
{
    struct csv_attestation_user_data *user_data;
    uint64_t user_data_pa;
    long ret;

    if (!report) {
        printf("NULL pointer for report\n");
        return -1;
    }

    /* prepare user data */
    user_data = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (user_data == MAP_FAILED) {
        printf("mmap failed\n");
        return -1;
    }
    printf("mmap %p\n", user_data);

    snprintf((char *)user_data->data, GUEST_ATTESTATION_DATA_SIZE, "%s", "user data");
    gen_random_bytes(user_data->mnonce, GUEST_ATTESTATION_NONCE_SIZE);
    memcpy(g_mnonce, user_data->mnonce, GUEST_ATTESTATION_NONCE_SIZE);

    // compute hash and save to the private page
    sm3((const unsigned char *)user_data,
        GUEST_ATTESTATION_DATA_SIZE + GUEST_ATTESTATION_NONCE_SIZE,
        (unsigned char *)&user_data->hash);

    csv_data_dump("data", user_data->data, GUEST_ATTESTATION_DATA_SIZE);
    csv_data_dump("mnonce", user_data->mnonce, GUEST_ATTESTATION_NONCE_SIZE);
    csv_data_dump("hash", (unsigned char *)&user_data->hash, sizeof(hash_block_u));
    printf("data: %s\n", user_data->data);

    /* call host to get attestation report */
    user_data_pa = va_to_pa((uint64_t)user_data);
    printf("user_data_pa: %lx\n", user_data_pa);

    ret = hypercall(KVM_HC_VM_ATTESTATION, user_data_pa, PAGE_SIZE);
    if (ret) {
        printf("hypercall fail: %ld\n", ret);
        munmap(user_data, PAGE_SIZE);
        return -1;
    }
    memcpy(report, user_data, sizeof(*report));
    munmap(user_data, PAGE_SIZE);

    return 0;
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

int vmmcall_get_attestation_report(unsigned char* report_buf, unsigned int buf_len)
{
    int ret;
    struct csv_attestation_report report;

    if (buf_len < sizeof(report)){
        printf("The allocated length is too short to meet the generated report!\n");
        printf("The length should not be less than %ld \n", sizeof(report));
        return -1;
    }

    if (report_buf == NULL) {
        printf("allocate memory failed\n");
        return -1;
    }

    printf("get attestation report & save to %s\n", ATTESTATION_REPORT_FILE);

    ret = get_attestation_report(&report);
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
