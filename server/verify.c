#include "attestation.h"
#include "csv-verify.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <stdint.h>
 
#include "openssl/conf.h"
#include "openssl/evp.h"
#include "openssl/sm2.h"
#include "openssl/ec.h"
#include "openssl/err.h"
#include "openssl/sm3.h"

#define PUB_X_POS 20
#define PUB_Y_POS 92
#define CSV_PUBKEY_LENGTH 32
#define CSV_SIG_LENGTH 32

#define CSV_ECC_CURVE_NAME NID_sm2p256v1

uint8_t* get_pub_x(uint8_t* buffer){
    uint8_t* ret = (uint8_t*)malloc(CSV_PUBKEY_LENGTH);
    memcpy(ret, buffer + PUB_X_POS, CSV_PUBKEY_LENGTH);
    return ret;
}

uint8_t* get_pub_y(uint8_t* buffer){
    uint8_t* ret = (uint8_t*)malloc(CSV_PUBKEY_LENGTH);
    memcpy(ret, buffer + PUB_Y_POS, CSV_PUBKEY_LENGTH);
    return ret;
}

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

unsigned char* hex2bin(const char* hexstr, size_t* size)
{
    size_t hexstrLen = strlen(hexstr);
    size_t bytesLen = hexstrLen / 2;

    unsigned char* bytes = (unsigned char*) malloc(bytesLen);

    int count = 0;
    const char* pos = hexstr;

    for(count = 0; count < bytesLen; count++) {
        sscanf(pos, "%2hhx", &bytes[count]);
        pos += 2;
    }

    if( size != NULL )
        *size = bytesLen;

    return bytes;
}

uint8_t* get_random_number(struct csv_attestation_report* report){
    uint8_t* ret = (uint8_t*)malloc(GUEST_ATTESTATION_NONCE_SIZE);
    int j = sizeof(report->mnonce) / sizeof(uint32_t);
    for (int i = 0; i < j; i++)
         ((uint32_t *)ret)[i] = ((uint32_t *)report->mnonce)[i] ^ report->anonce;
    return ret;
}

static void invert_endian(unsigned char* buf, int len)
{
    int i;

    for(i = 0; i < len/2; i++)
    {
        unsigned int tmp = buf[i];
        buf[i] = buf[len - i -1];
        buf[len - i -1] =  tmp;
    }
}


static int gmssl_sm2_verify(struct ecc_point_q  Q,unsigned char *userid,
                      unsigned int userid_len, const unsigned char *msg, unsigned int msg_len, struct ecdsa_sign *sig_in){
    int        ret;
    EC_KEY    *eckey;
    unsigned char dgst[ECC_LEN];
    long unsigned int dgstlen;

    if (!msg || !userid|| !sig_in) {
        printf("gmssl_sm2 dsa256_verify invalid input parameter\n");
        return -1;
    }

    invert_endian(sig_in->r, ECC_LEN);
    invert_endian(sig_in->s, ECC_LEN);

    BIGNUM *bn_qx = BN_bin2bn(Q.Qx, 32, NULL);
    BIGNUM *bn_qy = BN_bin2bn(Q.Qy, 32, NULL);

    eckey = EC_KEY_new();
    EC_GROUP *group256 = EC_GROUP_new_by_curve_name(NID_sm2p256v1);
    EC_KEY_set_group(eckey, group256);
    EC_POINT *ecpt_pubkey = EC_POINT_new(group256);
    EC_POINT_set_affine_coordinates_GFp(group256, ecpt_pubkey, bn_qx, bn_qy, NULL);
    EC_KEY_set_public_key(eckey, ecpt_pubkey);

    if (eckey == NULL) {
        /* error */
        printf("EC_KEY_new_by_curve_name");
        EC_POINT_free(ecpt_pubkey);
        return -1;
    }

    dgstlen = sizeof(dgst);
    SM2_compute_message_digest(EVP_sm3(), EVP_sm3(), msg, msg_len, (const char *)userid,
                                userid_len,dgst, &dgstlen, eckey);

    /* verify */
    ECDSA_SIG *s = ECDSA_SIG_new();
    BIGNUM *sig_r=BN_new();
    BIGNUM *sig_s=BN_new();
    BN_bin2bn(sig_in->r, 32, sig_r);
    BN_bin2bn(sig_in->s, 32, sig_s);
    ECDSA_SIG_set0(s, sig_r, sig_s);

    ret = SM2_do_verify(dgst, dgstlen, s, eckey);

    EC_POINT_free(ecpt_pubkey);
    ECDSA_SIG_free(s);
    EC_GROUP_free(group256);
    EC_KEY_free(eckey);

    if (1 != ret) {
        printf("SM2_do_verify fail!, ret=%d\n", ret);
        return -1;
    }else

    return 0;
}

static int csv_cert_verify(const char *data, uint32_t datalen, ecc_signature_t *signature, ecc_pubkey_t *pubkey)
{
    struct ecc_point_q Q;

    Q.curve_id = pubkey->curve_id;
    memcpy(Q.Qx, pubkey->Qx, ECC_LEN);
    memcpy(Q.Qy, pubkey->Qy, ECC_LEN);
    invert_endian(Q.Qx, ECC_LEN);
    invert_endian(Q.Qy, ECC_LEN);

    struct ecdsa_sign sig_in;
    memcpy(sig_in.r, signature->sig_r, ECC_LEN);
    memcpy(sig_in.s, signature->sig_s, ECC_LEN);

    return gmssl_sm2_verify(Q, ((userid_u*)pubkey->user_id)->uid, ((userid_u*)pubkey->user_id)->len, (const unsigned char *)data, datalen, &sig_in);
}

int csv_attestation_report_verify(struct csv_attestation_report *report, ecc_pubkey_t *pubkey)
{
    int ret = 0;
    ret = csv_cert_verify((const char *)report, ATTESTATION_REPORT_SIGNED_SIZE, &report->ecc_sig1, pubkey);
    return ret;
}

int csv_do_verify(char* report_hex, char* pub_x_hex, char* pub_y_hex, char* usr_id_hex, char* random_number_hex){
    size_t report_len, pub_x_len, pub_y_len, usr_id_len, random_number_len;
    int ret = 1;
    uint8_t* report = hex2bin(report_hex, &report_len);
    uint8_t* pub_x = hex2bin(pub_x_hex, &pub_x_len);
    uint8_t* pub_y = hex2bin(pub_y_hex, &pub_y_len);
    uint8_t* usr_id = hex2bin(usr_id_hex, &usr_id_len);
    uint8_t* random_number = hex2bin(random_number_hex, &random_number_len);
    uint8_t* report_rn;
    int i = 0;

    if(!(pub_x_len == CSV_PUBKEY_LENGTH &&
    pub_y_len == CSV_PUBKEY_LENGTH &&
    usr_id_len == HYGON_USER_ID_SIZE)){
        printf("Params error.\n");
        printf("Params len: %lu, PUB KEY len: %u\n", pub_x_len, CSV_PUBKEY_LENGTH);
        printf("Params len: %lu, user id len: %u\n", usr_id_len, HYGON_USER_ID_SIZE);
        ret = -2;
        goto err;
    }

    struct csv_attestation_report csv_report;
    memcpy(&csv_report, report, sizeof(struct csv_attestation_report));
    if(random_number_len != GUEST_ATTESTATION_NONCE_SIZE){
        printf("Random Number error.\n");
        ret = -3;
        goto err;
    }
    report_rn = get_random_number(&csv_report);
    for(i = 0; i < GUEST_ATTESTATION_NONCE_SIZE; ++i){
        if(report_rn[i] != random_number[i]){
            printf("Random Number error.\n");
            ret = -3;
            goto err;
        }
    }

    ecc_pubkey_t ecc_pubkey;
    ecc_pubkey.curve_id = 3;
    memcpy((void*)&ecc_pubkey.Qx, pub_x, CSV_PUBKEY_LENGTH);
    memcpy((void*)&ecc_pubkey.Qy, pub_y, CSV_PUBKEY_LENGTH);
    memcpy((void*)&ecc_pubkey.user_id, usr_id, HYGON_USER_ID_SIZE);

    ret = csv_attestation_report_verify(&csv_report, &ecc_pubkey);

err:
    if(report)
        free(report);
    if(pub_x)
        free(pub_x);
    if(pub_y)
        free(pub_y);
    if(usr_id)
        free(usr_id);
    if(random_number)
        free(random_number);
    if(report_rn)
        free(report_rn);
    return ret;
}

// int main(void){
//     unsigned char buffer[3000];
//     char report_path[] = "report.cert";
//     char pek_path[] = "pek.cert";
//     char random_number_hex[] = "74a18b95e6d4f23a47a9ad1e99a043a5";
//     FILE* report_bin = fopen(report_path, "rb");
//     FILE* pek_bin = fopen(pek_path, "rb");
//     memset(buffer, 0, 3000);

//     fread(buffer, 1, 3000, report_bin);
//     struct csv_attestation_report report;
//     memcpy(&report, buffer, sizeof(struct csv_attestation_report));

//     char report_hex[6000];
//     memset(report_hex, 0, 6000);
//     dump_buffer2str(buffer, report_hex, 3000);

//     memset(buffer, 0, 3000);
//     fread(buffer, 1, 3000, pek_bin);
//     CSV_CERT_t pek_cert;
//     memcpy(&pek_cert, buffer, sizeof(CSV_CERT_t));
//     ecc_pubkey_t ecc_pubkey = pek_cert.ecc_pubkey;

//     uint8_t* pub_x = get_pub_x(buffer);
//     uint8_t* pub_y = get_pub_y(buffer);
//     char pub_x_hex[1000];
//     memset(pub_x_hex, 0, 1000);
//     char pub_y_hex[1000];
//     memset(pub_y_hex, 0, 1000);
//     char usr_id_hex[1000];
//     memset(usr_id_hex, 0, 1000);
//     dump_buffer2str(pub_x, pub_x_hex, CSV_PUBKEY_LENGTH);
//     dump_buffer2str(pub_y, pub_y_hex, CSV_PUBKEY_LENGTH);
//     dump_buffer2str((uint8_t*)(&ecc_pubkey.user_id), usr_id_hex, HYGON_USER_ID_SIZE);

//     int result = csv_do_verify(report_hex, pub_x_hex, pub_y_hex, usr_id_hex, random_number_hex);
//     printf("result:%d\n", result);

//     return 0;
// }