#include "openssl/conf.h"
#include "openssl/evp.h"
#include "openssl/sm2.h"
#include "openssl/ec.h"
#include "openssl/err.h"
#include "openssl/sm3.h"

#include <stdio.h>

#define CSV_PUBKEY_LENGTH 32

unsigned char* hex2bin(const char* hexstr)
{
    if(strlen(hexstr) != CSV_PUBKEY_LENGTH << 1)
        return NULL;
    size_t bytesLen = CSV_PUBKEY_LENGTH;

    unsigned char* bytes = (unsigned char*) malloc(bytesLen);

    int count = 0;
    const char* pos = hexstr;

    for(count = 0; count < bytesLen; count++) {
        sscanf(pos, "%2hhx", &bytes[count]);
        pos += 2;
    }

    return bytes;
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

EC_KEY* sm2_xy_to_ec_key(const char *x_point, const char *y_point) {
    EC_KEY *ec_key = EC_KEY_new();
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_sm2p256v1);
    EC_POINT *point = EC_POINT_new(group);
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    unsigned char* x_point_bin = hex2bin(x_point);
    unsigned char* y_point_bin = hex2bin(y_point);

    int ret = 0;

    if (ec_key == NULL) {
        fprintf(stderr, "Error creating EC_KEY\n");
        goto err;
    }
    
    if (group == NULL) {
        fprintf(stderr, "Error creating EC_GROUP\n");
        ret = 1;
        goto err;
    }

    if (EC_KEY_set_group(ec_key, group) != 1) {
        fprintf(stderr, "Error setting group for EC_KEY\n");
        ret = 1;
        goto err;
    }

    if (point == NULL) {
        fprintf(stderr, "Error creating EC_POINT\n");
        ret = 1;
        goto err;
    }

    if (x == NULL || y == NULL) {
        fprintf(stderr, "Error creating BIGNUM\n");
        ret = 1;
        goto err;
    }

    if(!x_point_bin || !y_point_bin){
        fprintf(stderr, "Error pubkey\n");
        ret = 1;
        goto err;
    }

    invert_endian(x_point_bin, CSV_PUBKEY_LENGTH);
    invert_endian(y_point_bin, CSV_PUBKEY_LENGTH);

    if (BN_bin2bn(x_point_bin, CSV_PUBKEY_LENGTH, x) == 0 || BN_bin2bn(y_point_bin, CSV_PUBKEY_LENGTH, y) == 0) {
        fprintf(stderr, "Error converting hex string to BIGNUM\n");
        ret = 1;
        goto err;
    }

    if (EC_POINT_set_affine_coordinates_GFp(group, point, x, y, NULL) != 1) {
        fprintf(stderr, "Error setting affine coordinates for EC_POINT\n");
        ret = 1;
        goto err;
    }

    if (EC_KEY_set_public_key(ec_key, point) != 1) {
        fprintf(stderr, "Error setting public key for EC_KEY\n");
        ret = 1;
        goto err;
    }

err:
    if(x)
        BN_free(x);
    if(y)
        BN_free(y);
    if(point)
        EC_POINT_free(point);
    if(group)
        EC_GROUP_free(group);
    if(x_point_bin)
        free(x_point_bin);
    if(y_point_bin)
        free(y_point_bin);  
    if(ret){
        EC_KEY_free(ec_key);
        ec_key = NULL;
    }
    return ec_key;
}

int main() {
    const char *x_point = "5250a6961c5ce8f3e5ce913a88db1b0bc35fcd60258da6aeac61a9dd526cdef9";
    const char *y_point = "dd4742c4b12b8334b9d7570e457efb359911e5ddf2ea24b1c6341954245204e2";


    EC_KEY *ec_key = sm2_xy_to_ec_key(x_point, y_point);
    if (ec_key == NULL) {
        fprintf(stderr, "Failed to convert SM2 public key to EC_KEY\n");
        return 1;
    }

    fprintf(stdout, "Succeed to convert SM2 public key to EC_KEY\n");

    EC_KEY_free(ec_key);

    return 0;
}
