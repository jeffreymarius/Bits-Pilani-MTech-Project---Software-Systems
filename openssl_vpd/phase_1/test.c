#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

extern const EVP_CIPHER *EVP_vpd(void);

int main() {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    /* ---- KEY ---- */
    unsigned char key[12000];
    memset(key, 0x11, sizeof(key));

    /* ---- PLAINTEXT ---- */
    unsigned char msg[] = "OMCI over TLS certificate authentication";
    int msg_len = strlen((char *)msg);

    unsigned char enc[256];
    unsigned char dec[256];
    int outlen1 = 0, outlen2 = 0;
    int declen1 = 0, declen2 = 0;

    /* ---- ENCRYPT ---- */
    EVP_EncryptInit_ex(ctx, EVP_vpd(), NULL, key, NULL);

    EVP_EncryptUpdate(ctx, enc, &outlen1, msg, msg_len);
    EVP_EncryptFinal_ex(ctx, enc + outlen1, &outlen2);

    int enc_len = outlen1 + outlen2;

    /* ---- DECRYPT ---- */
    EVP_DecryptInit_ex(ctx, EVP_vpd(), NULL, key, NULL);

    EVP_DecryptUpdate(ctx, dec, &declen1, enc, enc_len);
    EVP_DecryptFinal_ex(ctx, dec + declen1, &declen2);

    int dec_len = declen1 + declen2;
    dec[dec_len] = '\0';

    printf("Recovered: %s\n", dec);

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

