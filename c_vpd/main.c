#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include "evp_myvpd.h"

int main() {
    EVP_add_cipher_myvpd();

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    const char *msg = "OMCI over TLS certificate authentication";
    unsigned char out[256], back[256];
    int outl, backl;

    printf("%s\n",msg);
    EVP_EncryptInit_ex(ctx, EVP_myvpd(), NULL, NULL, NULL);
    EVP_EncryptUpdate(ctx, out, &outl, (unsigned char*)msg, strlen(msg));
    EVP_EncryptFinal_ex(ctx, out+outl, &outl);

    EVP_DecryptInit_ex(ctx, EVP_myvpd(), NULL, NULL, NULL);
    EVP_DecryptUpdate(ctx, back, &backl, out, strlen(msg));
    EVP_DecryptFinal_ex(ctx, back+backl, &backl);

    back[strlen(msg)] = 0;
    printf("Recovered: %s\n", back);
}

