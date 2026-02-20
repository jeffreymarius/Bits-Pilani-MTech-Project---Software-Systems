#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>
#include "vpd_core.h"

typedef struct {
    uint8_t *keys[8];
    int segment;
} VPD_CTX;

static int vpd_init(EVP_CIPHER_CTX *ctx,
                    const unsigned char *key,
                    const unsigned char *iv,
                    int enc)
{
    VPD_CTX *c = EVP_CIPHER_CTX_get_cipher_data(ctx);
    int keylen = EVP_CIPHER_CTX_key_length(ctx);

    c->segment = keylen / 8;

    for (int i = 0; i < 8; i++) {
        c->keys[i] = malloc(c->segment);
        memcpy(c->keys[i], key + i * c->segment, c->segment);
    }
    return 1;
}

static int vpd_do_cipher(EVP_CIPHER_CTX *ctx,
                         unsigned char *out,
                         const unsigned char *in,
                         size_t inlen)
{
    VPD_CTX *c = EVP_CIPHER_CTX_get_cipher_data(ctx);

    uint8_t *tmp = malloc(inlen);
    memcpy(tmp, in, inlen);

    uint8_t *res;
    if (EVP_CIPHER_CTX_encrypting(ctx))
        res = encrypt_bytes(tmp, inlen, c->keys);
    else
        res = decrypt_bytes(tmp, inlen, c->keys);

    memcpy(out, res, inlen);

    free(tmp);
    free(res);
    return 1;
}

static int vpd_cleanup(EVP_CIPHER_CTX *ctx)
{
    VPD_CTX *c = EVP_CIPHER_CTX_get_cipher_data(ctx);
    for (int i = 0; i < 8; i++)
        free(c->keys[i]);
    return 1;
}

const EVP_CIPHER *EVP_vpd(void)
{
    static EVP_CIPHER *cipher = NULL;
    if (cipher)
        return cipher;

    cipher = EVP_CIPHER_meth_new(NID_undef, 1, 12000);
    EVP_CIPHER_meth_set_iv_length(cipher, 0);
    EVP_CIPHER_meth_set_flags(cipher, EVP_CIPH_STREAM_CIPHER);
    EVP_CIPHER_meth_set_init(cipher, vpd_init);
    EVP_CIPHER_meth_set_do_cipher(cipher, vpd_do_cipher);
    EVP_CIPHER_meth_set_cleanup(cipher, vpd_cleanup);
    EVP_CIPHER_meth_set_impl_ctx_size(cipher, sizeof(VPD_CTX));
    return cipher;
}

