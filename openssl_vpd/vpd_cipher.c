#include <openssl/core.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "vpd_core.h"

#include <openssl/crypto.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define NUM_KEYS 8

/* Cipher context */
typedef struct {
    unsigned char *buf;
    size_t buflen;
    size_t bufcap;
    int enc;   // 1 = encrypt, 0 = decrypt
    uint8_t **keys;
     int num_keys;
} VPD_CTX;

/* --------------------- New / Free --------------------- */

static void *vpd_newctx(void *provctx)
{
    VPD_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (!ctx)
        return NULL;

    ctx->num_keys = NUM_KEYS;
    ctx->keys = NULL; // allocated in vpd_init    
    ctx->buf = NULL;
    return ctx;
}

static void vpd_freectx(void *vctx)
{
	
    if (!vctx) return;
    VPD_CTX *ctx = (VPD_CTX *)vctx;

    OPENSSL_free(ctx->buf);
    if (ctx->keys) {
        for (int i = 0; i < ctx->num_keys; i++) {
            OPENSSL_free(ctx->keys[i]);
        }
        OPENSSL_free(ctx->keys);
        ctx->keys = NULL;
    }

    OPENSSL_free(ctx);

}

/* --------------------- Init --------------------- */
/*
static int vpd_init(void *vctx,
                    const unsigned char *key,
                    size_t keylen,
                    const unsigned char *iv,
                    size_t ivlen,
                    const OSSL_PARAM params[])
{
    VPD_CTX *ctx = vctx;

     if (!ctx) return 0;

    ctx->buf = NULL;
    ctx->buflen = 0;
    ctx->bufcap = 0;
    ctx->enc = (iv == NULL);  // OpenSSL convention

    if (key == NULL && keylen == 0) {
        return 1;
    }
    if (keylen != 32 && keylen != (size_t)-1) return 1;

// 1. If key is NULL, just return 1 to allow context setup
    // OpenSSL will call this again with the actual key later.
    if (key == NULL && params == NULL) {
        return 1; 
    }

// 2. Handle key from direct pointer
    if (key != NULL) {
        if (keylen != 32) {
            fprintf(stderr, "VPD: Expected 32 byte key, got %x\n", keylen);
            return 0; 
        }
    }
// 3. Handle key from params
    else if (params != NULL) {
        const OSSL_PARAM *p = OSSL_PARAM_locate_const(params, "key");
        if (p != NULL) {
            key = p->data;
            keylen = p->data_size;
        }
    }
 
if (key == NULL || (keylen != 32 && keylen != (size_t)-1)) {
        return 1; // Still waiting for the real key in a subsequent call
    }

    // 4. Only fail if we actually HAVE a key and it's the wrong size
//    if (key != NULL && keylen != 32) return 0;

    
    ctx->keys = OPENSSL_malloc(sizeof(uint8_t*) * ctx->num_keys);
    if (!ctx->keys) return 0;

    for (int i = 0; i < ctx->num_keys; i++) {
        ctx->keys[i] = OPENSSL_malloc(1500);
        if (!ctx->keys[i]) {
            // cleanup previous allocations
            for (int j = 0; j < i; j++) OPENSSL_free(ctx->keys[j]);
            OPENSSL_free(ctx->keys);
            ctx->keys = NULL;
            return 0;
        }

        // Fill keys safely
        for (int j = 0; j < 1500; j++) {
            ctx->keys[i][j] = key[(i + j) % keylen];
        }
    }

    return 1;
}
*/

/*
static int vpd_init(void *vctx, const unsigned char *key, size_t keylen,
                    const unsigned char *iv, size_t ivlen, const OSSL_PARAM params[])
{
    VPD_CTX *ctx = (VPD_CTX *)vctx;
    if (!ctx) return 0;

    // Record direction
    ctx->enc = (iv == NULL);

    // If key is NULL, OpenSSL is just initializing. Success.
    if (key == NULL) return 1;

    // If keylen is 0, ignore but success.
    if (keylen == 0) return 1;

    // ACTUAL KEY INITIALIZATION
    if (ctx->keys == NULL) {
        ctx->keys = OPENSSL_malloc(sizeof(uint8_t*) * 8);
        if (!ctx->keys) return 0;

        for (int i = 0; i < 8; i++) {
            ctx->keys[i] = OPENSSL_malloc(1500);
            if (!ctx->keys[i]) return 0;

            for (int j = 0; j < 1500; j++) {
                ctx->keys[i][j] = key[(i + j) % 32];
            }
        }
        fprintf(stderr, "DEBUG: Keys initialized for ctx %p\n", (void*)ctx);
    }
    return 1;
}
*/
static int vpd_init(void *vctx, const unsigned char *key, size_t keylen,
                    const unsigned char *iv, size_t ivlen, const OSSL_PARAM params[])
{
fprintf(stderr, "TRACE: vpd_init called | key: %p | keylen: %zu\n", (void*)key, keylen);

    VPD_CTX *ctx = (VPD_CTX *)vctx;
    if (!ctx) return 0;

    // IF KEY IS NULL, WE MUST RETURN 1 IMMEDIATELY
    if (key == NULL) {
        fprintf(stderr, "TRACE: Handshake successful (key is NULL)\n");
        return 1;
    }

    // NOW check keylen for the ACTUAL key
size_t effective_keylen = (keylen == 0) ? 32 : keylen;

    if (effective_keylen != 32) {
        fprintf(stderr, "VPD Error: Expected 32 byte key, got %zu\n", keylen);
        return 0;
    }    

    // 4. Initialize your internal keys
    if (ctx->keys == NULL) {
        ctx->keys = OPENSSL_malloc(sizeof(uint8_t*) * 8);
        if (!ctx->keys) return 0;

        for (int i = 0; i < 8; i++) {
            ctx->keys[i] = OPENSSL_malloc(1500);
            if (!ctx->keys[i]) return 0;

            for (int j = 0; j < 1500; j++) {
                ctx->keys[i][j] = key[(i + j) % 32];
            }
        }
        fprintf(stderr, "DEBUG: Keys initialized successfully from -K\n");
    }

    return 1;
}

static int vpd_e_init(void *vctx, const unsigned char *key, size_t keylen,
                      const unsigned char *iv, size_t ivlen, const OSSL_PARAM params[])
{
    VPD_CTX *ctx = (VPD_CTX *)vctx;
    if (ctx) ctx->enc = 1; // 1 for Encrypt
    return vpd_init(vctx, key, keylen, iv, ivlen, params);
}

static int vpd_d_init(void *vctx, const unsigned char *key, size_t keylen,
                      const unsigned char *iv, size_t ivlen, const OSSL_PARAM params[])
{
    VPD_CTX *ctx = (VPD_CTX *)vctx;
    if (ctx) ctx->enc = 0; // 0 for Decrypt
    return vpd_init(vctx, key, keylen, iv, ivlen, params);
}

/* --------------------- Update --------------------- */


static int vpd_update(void *vctx,
                      unsigned char *out, size_t *outl,
                      size_t outsize,
                      const unsigned char *in, size_t inl)
{
    VPD_CTX *ctx = vctx;

    if (ctx->buflen + inl > ctx->bufcap) {
        size_t newcap = ctx->bufcap ? ctx->bufcap * 2 : 1024;
        while (newcap < ctx->buflen + inl)
            newcap *= 2;

        ctx->buf = OPENSSL_realloc(ctx->buf, newcap);
        ctx->bufcap = newcap;
    }

    memcpy(ctx->buf + ctx->buflen, in, inl);
    ctx->buflen += inl;

    *outl = 0;
    return 1;
}

/* --------------------- Final --------------------- */
/*
static int vpd_final(void *vctx,
                     unsigned char *out, size_t *outl,
                     size_t outsize)
{
    VPD_CTX *ctx = (VPD_CTX *)vctx;
    fprintf(stderr, "DEBUG: Entering vpd_final. Buflen: %zu, Outsize: %zu\n", ctx->buflen, outsize);
    if (out == NULL) {
        *outl = ctx->buflen; 
        return 1; // Success!
    }

    fprintf(stderr, "DEBUG: Finalizing. Buflen: %zu, Outsize: %zu\n", ctx->buflen, outsize);

    if (!ctx || ctx->keys == NULL || ctx->buflen == 0) 
    {
	    fprintf(stderr, "DEBUG: Keys are NULL!\n");
	    return 0;
    }
    uint8_t *res = process_vpd(ctx->buf, ctx->buflen, ctx->keys, ctx->enc);
    if (!res) {
	    fprintf(stderr, "DEBUG: process_vpd returned NULL!\n");
	    return 0;
    }

    if (outsize < ctx->buflen) {
        fprintf(stderr, "DEBUG: Outsize too small! %zu < %zu\n", outsize, ctx->buflen);
        free(res);
        return 0;
    }
    memcpy(out, res, ctx->buflen);
    *outl = ctx->buflen;
    fprintf(stderr, "DEBUG: vpd_final Success. Outputting %zu bytes\n", *outl);
    free(res); // Standard free is fine here
    return 1;
}
*/

static int vpd_final(void *vctx, unsigned char *out, size_t *outl, size_t outsize)
{
    VPD_CTX *ctx = (VPD_CTX *)vctx;

    // If out is NULL, OpenSSL is asking for the size
    if (out == NULL) {
        *outl = ctx->buflen;
        return 1;
    }

    // Now we are actually encrypting/decrypting
    if (!ctx->keys) {
        fprintf(stderr, "DEBUG: Keys are still NULL in Final!\n");
        return 0;
    }

    uint8_t *res = process_vpd(ctx->buf, ctx->buflen, ctx->keys, ctx->enc);
    if (!res) return 0;

    memcpy(out, res, ctx->buflen);
    *outl = ctx->buflen;

    free(res);
    return 1;
}

/* --------------------- Get Params --------------------- */

static int vpd_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, 1))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, 32))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, 0))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE);
    if (p != NULL && !OSSL_PARAM_set_uint(p, EVP_CIPH_STREAM_CIPHER))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_PADDING);
    if (p != NULL && !OSSL_PARAM_set_uint(p, 0)) 
        return 0;

    return 1;
}

static void *vpd_dupctx(void *vctx)
{
    VPD_CTX *old = (VPD_CTX *)vctx;
    VPD_CTX *new = vpd_newctx(NULL);

    if (new == NULL) return NULL;

    fprintf(stderr, "DEBUG: Duplicating ctx from %p to %p\n", (void*)old, (void*)new);

    new->enc = old->enc;
    new->num_keys = old->num_keys;

    // Copy keys if they exist
    if (old->keys) {
        new->keys = OPENSSL_malloc(sizeof(uint8_t*) * 8);
        for (int i = 0; i < 8; i++) {
            new->keys[i] = OPENSSL_malloc(1500);
            memcpy(new->keys[i], old->keys[i], 1500);
        }
    }

    // Copy buffer if it exists
    if (old->buflen > 0) {
        new->buf = OPENSSL_malloc(old->bufcap);
        memcpy(new->buf, old->buf, old->buflen);
        new->buflen = old->buflen;
        new->bufcap = old->bufcap;
    }

    return new;
}


/* --------------------- Dispatch Table --------------------- */
const OSSL_DISPATCH vpd_cipher_functions[] = {
    { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))vpd_newctx },
    { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))vpd_freectx },

    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))vpd_e_init },
    { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))vpd_d_init },

    { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))vpd_update },
    { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))vpd_final },

    { OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void))vpd_get_params },
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (void (*)(void))vpd_get_params },
    { OSSL_FUNC_CIPHER_DUPCTX, (void (*)(void))vpd_dupctx },
    { 0, NULL }
};

