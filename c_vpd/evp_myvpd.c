#include <openssl/evp.h>
#include <openssl/objects.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

/* ===================== CONFIG ===================== */

#define VPD_KEY_PARTS 8
#define VPD_MIN_KEYLEN 8     /* MUST be non-zero */
#define VPD_BLOCK_SIZE 1     /* Stream-style */

/* ===================== IMAGE TYPE ===================== */

typedef struct {
    uint8_t ***px;
    int h, w;
} Image;

/* ===================== SAFE ALLOC ===================== */

static Image image_alloc(int h, int w) {
    Image img;
    img.h = h;
    img.w = w;
    img.px = calloc(h, sizeof(uint8_t **));
    for (int i = 0; i < h; i++) {
        img.px[i] = calloc(w, sizeof(uint8_t *));
        for (int j = 0; j < w; j++) {
            img.px[i][j] = calloc(3, 1);
        }
    }
    return img;
}

static void image_free(Image *img) {
    for (int i = 0; i < img->h; i++) {
        for (int j = 0; j < img->w; j++)
            free(img->px[i][j]);
        free(img->px[i]);
    }
    free(img->px);
}

/* ===================== BYTE <-> IMAGE ===================== */

static Image bytes_to_image(const uint8_t *data, int len, int *origLen) {
    *origLen = len;
    int pixels = (len + 2) / 3;
    int w = (int)(sqrt(pixels) + 1);
    int h = (pixels + w - 1) / w;

    Image img = image_alloc(h, w);
    int idx = 0;

    for (int i = 0; i < h; i++)
        for (int j = 0; j < w; j++)
            for (int k = 0; k < 3; k++)
                if (idx < len)
                    img.px[i][j][k] = data[idx++];

    return img;
}

static uint8_t *image_to_bytes(Image *img, int origLen) {
    uint8_t *out = malloc(origLen);
    int idx = 0;

    for (int i = 0; i < img->h && idx < origLen; i++)
        for (int j = 0; j < img->w && idx < origLen; j++)
            for (int k = 0; k < 3 && idx < origLen; k++)
                out[idx++] = img->px[i][j][k];

    return out;
}

/* ===================== VPD XOR ===================== */

static void vpd_encrypt(uint8_t *buf, int len) {
    for (int i = 1; i < len; i++)
        buf[i] ^= buf[i - 1];
}

static void vpd_decrypt(uint8_t *buf, int len) {
    for (int i = len - 1; i > 0; i--)
        buf[i] ^= buf[i - 1];
}

/* ===================== ZIGZAG XOR ===================== */

static void zigzag(Image *img, const uint8_t *K, int klen, int origLen) {
    int idx = 0;
    if (klen == 0) return;  /* SAFETY */

    for (int i = 0; i < img->h; i++)
        for (int j = 0; j < img->w; j++)
            for (int k = 0; k < 3 && idx < origLen; k++)
                img->px[i][j][k] ^= K[idx++ % klen];
}

/* ===================== PLANET DOMAIN ===================== */

#define planet zigzag
#define planet_dec zigzag

/* ===================== INTERSHUFFLING ===================== */

static void intershuffle(Image *img, const uint8_t *K1, int k1,
                         const uint8_t *K2, int k2,
                         const uint8_t *K3, int k3,
                         int origLen) {
    if (k1 == 0 || k2 == 0 || k3 == 0) return;

    int idx = 0;
    for (int i = 0; i < img->h && idx < origLen; i++)
        for (int j = 0; j < img->w && idx < origLen; j++)
            for (int k = 0; k < 3 && idx < origLen; k++, idx++) {
                int ni = K1[i % k1] % img->h;
                int nj = K2[j % k2] % img->w;
                int nk = K3[k % k3] % 3;

                uint8_t tmp = img->px[i][j][k];
                img->px[i][j][k] = img->px[ni][nj][nk];
                img->px[ni][nj][nk] = tmp;
            }
}

static void reverse_intershuffle(Image *img, const uint8_t *K1, int k1,
                                 const uint8_t *K2, int k2,
                                 const uint8_t *K3, int k3,
                                 int origLen) {
    if (k1 == 0 || k2 == 0 || k3 == 0) return;

    for (int i = img->h - 1; i >= 0; i--)
        for (int j = img->w - 1; j >= 0; j--)
            for (int k = 2; k >= 0; k--) {
                int idx = i * img->w * 3 + j * 3 + k;
                if (idx >= origLen) continue;

                int ni = K1[i % k1] % img->h;
                int nj = K2[j % k2] % img->w;
                int nk = K3[k % k3] % 3;

                uint8_t tmp = img->px[i][j][k];
                img->px[i][j][k] = img->px[ni][nj][nk];
                img->px[ni][nj][nk] = tmp;
            }
}

/* ===================== EVP CONTEXT ===================== */

typedef struct {
    uint8_t *key;
    int keylen;
    int enc;
} VPD_CTX;

/* ===================== CORE CIPHER ===================== */

static int vpd_do_cipher(EVP_CIPHER_CTX *ctx,
                         unsigned char *out,
                         const unsigned char *in,
                         size_t len) {
    VPD_CTX *vctx = EVP_CIPHER_CTX_get_cipher_data(ctx);
    if (!vctx || vctx->keylen < VPD_MIN_KEYLEN)
        return 0;

    int origLen;
    Image img = bytes_to_image(in, len, &origLen);

    const uint8_t *K = vctx->key;
    int seg = vctx->keylen / VPD_KEY_PARTS;
    if (seg == 0) seg = 1;

    const uint8_t *K0 = K + seg * 0;
    const uint8_t *K1 = K + seg * 1;
    const uint8_t *K2 = K + seg * 2;
    const uint8_t *K3 = K + seg * 3;
    const uint8_t *K4 = K + seg * 4;
    const uint8_t *K5 = K + seg * 5;
    const uint8_t *K6 = K + seg * 6;
    const uint8_t *K7 = K + seg * 7;

    uint8_t *buf = image_to_bytes(&img, origLen);

    if (vctx->enc) {
        vpd_encrypt(buf, origLen);
        zigzag(&img, K3, seg, origLen);
        intershuffle(&img, K0, seg, K1, seg, K2, seg, origLen);
        planet(&img, K7, seg, origLen);
    } else {
        planet_dec(&img, K7, seg, origLen);
        reverse_intershuffle(&img, K0, seg, K1, seg, K2, seg, origLen);
        zigzag(&img, K3, seg, origLen);
        vpd_decrypt(buf, origLen);
    }

    memcpy(out, buf, len);
    free(buf);
    image_free(&img);
    return 1;
}

/* ===================== EVP GLUE ===================== */

static int vpd_init(EVP_CIPHER_CTX *ctx,
                    const unsigned char *key,
                    const unsigned char *iv,
                    int enc) {
    VPD_CTX *vctx = EVP_CIPHER_CTX_get_cipher_data(ctx);
    vctx->key = (uint8_t *)key;
    vctx->keylen = EVP_CIPHER_CTX_key_length(ctx);
    vctx->enc = enc;
    return 1;
}

static EVP_CIPHER *vpd_cipher(void) {
    static EVP_CIPHER *cipher = NULL;
    if (cipher) return cipher;

    cipher = EVP_CIPHER_meth_new(NID_undef, VPD_BLOCK_SIZE, 32);
    EVP_CIPHER_meth_set_iv_length(cipher, 0);
    EVP_CIPHER_meth_set_flags(cipher, EVP_CIPH_STREAM_CIPHER);
    EVP_CIPHER_meth_set_init(cipher, vpd_init);
    EVP_CIPHER_meth_set_do_cipher(cipher, vpd_do_cipher);
    EVP_CIPHER_meth_set_impl_ctx_size(cipher, sizeof(VPD_CTX));
    return cipher;
}

/* ===================== REGISTRATION ===================== */

void EVP_add_vpd(void) {
    EVP_add_cipher(vpd_cipher());
}

