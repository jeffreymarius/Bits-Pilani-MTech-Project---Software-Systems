#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>

/* ---------------------------- Helper: Key Slicing ---------------------------- */

// Converts a byte key into a u64 array for shuffling math
static uint64_t *slice_to_u64(const uint8_t *data, int dlen, int len) {
    uint64_t *out = (uint64_t *)malloc(len * sizeof(uint64_t));
    if (!out) return NULL;

    if (dlen <= 0) {
        memset(out, 0, len * sizeof(uint64_t));
        return out;
    }

    for (int i = 0; i < len; i++) {
        out[i] = (uint64_t)data[i % dlen];
    }
    return out;
}

/* ---------------------------- VPD Transformation ---------------------------- */

// Cumulative XOR: The core VPD logic
static void vpd_transform(uint8_t *data, int len, int encrypt) {
    if (encrypt) {
        // Forward XOR
        for (int i = 1; i < len; i++) {
            data[i] ^= data[i - 1];
        }
    } else {
        // Backward XOR
        for (int i = len - 1; i > 0; i--) {
            data[i] ^= data[i - 1];
        }
    }
}

/* ---------------------------- Flat Intershuffle ---------------------------- */

// Shuffles bytes based on key values using 1D index math
static void flat_shuffle(uint8_t *data, int h, int w, uint64_t *K1, uint64_t *K2, uint64_t *K3, int len, int reverse) {
    // To reverse a shuffle, we must perform the exact same swaps in reverse order
    int start = reverse ? len - 1 : 0;
    int end   = reverse ? -1 : len;
    int step  = reverse ? -1 : 1;

    for (int idx = start; idx != end; idx += step) {
        // Map 1D index to virtual 3D coordinates (row, col, channel)
        int i = idx / (w * 3);
        int j = (idx / 3) % w;
        int k = idx % 3;

        // Calculate target coordinates based on key slices
        int ni = (K1[i] % 256) % h;
        int nj = (K2[j] % 256) % w;
        int nk = (K3[k] % 3);

        // Map target 3D coordinates back to a 1D target index
        int target_idx = (ni * w * 3) + (nj * 3) + nk;

        if (target_idx < len) {
            uint8_t temp = data[idx];
            data[idx] = data[target_idx];
            data[target_idx] = temp;
        }
    }
}

/* ---------------------------- Main Entry Points ---------------------------- */

// Main wrapper to handle the rounds of encryption/decryption
uint8_t *process_vpd(const uint8_t *data, int len, uint8_t **keys, int encrypt) {
    if (len <= 0 || !keys) return NULL;

    // 1. Determine virtual image dimensions
    int numPixels = (len + 2) / 3;
    int w = (int)ceil(sqrt((double)numPixels));
    int h = (numPixels + w - 1) / w;

    // 2. Allocate output buffer
    uint8_t *work = (uint8_t *)malloc(len);
    if (!work) return NULL;
    memcpy(work, data, len);

    // 3. Prepare Key Slices for Shuffling
    uint64_t *K0 = slice_to_u64(keys[0], 32, h);
    uint64_t *K1 = slice_to_u64(keys[1], 32, w);
    uint64_t *K2 = slice_to_u64(keys[2], 32, 3);
    uint64_t *K4 = slice_to_u64(keys[4], 32, h);
    uint64_t *K5 = slice_to_u64(keys[5], 32, w);
    uint64_t *K6 = slice_to_u64(keys[6], 32, 3);

    if (encrypt) {
        // --- Round 1 ---
        vpd_transform(work, len, 1);
        flat_shuffle(work, h, w, K0, K1, K2, len, 0);
        for (int i = 0; i < len; i++) work[i] ^= keys[3][i % 32]; // Zigzag XOR

        // --- Round 2 ---
        vpd_transform(work, len, 1);
        flat_shuffle(work, h, w, K4, K5, K6, len, 0);
        for (int i = 0; i < len; i++) work[i] ^= keys[3][i % 32];

        // --- Final Round ---
        vpd_transform(work, len, 1);
        for (int i = 0; i < len; i++) work[i] ^= keys[7][i % 32];

    } else {
        // --- Reverse Round 3 ---
        for (int i = 0; i < len; i++) work[i] ^= keys[7][i % 32];
        vpd_transform(work, len, 0);

        // --- Reverse Round 2 ---
        for (int i = 0; i < len; i++) work[i] ^= keys[3][i % 32];
        flat_shuffle(work, h, w, K4, K5, K6, len, 1); // Reverse shuffle
        vpd_transform(work, len, 0);

        // --- Reverse Round 1 ---
        for (int i = 0; i < len; i++) work[i] ^= keys[3][i % 32];
        flat_shuffle(work, h, w, K0, K1, K2, len, 1); // Reverse shuffle
        vpd_transform(work, len, 0);
    }

    // Cleanup
    free(K0); free(K1); free(K2);
    free(K4); free(K5); free(K6);

    return work;
}

// OpenSSL Provider compatible wrappers
uint8_t *encrypt_bytes(uint8_t *data, int len, uint8_t **keys) {
    return process_vpd(data, len, keys, 1);
}

uint8_t *decrypt_bytes(uint8_t *data, int len, uint8_t **keys) {
    return process_vpd(data, len, keys, 0);
}


