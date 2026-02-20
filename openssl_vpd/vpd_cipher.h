#ifndef VPD_CIPHER_H
#define VPD_CIPHER_H

#include <openssl/core.h>

/* Dispatch table for the VPD cipher */
extern const OSSL_DISPATCH vpd_cipher_functions[];

/* Algorithm table exposed to OpenSSL core */
extern const OSSL_ALGORITHM vpd_ciphers[];

#endif

