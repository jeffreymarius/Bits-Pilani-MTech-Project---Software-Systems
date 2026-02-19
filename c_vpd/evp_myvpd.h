#ifndef EVP_MYVPD_H
#define EVP_MYVPD_H

#include <openssl/evp.h>

void EVP_add_cipher_myvpd(void);
const EVP_CIPHER *EVP_myvpd(void);

#endif

