#ifndef VPD_CORE_H
#define VPD_CORE_H

#include <stdint.h>

uint8_t *encrypt_bytes(uint8_t *data, int len, uint8_t **keys);
uint8_t *decrypt_bytes(uint8_t *data, int len, uint8_t **keys);

#endif

