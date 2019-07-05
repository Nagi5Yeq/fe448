#ifndef DEFS_H
#define DEFS_H

#include <stdint.h>
#include <stdlib.h>

typedef int8_t crypto_int8;
typedef uint8_t crypto_uint8;
typedef int16_t crypto_int16;
typedef uint16_t crypto_uint16;
typedef int32_t crypto_int32;
typedef uint32_t crypto_uint32;

int crypto_sign_ed448_keypair(unsigned char *pk, unsigned char *sk);

int crypto_sign_ed448_detached(unsigned char *sign, unsigned long long *smlen, const unsigned char *m, unsigned long long mlen, const unsigned char *sk);

#endif /* DEFS_H */
