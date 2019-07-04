#ifndef FE448_H
#define FE448_H

#include "defs.h"

#define fe448              crypto_sign_ed448_ref_fe448
#define fe448_freeze       crypto_sign_ed448_ref_fe448_freeze
#define fe448_unpack       crypto_sign_ed448_ref_fe448_unpack
#define fe448_pack         crypto_sign_ed448_ref_fe448_pack
#define fe448_iszero       crypto_sign_ed448_ref_fe448_iszero
#define fe448_iseq_vartime crypto_sign_ed448_ref_fe448_iseq_vartime
#define fe448_cmov         crypto_sign_ed448_ref_fe448_cmov
#define fe448_setone       crypto_sign_ed448_ref_fe448_setone
#define fe448_setzero      crypto_sign_ed448_ref_fe448_setzero
#define fe448_neg          crypto_sign_ed448_ref_fe448_neg
#define fe448_getparity    crypto_sign_ed448_ref_fe448_getparity
#define fe448_add          crypto_sign_ed448_ref_fe448_add
#define fe448_sub          crypto_sign_ed448_ref_fe448_sub
#define fe448_mul          crypto_sign_ed448_ref_fe448_mul
#define fe448_square       crypto_sign_ed448_ref_fe448_square
#define fe448_invert       crypto_sign_ed448_ref_fe448_invert
#define fe448_pow2523      crypto_sign_ed448_ref_fe448_pow2523

typedef struct 
{
  crypto_uint32 v[57]; 
}
fe448;

void fe448_freeze(fe448 *r);

void fe448_unpack(fe448 *r, const unsigned char x[57]);

void fe448_pack(unsigned char r[57], const fe448 *x);

int fe448_iszero(const fe448 *x);

int fe448_iseq_vartime(const fe448 *x, const fe448 *y);

void fe448_cmov(fe448 *r, const fe448 *x, unsigned char b);

void fe448_setone(fe448 *r);

void fe448_setzero(fe448 *r);

void fe448_neg(fe448 *r, const fe448 *x);

unsigned char fe448_getparity(const fe448 *x);

void fe448_add(fe448 *r, const fe448 *x, const fe448 *y);

void fe448_sub(fe448 *r, const fe448 *x, const fe448 *y);

void fe448_mul(fe448 *r, const fe448 *x, const fe448 *y);

void fe448_square(fe448 *r, const fe448 *x);

void fe448_invert(fe448 *r, const fe448 *x);

void fe448_pow446(fe448 *r, const fe448 *x);

#endif
