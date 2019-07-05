#ifndef GE448_H
#define GE448_H

#include "fe448.h"
#include "sc448.h"

#define ge448                           crypto_sign_ge448
#define ge448_base                      crypto_sign_ge448_base
#define ge448_unpackneg_vartime         crypto_sign_unpackneg_vartime
#define ge448_pack                      crypto_sign_pack
#define ge448_isneutral_vartime         crypto_sign_isneutral_vartime
#define ge448_double_scalarmult_vartime crypto_sign_double_scalarmult_vartime
#define ge448_scalarmult_base           crypto_sign_scalarmult_base

typedef struct
{
  fe448 x;
  fe448 y;
  fe448 z;
} ge448;

extern const ge448 ge448_base;

int ge448_unpackneg_vartime(ge448 *r, const unsigned char p[57]);

void ge448_pack(unsigned char r[57], const ge448 *p);

int ge448_isneutral_vartime(const ge448 *p);

void ge448_double_scalarmult_vartime(ge448 *r, const ge448 *p1, const sc448 *s1, const ge448 *p2, const sc448 *s2);

void ge448_scalarmult_base(ge448 *r, const sc448 *s);

#endif
