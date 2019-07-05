#ifndef SC448_H
#define SC448_H

#include "defs.h"

#define sc448                  crypto_sign_ed448_ref_sc448
#define sc448_from57bytes      crypto_sign_ed448_ref_sc448_from57bytes
#define sc448_from114bytes     crypto_sign_ed448_ref_sc448_from114bytes
#define sc448_to57bytes        crypto_sign_ed448_ref_sc448_to57bytes
#define sc448_iszero_vartime   crypto_sign_ed448_ref_sc448_iszero_vartime
#define sc448_isshort_vartime  crypto_sign_ed448_ref_sc448_isshort_vartime
#define sc448_lt_vartime       crypto_sign_ed448_ref_sc448_lt_vartime
#define sc448_add              crypto_sign_ed448_ref_sc448_add
#define sc448_sub_nored        crypto_sign_ed448_ref_sc448_sub_nored
#define sc448_mul              crypto_sign_ed448_ref_sc448_mul
#define sc448_window3          crypto_sign_ed448_ref_sc448_window3
#define sc448_2interleave2     crypto_sign_ed448_ref_sc448_2interleave2

typedef struct 
{
  crypto_uint32 v[57]; 
}
sc448;

void sc448_from57bytes(sc448 *r, const unsigned char x[57]);

void sc448_from114bytes(sc448 *r, const unsigned char x[114]);

void sc448_to57bytes(unsigned char r[57], const sc448 *x);

int sc448_iszero_vartime(const sc448 *x);

int sc448_isshort_vartime(const sc448 *x);

int sc448_lt_vartime(const sc448 *x, const sc448 *y);

void sc448_add(sc448 *r, const sc448 *x, const sc448 *y);

void sc448_sub_nored(sc448 *r, const sc448 *x, const sc448 *y);

void sc448_mul(sc448 *r, const sc448 *x, const sc448 *y);

/* Convert s into a representation of the form \sum_{i=0}^{84}r[i]2^3
 * with r[i] in {-4,...,3}
 */
void sc448_window3(signed char r[150], const sc448 *s);

void sc448_2interleave2(unsigned char r[223], const sc448 *s1, const sc448 *s2);

#endif
