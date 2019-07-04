#include "sc448.h"

/* order of base point of Ed448-Goldilocks: 2**446-13818066809895115352007386748515426880336692474882178609894547503885 */

static const crypto_uint32 m[57] = {0xF3, 0x44, 0x58, 0xAB, 0x92, 0xC2, 0x78, 0x23, 0x55, 0x8F, 0xC5, 0x8D, 0x72, 0xC2, 0x6C, 0x21,
                                    0x90, 0x36, 0xD6, 0xAE, 0x49, 0xDB, 0x4E, 0xC4, 0xE9, 0x23, 0xCA, 0x7C, 0xFF, 0xFF, 0xFF, 0xFF,
                                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x3F, 0x00};

/* 256**114//m */
static const crypto_uint32 mu[59] = {0x0A, 0xD0, 0xE0, 0xB0, 0x7B, 0x4A, 0xD5, 0xD6, 0x73, 0xC8, 0xAD, 0x0A, 0xA7, 0x23, 0xD7, 0xD8,
                                     0x33, 0xE9, 0xFD, 0x96, 0x9C, 0x12, 0x65, 0x4B, 0x12, 0xBB, 0x63, 0xC1, 0x5D, 0x33, 0x08, 0x00,
                                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04};

static crypto_uint32 lt(crypto_uint32 a, crypto_uint32 b) /* 16-bit inputs */
{
  unsigned int x = a;
  x -= (unsigned int)b; /* 0..65535: no; 4294901761..4294967295: yes */
  x >>= 31;             /* 0: no; 1: yes */
  return x;
}

/* Reduce coefficients of r before calling reduce_add_sub */
static void reduce_add_sub(sc448 *r)
{
  crypto_uint32 pb = 0;
  crypto_uint32 b;
  crypto_uint32 mask;
  int i;
  unsigned char t[57];

  for (i = 0; i < 57; i++)
  {
    pb += m[i];
    b = lt(r->v[i], pb);
    t[i] = r->v[i] - pb + (b << 8);
    pb = b;
  }
  mask = b - 1;
  for (i = 0; i < 57; i++)
    r->v[i] ^= mask & (r->v[i] ^ t[i]);
}

/* Reduce coefficients of x before calling barrett_reduce */
static void barrett_reduce(sc448 *r, const crypto_uint32 x[114])
{
  /* See HAC, Alg. 14.42 */
  int i, j;
  crypto_uint32 q2[116];
  crypto_uint32 *q3 = q2 + 58;
  crypto_uint32 r1[58];
  crypto_uint32 r2[58];
  crypto_uint32 carry;
  crypto_uint32 pb = 0;
  crypto_uint32 b;

  for (i = 0; i < 116; ++i)
    q2[i] = 0;
  for (i = 0; i < 58; ++i)
    r2[i] = 0;

  for (i = 0; i < 59; i++)
    for (j = 0; j < 58; j++)
      if (i + j >= 56)
        q2[i + j] += mu[i] * x[j + 56];
  carry = q2[56] >> 8;
  q2[57] += carry;
  carry = q2[57] >> 8;
  q2[58] += carry;

  for (i = 0; i < 58; i++)
    r1[i] = x[i];
  for (i = 0; i < 57; i++)
    for (j = 0; j < 58; j++)
      if (i + j < 58)
        r2[i + j] += m[i] * q3[j];

  for (i = 0; i < 57; i++)
  {
    carry = r2[i] >> 8;
    r2[i + 1] += carry;
    r2[i] &= 0xff;
  }

  for (i = 0; i < 57; i++)
  {
    pb += r2[i];
    b = lt(r1[i], pb);
    r->v[i] = r1[i] - pb + (b << 8);
    pb = b;
  }

  /* XXX: Can it really happen that r<0?, See HAC, Alg 14.42, Step 3 
   * If so: Handle  it here!
   */

  reduce_add_sub(r);
  reduce_add_sub(r);
  reduce_add_sub(r);
  reduce_add_sub(r);
}

void sc448_from57bytes(sc448 *r, const unsigned char x[57])
{
  int i;
  crypto_uint32 t[114];
  for (i = 0; i < 57; i++)
    t[i] = x[i];
  for (i = 57; i < 114; ++i)
    t[i] = 0;
  barrett_reduce(r, t);
}

void sc448_from114bytes(sc448 *r, const unsigned char x[114])
{
  int i;
  crypto_uint32 t[114];
  for (i = 0; i < 114; i++)
    t[i] = x[i];
  barrett_reduce(r, t);
}

void sc448_to57bytes(unsigned char r[57], const sc448 *x)
{
  int i;
  for (i = 0; i < 57; i++)
    r[i] = x->v[i];
}

int sc448_iszero_vartime(const sc448 *x)
{
  int i;
  for (i = 0; i < 57; i++)
    if (x->v[i] != 0)
      return 0;
  return 1;
}

int sc448_lt_vartime(const sc448 *x, const sc448 *y)
{
  int i;
  for (i = 56; i >= 0; i--)
  {
    if (x->v[i] < y->v[i])
      return 1;
    if (x->v[i] > y->v[i])
      return 0;
  }
  return 0;
}

void sc448_add(sc448 *r, const sc448 *x, const sc448 *y)
{
  int i, carry;
  for (i = 0; i < 57; i++)
    r->v[i] = x->v[i] + y->v[i];
  for (i = 0; i < 56; i++)
  {
    carry = r->v[i] >> 8;
    r->v[i + 1] += carry;
    r->v[i] &= 0xff;
  }
  reduce_add_sub(r);
}

void sc448_sub_nored(sc448 *r, const sc448 *x, const sc448 *y)
{
  crypto_uint32 b = 0;
  crypto_uint32 t;
  int i;
  for (i = 0; i < 57; i++)
  {
    t = x->v[i] - y->v[i] - b;
    r->v[i] = t & 255;
    b = (t >> 8) & 1;
  }
}

void sc448_mul(sc448 *r, const sc448 *x, const sc448 *y)
{
  int i, j, carry;
  crypto_uint32 t[114];
  for (i = 0; i < 114; i++)
    t[i] = 0;

  for (i = 0; i < 57; i++)
    for (j = 0; j < 57; j++)
      t[i + j] += x->v[i] * y->v[j];

  /* Reduce coefficients */
  for (i = 0; i < 113; i++)
  {
    carry = t[i] >> 8;
    t[i + 1] += carry;
    t[i] &= 0xff;
  }

  barrett_reduce(r, t);
}
 /* not implemented yet */
#if 0
void sc25519_window3(signed char r[85], const sc25519 *s)
{
    char carry;
    int i;
    for (i = 0; i < 10; i++)
    {
        r[8 * i + 0] = s->v[3 * i + 0] & 7;
        r[8 * i + 1] = (s->v[3 * i + 0] >> 3) & 7;
        r[8 * i + 2] = (s->v[3 * i + 0] >> 6) & 7;
        r[8 * i + 2] ^= (s->v[3 * i + 1] << 2) & 7;
        r[8 * i + 3] = (s->v[3 * i + 1] >> 1) & 7;
        r[8 * i + 4] = (s->v[3 * i + 1] >> 4) & 7;
        r[8 * i + 5] = (s->v[3 * i + 1] >> 7) & 7;
        r[8 * i + 5] ^= (s->v[3 * i + 2] << 1) & 7;
        r[8 * i + 6] = (s->v[3 * i + 2] >> 2) & 7;
        r[8 * i + 7] = (s->v[3 * i + 2] >> 5) & 7;
    }
    r[8 * i + 0] = s->v[3 * i + 0] & 7;
    r[8 * i + 1] = (s->v[3 * i + 0] >> 3) & 7;
    r[8 * i + 2] = (s->v[3 * i + 0] >> 6) & 7;
    r[8 * i + 2] ^= (s->v[3 * i + 1] << 2) & 7;
    r[8 * i + 3] = (s->v[3 * i + 1] >> 1) & 7;
    r[8 * i + 4] = (s->v[3 * i + 1] >> 4) & 7;

    /* Making it signed */
    carry = 0;
    for (i = 0; i < 84; i++)
    {
        r[i] += carry;
        r[i + 1] += r[i] >> 3;
        r[i] &= 7;
        carry = r[i] >> 2;
        r[i] -= carry << 3;
    }
    r[84] += carry;
}

void sc25519_window5(signed char r[51], const sc25519 *s)
{
    char carry;
    int i;
    for (i = 0; i < 6; i++)
    {
        r[8 * i + 0] = s->v[5 * i + 0] & 31;
        r[8 * i + 1] = (s->v[5 * i + 0] >> 5) & 31;
        r[8 * i + 1] ^= (s->v[5 * i + 1] << 3) & 31;
        r[8 * i + 2] = (s->v[5 * i + 1] >> 2) & 31;
        r[8 * i + 3] = (s->v[5 * i + 1] >> 7) & 31;
        r[8 * i + 3] ^= (s->v[5 * i + 2] << 1) & 31;
        r[8 * i + 4] = (s->v[5 * i + 2] >> 4) & 31;
        r[8 * i + 4] ^= (s->v[5 * i + 3] << 4) & 31;
        r[8 * i + 5] = (s->v[5 * i + 3] >> 1) & 31;
        r[8 * i + 6] = (s->v[5 * i + 3] >> 6) & 31;
        r[8 * i + 6] ^= (s->v[5 * i + 4] << 2) & 31;
        r[8 * i + 7] = (s->v[5 * i + 4] >> 3) & 31;
    }
    r[8 * i + 0] = s->v[5 * i + 0] & 31;
    r[8 * i + 1] = (s->v[5 * i + 0] >> 5) & 31;
    r[8 * i + 1] ^= (s->v[5 * i + 1] << 3) & 31;
    r[8 * i + 2] = (s->v[5 * i + 1] >> 2) & 31;

    /* Making it signed */
    carry = 0;
    for (i = 0; i < 50; i++)
    {
        r[i] += carry;
        r[i + 1] += r[i] >> 5;
        r[i] &= 31;
        carry = r[i] >> 4;
        r[i] -= carry << 5;
    }
    r[50] += carry;
}

void sc25519_2interleave2(unsigned char r[127], const sc25519 *s1, const sc25519 *s2)
{
    int i;
    for (i = 0; i < 31; i++)
    {
        r[4 * i] = (s1->v[i] & 3) ^ ((s2->v[i] & 3) << 2);
        r[4 * i + 1] = ((s1->v[i] >> 2) & 3) ^ (((s2->v[i] >> 2) & 3) << 2);
        r[4 * i + 2] = ((s1->v[i] >> 4) & 3) ^ (((s2->v[i] >> 4) & 3) << 2);
        r[4 * i + 3] = ((s1->v[i] >> 6) & 3) ^ (((s2->v[i] >> 6) & 3) << 2);
    }
    r[124] = (s1->v[31] & 3) ^ ((s2->v[31] & 3) << 2);
    r[125] = ((s1->v[31] >> 2) & 3) ^ (((s2->v[31] >> 2) & 3) << 2);
    r[126] = ((s1->v[31] >> 4) & 3) ^ (((s2->v[31] >> 4) & 3) << 2);
}
#endif
