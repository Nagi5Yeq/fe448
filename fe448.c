#define WINDOWSIZE 1 /* Should be 1,2, or 4 */
#define WINDOWMASK ((1 << WINDOWSIZE) - 1)

#include "fe448.h"

/* 2**448-2**224-1 */
static const crypto_uint32 m[57] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF,
                                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00};

/* 256**114//m */
static const crypto_uint32 mu[59] = {0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
                                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

static crypto_uint32 equal(crypto_uint32 a, crypto_uint32 b) /* 16-bit inputs */
{
  crypto_uint32 x = a ^ b; /* 0: yes; 1..65535: no */
  x -= 1;                  /* 4294967295: yes; 0..65534: no */
  x >>= 31;                /* 1: yes; 0: no */
  return x;
}

static crypto_uint32 lt(crypto_uint32 a, crypto_uint32 b) /* 16-bit inputs */
{
  unsigned int x = a;
  x -= (unsigned int)b; /* 0..65535: no; 4294901761..4294967295: yes */
  x >>= 31;             /* 0: no; 1: yes */
  return x;
}

static void reduce_add_sub(fe448 *r)
{
  crypto_uint32 t;
  int i, rep;

  for (rep = 0; rep < 4; rep++)
  {
    t = r->v[56];
    r->v[56] = 0;
    r->v[0] += t;
    r->v[28] += t;
    for (i = 0; i < 56; i++)
    {
      t = r->v[i] >> 8;
      r->v[i + 1] += t;
      r->v[i] &= 255;
    }
  }
}

/* copied from sc448.c, a bit of slowly on 2**448-2**224-1 */
static void barrett_reduce(fe448 *r, const crypto_uint32 x[114])
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

  reduce_add_sub(r);
  reduce_add_sub(r);
  reduce_add_sub(r);
  reduce_add_sub(r);
}

/* reduction modulo 2**448-2**224-1 */
void fe448_freeze(fe448 *r)
{
  int i;
  crypto_uint32 m0;
  crypto_uint32 m1;
  crypto_uint32 b = 0, t;
  m0 = equal(r->v[56], 0);
  for (i = 55; i > 28; i--)
    m0 &= equal(r->v[i], 255);
  m1 = m0;
  m0 &= equal(r->v[28], 255);
  m1 &= equal(r->v[28], 254);
  for (i = 27; i >= 0; i--)
    m1 &= equal(r->v[i], 255);

  m0 |= m1;
  m0 = -m0;

  for (i = 0; i < 57; i++)
  {
    t = r->v[i] - m[i] - b;
    r->v[i] -= (m[i] + b) & 255 & m0;
    b = (t >> 8) & 1;
  }
}

void fe448_unpack(fe448 *r, const unsigned char x[57])
{
  int i;
  for (i = 0; i < 56; i++)
    r->v[i] = x[i];
  r->v[56] = 0;
}

/* Assumes input x being reduced below 2^448 */
void fe448_pack(unsigned char r[57], const fe448 *x)
{
  int i;
  fe448 y = *x;
  fe448_freeze(&y);
  for (i = 0; i < 57; i++)
    r[i] = y.v[i];
}

int fe448_iszero(const fe448 *x)
{
  int i;
  int r;
  fe448 t = *x;
  fe448_freeze(&t);
  r = equal(t.v[0], 0);
  for (i = 1; i < 57; i++)
    r &= equal(t.v[i], 0);
  return r;
}

int fe448_iseq_vartime(const fe448 *x, const fe448 *y)
{
  int i;
  fe448 t1 = *x;
  fe448 t2 = *y;
  fe448_freeze(&t1);
  fe448_freeze(&t2);
  for (i = 0; i < 57; i++)
    if (t1.v[i] != t2.v[i])
      return 0;
  return 1;
}

void fe448_cmov(fe448 *r, const fe448 *x, unsigned char b)
{
  int i;
  crypto_uint32 mask = b;
  mask = -mask;
  for (i = 0; i < 57; i++)
    r->v[i] ^= mask & (x->v[i] ^ r->v[i]);
}

unsigned char fe448_getparity(const fe448 *x)
{
  fe448 t = *x;
  fe448_freeze(&t);
  return t.v[0] & 1;
}

void fe448_setone(fe448 *r)
{
  int i;
  r->v[0] = 1;
  for (i = 1; i < 57; i++)
    r->v[i] = 0;
}

void fe448_setzero(fe448 *r)
{
  int i;
  for (i = 0; i < 57; i++)
    r->v[i] = 0;
}

void fe448_neg(fe448 *r, const fe448 *x)
{
  fe448 t;
  int i;
  for (i = 0; i < 57; i++)
    t.v[i] = x->v[i];
  fe448_setzero(r);
  fe448_sub(r, r, &t);
}

void fe448_add(fe448 *r, const fe448 *x, const fe448 *y)
{
  int i;
  for (i = 0; i < 57; i++)
    r->v[i] = x->v[i] + y->v[i];
  reduce_add_sub(r);
}

void fe448_sub(fe448 *r, const fe448 *x, const fe448 *y)
{
  int i;
  crypto_uint32 t[57];
  for (i = 0; i < 28; i++) /* add x with p previously so that r>0 */
  {
    t[i] = x->v[i] + 0x1fe;
  }
  t[28] = x->v[28] + 0x1fc;
  for (i = 29; i < 56; i++)
  {
    t[i] = x->v[i] + 0x1fe;
  }
  t[56] = 0;
  for (i = 0; i < 57; i++)
    r->v[i] = t[i] - y->v[i];
  reduce_add_sub(r);
}

/* a slow version copied from sc448.c */
void fe448_mul(fe448 *r, const fe448 *x, const fe448 *y)
{
  int i, j, carry;
  crypto_uint32 t[114];
  for (i = 0; i < 114; i++)
    t[i] = 0;

  for (i = 0; i < 57; i++)
    for (j = 0; j < 57; j++)
      t[i + j] += x->v[i] * y->v[j];

  for (i = 0; i < 113; i++)
  {
    carry = t[i] >> 8;
    t[i + 1] += carry;
    t[i] &= 0xff;
  }

  barrett_reduce(r, t);
}

void fe448_square(fe448 *r, const fe448 *x)
{
  fe448_mul(r, x, x);
}

void fe448_invert(fe448 *r, const fe448 *x)
{
  fe448 t0;
  fe448 t1;
  fe448 t2;
  int i;

  fe448_square(&t0, x);
  fe448_mul(&t0, &t0, x); /* 2^2 - 1 */
  fe448_square(&t0, &t0); /* 2^3 - 2 */
  fe448_mul(&t1, &t0, x); /* 2^3 - 1 */
  fe448_square(&t0, &t1); /* 2^4 - 2^1 */
  for (i = 0; i < 2; i++)
  {
    fe448_square(&t0, &t0);
  }                         /* 2^6 - 2^3 */
  fe448_mul(&t1, &t1, &t0); /* 2^6 - 1 */
  fe448_square(&t0, &t1);   /* 2^7 - 2^1 */
  for (i = 0; i < 5; i++)
  {
    fe448_square(&t0, &t0);
  }                         /* 2^12 - 2^6 */
  fe448_mul(&t1, &t1, &t0); /* 2^12 - 1 */
  fe448_square(&t1, &t1);   /* 2^13 - 2^1 */
  fe448_mul(&t1, &t1, x);   /* 2^13 - 1 */
  fe448_square(&t0, &t1);   /* 2^14 - 2^1 */
  for (i = 0; i < 12; i++)
  {
    fe448_square(&t0, &t0);
  }                         /* 2^26 - 2^13 */
  fe448_mul(&t1, &t1, &t0); /* 2^26 - 1 */
  fe448_square(&t1, &t1);   /* 2^26 - 2^1 */
  fe448_mul(&t1, &t1, x);   /* 2^27 - 1 */
  fe448_square(&t0, &t1);   /* 2^28 - 2^1 */
  for (i = 0; i < 26; i++)
  {
    fe448_square(&t0, &t0);
  }                         /* 2^54 - 2^27 */
  fe448_mul(&t1, &t1, &t0); /* 2^54 - 1 */
  fe448_square(&t1, &t1);   /* 2^55 - 2^1 */
  fe448_mul(&t1, &t1, x);   /* 2^55 - 1 */
  fe448_square(&t0, &t1);   /* 2^56 - 2^1 */
  for (i = 0; i < 54; i++)
  {
    fe448_square(&t0, &t0);
  }                         /* 2^110 - 2^55 */
  fe448_mul(&t1, &t1, &t0); /* 2^110 - 1 */
  fe448_square(&t1, &t1);   /* 2^111 - 2^1 */
  fe448_mul(&t1, &t1, x);   /* 2^111 - 1 */
  fe448_square(&t0, &t1);   /* 2^112 - 2^1 */
  for (i = 0; i < 110; i++)
  {
    fe448_square(&t0, &t0);
  }                         /* 2^222 - 2^111 */
  fe448_mul(&t2, &t1, &t0); /* 2^222 - 1 */
  fe448_square(&t1, &t2);   /* 2^223 - 2^1 */
  fe448_mul(&t1, &t1, x);   /* 2^223 - 1 */
  fe448_square(&t0, &t1);   /* 2^224 - 2^1 */
  for (i = 0; i < 222; i++)
  {
    fe448_square(&t0, &t0);
  }                         /* 2^446 - 2^223 */
  fe448_mul(&t0, &t2, &t0); /* 2^446 - 2^222 - 1 */
  fe448_square(&t0, &t0);   /* 2^447 - 2^223 - 2 */
  fe448_square(&t0, &t0);   /* 2^448 - 2^224 - 4 */
  fe448_mul(r, &t0, x);     /* 2^448 - 2^224 - 3 */
}

/* pow(2**446-2**222-1) */
void fe448_pow446(fe448 *r, const fe448 *x)
{
}
