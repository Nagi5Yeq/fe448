#include "fe448.h"
#include "sc448.h"
#include "ge448.h"

/* 
 * Ed448-Goldilocks: x^2 + y^2 = 1 + dx^2y^2 
 * with d = -39081
 */

/* d */
static const fe448 ge448_ecd = {{0x56, 0x67, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF,
                                 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00}};

#define ge448_p3 ge448 /* use projective coordinates only */

typedef struct
{
  fe448 x;
  fe448 y;
} ge448_aff;

/* Packed coordinates of the base point */
const ge448 ge448_base = {{{0x5E, 0xC0, 0x0C, 0xC7, 0x2B, 0xA8, 0x26, 0x26, 0x8E, 0x93, 0x00, 0x8B, 0xE1, 0x80, 0x3B, 0x43,
                            0x11, 0x65, 0xB6, 0x2A, 0xF7, 0x1A, 0xAE, 0x12, 0x64, 0xA4, 0xD3, 0xA3, 0x24, 0xE3, 0x6D, 0xEA,
                            0x67, 0x17, 0x0F, 0x47, 0x70, 0x65, 0x14, 0x9E, 0xDA, 0x36, 0xBF, 0x22, 0xA6, 0x15, 0x1D, 0x22,
                            0xED, 0x0D, 0xED, 0x6B, 0xC6, 0x70, 0x19, 0x4F, 0x00}},
                          {{0x14, 0xFA, 0x30, 0xF2, 0x5B, 0x79, 0x08, 0x98, 0xAD, 0xC8, 0xD7, 0x4E, 0x2C, 0x13, 0xBD, 0xFD,
                            0xC4, 0x39, 0x7C, 0xE6, 0x1C, 0xFF, 0xD3, 0x3A, 0xD7, 0xC2, 0xA0, 0x05, 0x1E, 0x9C, 0x78, 0x87,
                            0x40, 0x98, 0xA3, 0x6C, 0x73, 0x73, 0xEA, 0x4B, 0x62, 0xC7, 0xC9, 0x56, 0x37, 0x20, 0x76, 0x88,
                            0x24, 0xBC, 0xB6, 0x6E, 0x71, 0x46, 0x3F, 0x69, 0x00}},
                          {{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}}};

/* Multiples of the base point in affine representation */
static const ge448_aff ge448_base_multiples_affine[745] = {
#include "ge448_base.data"
};

/* point addition from rfc8032 */
static void ge448_mixadd2(ge448_p3 *r, const ge448_aff *q)
{
  fe448 a, b, c, d, e, f, g, h;
  a = r->z;                    /* A=Z1*Z2 (Z2=1) */
  fe448_square(&b, &a);        /* B=A^2 */
  fe448_mul(&c, &r->x, &q->x); /* C=X1*X2 */
  fe448_mul(&d, &r->y, &q->y); /* D=Y1*Y2 */
  fe448_mul(&e, &c, &d);
  fe448_mul(&e, &e, &ge448_ecd); /* E=d*C*D */
  fe448_sub(&f, &b, &e);         /* F=B-E */
  fe448_add(&g, &b, &e);         /* G=B+E */
  fe448_add(&b, &r->x, &r->y);
  fe448_add(&h, &q->x, &q->y);
  fe448_mul(&h, &b, &h); /* H=(X1+Y1)*(X2+Y2) */
  fe448_sub(&h, &h, &c);
  fe448_sub(&h, &h, &d);
  fe448_mul(&h, &h, &f);
  fe448_mul(&r->x, &a, &h); /* X3=A*F*(H-C-D) */
  fe448_sub(&d, &d, &c);
  fe448_mul(&d, &d, &g);
  fe448_mul(&r->y, &a, &d); /* Y3=A*G*(D-C) */
  fe448_mul(&r->z, &f, &g); /* Z3=F*G */
}

static void add_p3(ge448_p3 *r, const ge448_p3 *p, const ge448_p3 *q)
{
  fe448 a, b, c, d, e, f, g, h;
  fe448_mul(&a, &p->z, &q->z); /* A=Z1*Z2 */
  fe448_square(&b, &a);        /* B=A^2 */
  fe448_mul(&c, &p->x, &q->x); /* C=X1*X2 */
  fe448_mul(&d, &p->y, &q->y); /* D=Y1*Y2 */
  fe448_mul(&e, &c, &d);
  fe448_mul(&e, &e, &ge448_ecd); /* E=d*C*D */
  fe448_sub(&f, &b, &e);         /* F=B-E */
  fe448_add(&g, &b, &e);         /* G=B+E */
  fe448_add(&b, &p->x, &p->y);
  fe448_add(&h, &q->x, &q->y);
  fe448_mul(&h, &b, &h); /* H=(X1+Y1)*(X2+Y2) */
  fe448_sub(&h, &h, &c);
  fe448_sub(&h, &h, &d);
  fe448_mul(&h, &h, &f);
  fe448_mul(&r->x, &a, &h); /* X3=A*F*(H-C-D) */
  fe448_sub(&d, &d, &c);
  fe448_mul(&d, &d, &g);
  fe448_mul(&r->y, &a, &d); /* Y3=A*G*(D-C) */
  fe448_mul(&r->z, &f, &g); /* Z3=F*G */
}

/* point doubling from rfc8032 */
static void dbl_p3(ge448_p3 *r, const ge448_p3 *p)
{
  fe448 b, c, d, e, h, j;
  fe448_add(&b, &p->x, &p->y);
  fe448_square(&b, &b);    /* B=(X1+Y1)^2 */
  fe448_square(&c, &p->x); /* C=X1^2 */
  fe448_square(&d, &p->y); /* D=Y1^2 */
  fe448_add(&e, &c, &d);   /* E=C+D */
  fe448_square(&h, &p->z); /* H=Z1^2 */
  fe448_sub(&j, &e, &h);
  fe448_sub(&j, &j, &h); /* J=E-2*H */
  fe448_sub(&h, &b, &e);
  fe448_mul(&r->x, &h, &j); /* X3=(B-E)*J */
  fe448_sub(&h, &c, &d);
  fe448_mul(&r->y, &e, &h); /* Y3=E*(C-D) */
  fe448_mul(&r->z, &e, &j); /* Z3=E*J */
}

/* Constant-time version of: if(b) r = p */
static void cmov_aff(ge448_aff *r, const ge448_aff *p, unsigned char b)
{
  fe448_cmov(&r->x, &p->x, b);
  fe448_cmov(&r->y, &p->y, b);
}

static unsigned char equal(signed char b, signed char c)
{
  unsigned char ub = b;
  unsigned char uc = c;
  unsigned char x = ub ^ uc; /* 0: yes; 1..255: no */
  crypto_uint32 y = x;       /* 0: yes; 1..255: no */
  y -= 1;                    /* 4294967295: yes; 0..254: no */
  y >>= 31;                  /* 1: yes; 0: no */
  return y;
}

static unsigned char negative(signed char b)
{
  unsigned long long x = b; /* 18446744073709551361..18446744073709551615: yes; 0..255: no */
  x >>= 63;                 /* 1: yes; 0: no */
  return x;
}

static void choose_t(ge448_aff *t, unsigned long long pos, signed char b)
{
  /* constant time */
  fe448 v;
  *t = ge448_base_multiples_affine[5 * pos + 0];
  cmov_aff(t, &ge448_base_multiples_affine[5 * pos + 1], equal(b, 1) | equal(b, -1));
  cmov_aff(t, &ge448_base_multiples_affine[5 * pos + 2], equal(b, 2) | equal(b, -2));
  cmov_aff(t, &ge448_base_multiples_affine[5 * pos + 3], equal(b, 3) | equal(b, -3));
  cmov_aff(t, &ge448_base_multiples_affine[5 * pos + 4], equal(b, -4));
  fe448_neg(&v, &t->x);
  fe448_cmov(&t->x, &v, negative(b));
}

static void setneutral(ge448 *r)
{
  fe448_setzero(&r->x);
  fe448_setone(&r->y);
  fe448_setone(&r->z);
}

/* ********************************************************************
 *                    EXPORTED FUNCTIONS
 ******************************************************************** */

/* return 0 on success, -1 otherwise */
int ge448_unpackneg_vartime(ge448_p3 *r, const unsigned char p[57])
{
  unsigned char par;
  fe448 t, chk, num, num2, den, den2, n3d;
  fe448_setone(&r->z);
  par = p[56] >> 7;
  fe448_unpack(&r->y, p);
  fe448_square(&num, &r->y);         /* x = y^2 */
  fe448_mul(&den, &num, &ge448_ecd); /* den = dy^2 */
  fe448_sub(&num, &num, &r->z);      /* x = y^2-1 */
  fe448_sub(&den, &r->z, &den);      /* den = dy^2-1 */

  /* Computation of sqrt(num/den) */
  /* 1.: computation of num^3 * den */
  fe448_square(&num2, &num);
  fe448_mul(&n3d, &num2, &num);
  fe448_mul(&n3d, &n3d, &den);

  /* 2. computation of r->x = n3d * (num^5*den^3)^((p-3)/4) */
  fe448_square(&den2, &den);
  fe448_mul(&t, &n3d, &den2);
  fe448_mul(&t, &t, &num2);
  fe448_pow446(&t, &t);
  fe448_mul(&r->x, &t, &n3d);

  /* 3. Check whether square root exists */
  fe448_square(&chk, &r->x);
  fe448_mul(&chk, &chk, &den);
  if (!fe448_iseq_vartime(&chk, &num))
    return -1;

  /* 4. Choose the desired square root according to parity: */
  if (fe448_getparity(&r->x) != (1 - par))
    fe448_neg(&r->x, &r->x);
  return 0;
}

void ge448_pack(unsigned char r[57], const ge448_p3 *p)
{
  fe448 tx, ty, zi;
  fe448_invert(&zi, &p->z);
  fe448_mul(&tx, &p->x, &zi);
  fe448_mul(&ty, &p->y, &zi);
  fe448_pack(r, &ty);
  r[56] ^= fe448_getparity(&tx) << 7;
}

int ge448_isneutral_vartime(const ge448_p3 *p)
{
  int ret = 1;
  if (!fe448_iszero(&p->x))
    ret = 0;
  if (!fe448_iseq_vartime(&p->y, &p->z))
    ret = 0;
  return ret;
}

/* computes [s1]p1 + [s2]p2 */
void ge448_double_scalarmult_vartime(ge448_p3 *r, const ge448_p3 *p1, const sc448 *s1, const ge448_p3 *p2, const sc448 *s2)
{
  ge448_p3 pre[16];
  unsigned char b[223];
  int i;

  /* precomputation s2 s1 */
  setneutral(pre);                     /* 00 00 */
  pre[1] = *p1;                        /* 00 01 */
  dbl_p3(&pre[2], p1);                 /* 00 10 */
  add_p3(&pre[3], &pre[1], &pre[2]);   /* 00 11 */
  pre[4] = *p2;                        /* 01 00 */
  add_p3(&pre[5], &pre[1], &pre[4]);   /* 01 01 */
  add_p3(&pre[6], &pre[2], &pre[4]);   /* 01 10 */
  add_p3(&pre[7], &pre[3], &pre[4]);   /* 01 11 */
  dbl_p3(&pre[8], p2);                 /* 10 00 */
  add_p3(&pre[9], &pre[1], &pre[8]);   /* 10 01 */
  dbl_p3(&pre[10], &pre[5]);           /* 10 10 */
  add_p3(&pre[11], &pre[3], &pre[8]);  /* 10 11 */
  add_p3(&pre[12], &pre[4], &pre[8]);  /* 11 00 */
  add_p3(&pre[13], &pre[1], &pre[12]); /* 11 01 */
  add_p3(&pre[14], &pre[2], &pre[12]); /* 11 10 */
  add_p3(&pre[15], &pre[3], &pre[12]); /* 11 11 */

  sc448_2interleave2(b, s1, s2);

  /* scalar multiplication */
  *r = pre[b[222]];
  for (i = 125; i >= 0; i--)
  {
    dbl_p3(r, r);
    dbl_p3(r, r);
    if (b[i] != 0)
    {
      add_p3(r, r, &pre[b[i]]);
    }
  }
}

void ge448_scalarmult_base(ge448_p3 *r, const sc448 *s)
{
  signed char b[149];
  int i;
  ge448_aff t;
  sc448_window3(b, s);

  choose_t((ge448_aff *)r, 0, b[0]);
  fe448_setone(&r->z);
  for (i = 1; i < 149; i++)
  {
    choose_t(&t, (unsigned long long)i, b[i]);
    ge448_mixadd2(r, &t);
  }
}
