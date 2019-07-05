#include "ge448.h"
#include <stdio.h>
#include <assert.h>

/*const ge448 ge448_base = {{{0x5E, 0xC0, 0x0C, 0xC7, 0x2B, 0xA8, 0x26, 0x26, 0x8E, 0x93, 0x00, 0x8B, 0xE1, 0x80, 0x3B, 0x43,
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
 */
#define ge448_p3 ge448 /* use projective coordinates only */

static const fe448 ge448_ecd = {{0x56, 0x67, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF,
                                 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00}};

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

static void output(ge448_p3 *p)
{
    int i, printed;
    fe448 tx, ty, zi;
    unsigned char px[57], py[57];
    char buffer[4000];
    fe448_invert(&zi, &p->z);
    fe448_mul(&tx, &p->x, &zi);
    fe448_mul(&ty, &p->y, &zi);
    fe448_pack(px, &tx);
    fe448_pack(py, &ty);
    printed = 0;
    printed += sprintf(buffer + printed, "{{{0x%02x", px[0]);
    for (i = 1; i < 57; i++)
    {
        printed += sprintf(buffer + printed, ", 0x%02x", px[i]);
    }
    printed += sprintf(buffer + printed, "}},\n");
    printed += sprintf(buffer + printed, " {{0x%02x", py[0]);
    for (i = 1; i < 57; i++)
    {
        printed += sprintf(buffer + printed, ", 0x%02x", py[i]);
    }
    printed += sprintf(buffer + printed, "}}}");
    assert(fwrite(buffer, 1, printed, stdout) == printed);
}

static void mul234(ge448 *group)
{
    int i;
    for (i = 2; i < 5; i++)
    {
        add_p3(&group[i], &group[i - 1], &group[1]);
    }
}

static void outputgroup(ge448 *group)
{
    int i;
    output(&group[0]);
    for (i = 1; i < 5; i++)
    {
        puts(",");
        output(&group[i]);
    }
}

int main()
{
    int i;
    /* 0d, 1d, 2d, 3d, 4d */
    ge448 group[5] = {{{{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
                       {{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
                       {{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}}},
                      {{{0x5E, 0xC0, 0x0C, 0xC7, 0x2B, 0xA8, 0x26, 0x26, 0x8E, 0x93, 0x00, 0x8B, 0xE1, 0x80, 0x3B, 0x43,
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
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}}}};
    mul234(group);
    outputgroup(group);
    for (i = 1; i < 150; i++)
    {
        add_p3(&group[1], &group[1], &group[1]);
        add_p3(&group[1], &group[1], &group[1]);
        add_p3(&group[1], &group[1], &group[1]);
        puts(",");
        mul234(group);
        outputgroup(group);
    }
    return 0;
}
