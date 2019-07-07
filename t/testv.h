#ifndef TESTV_H
#define TESTV_H

#include <stddef.h>

#define NTESTS 8

typedef struct
{
    const char *sk;
    const char *pk;
    const char *sign;
    const unsigned char *msg;
    unsigned long long mlen;
} test_t;

extern const test_t tests[NTESTS];

void hex2bin(unsigned char *out, const char *in);

#endif
