#include "defs.h"
#include <stdio.h>
#include <assert.h>

#include "testv.h"

/* check sign, pk can't be NULL */
void testsign(const test_t *tests, int ntest)
{
    int i, j;
    unsigned char bsk[114];
    unsigned char bsign[114];
    unsigned char mysign[114];
    for (j = 0; j < ntest; j++)
    {
        hex2bin(bsk, tests[j].sk);
        hex2bin(bsk + 57, tests[j].pk);
        hex2bin(bsign, tests[j].sign);
        crypto_sign_ed448_detached(mysign, NULL, tests[j].msg, tests[j].mlen, bsk);
        for (i = 0; i < 114; i++)
        {
            assert(bsign[i] == mysign[i]);
        }
        printf("test sign %d good\n", j);
    }
}

int main()
{
    testsign(tests, NTESTS);
    return 0;
}
