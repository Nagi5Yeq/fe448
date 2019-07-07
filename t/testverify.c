#include "defs.h"
#include <stdio.h>
#include <assert.h>

#include "testv.h"

/* check verify, pk can't be NULL */
void testverify(const test_t *tests, int ntest)
{
    int j;
    unsigned char bpk[57];
    unsigned char bsign[114];
    for (j = 0; j < ntest; j++)
    {
        hex2bin(bpk, tests[j].pk);
        hex2bin(bsign, tests[j].sign);
        assert(crypto_sign_ed448_open_detached(tests[j].msg, tests[j].mlen, bsign, bpk) == 0);
        printf("test verify %d good\n", j);
    }
}

int main()
{
    testverify(tests, NTESTS);
    return 0;
}
