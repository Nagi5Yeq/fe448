#include "defs.h"
#include "sha3.h"
#include "ge448.h"

/* temporarily use getrandom() */
#include <sys/random.h>

/* sk and pk are both 57 bytes, sk is not followed by pk */
int crypto_sign_ed448_keypair(
    unsigned char *pk,
    unsigned char *sk)
{
    sc448 scsk;
    ge448 gepk;
    unsigned char extsk[114];
    sha3_ctx_t ctx;

    (void)getrandom(sk, 57, 0);
    shake256_init(&ctx);
    shake_update(&ctx, sk, 57);
    shake_xof(&ctx);
    shake_out(&ctx, extsk, 114);
    extsk[56] = 0;
    extsk[55] |= 0x80;
    extsk[0] &= 0xFC;

    sc448_from57bytes(&scsk, extsk);
    ge448_scalarmult_base(&gepk, &scsk);
    ge448_pack(pk, &gepk);
    return 0;
}
