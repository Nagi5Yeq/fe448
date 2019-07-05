#include "defs.h"
#include "sha3.h"
#include "ge448.h"

/* temporarily use getrandom() */
#include <sys/random.h>

/* Ed448, no prehash or context */
const static unsigned char ed448_dom4[10] = {'S', 'i', 'g', 'E', 'd', '4', '4', '8', 0, 0};

/* pk is 57 bytes, sk is 114 bytes, sk is followed by pk */
int crypto_sign_ed448_keypair(
    unsigned char *pk,
    unsigned char *sk)
{
  int i;
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
  for (i = 0; i < 57; i++)
    sk[57 + i] = pk[i];
  return 0;
}

/* detached method, sign is 114 bytes */
int crypto_sign_ed448_detached(
    unsigned char *sign, unsigned long long *smlen,
    const unsigned char *m, unsigned long long mlen,
    const unsigned char *sk)
{
  sc448 scsk, scr, sck;
  ge448 ger;
  unsigned char extsk[114];
  unsigned char hashr[114];
  sha3_ctx_t ctx;

  if (smlen != NULL)
  {
    *smlen = 114;
  }
  shake256_init(&ctx);
  shake_update(&ctx, sk, 57);
  shake_xof(&ctx);
  shake_out(&ctx, extsk, 114);
  extsk[56] = 0;
  extsk[55] |= 0x80;
  extsk[0] &= 0xFC;
  shake256_init(&ctx);
  shake_update(&ctx, ed448_dom4, 10);
  shake_update(&ctx, extsk + 57, 57);
  shake_update(&ctx, m, mlen);
  shake_xof(&ctx);
  shake_out(&ctx, hashr, 114);
  sc448_from114bytes(&scr, hashr);
  ge448_scalarmult_base(&ger, &scr);
  ge448_pack(sign, &ger); /* part1: R=r[B] */
  shake256_init(&ctx);
  shake_update(&ctx, ed448_dom4, 10);
  shake_update(&ctx, sign, 57);
  shake_update(&ctx, sk + 57, 57);
  shake_update(&ctx, m, mlen);
  shake_xof(&ctx);
  shake_out(&ctx, hashr, 114);
  sc448_from114bytes(&sck, hashr);
  sc448_from57bytes(&scsk, extsk);
  sc448_mul(&scsk, &scsk, &sck);
  sc448_add(&scsk, &scsk, &scr);
  sc448_to57bytes(sign + 57, &scsk); /* part2: S=r+s*k */
  return 0;
}
