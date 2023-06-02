#include "ed25519.hpp"

#include <expected>
#include <cstring>
#include <sodium/crypto_hash_sha512.h>
#include <sodium/utils.h>

#include "internal.h"

void _crypto_sign_ed25519_clamp(unsigned char* k)
{
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
}

int _crypto_sign_ed25519_detached(unsigned char *sig, unsigned long long *siglen_p,
                              const unsigned char *m, unsigned long long mlen,
                              const unsigned char *sk) {
    crypto_hash_sha512_state hs;
    unsigned char az[64];
    unsigned char nonce[64];
    unsigned char hram[64];
    ge25519_p3 R;

    crypto_hash_sha512(az, sk, 32);
    crypto_hash_sha512_update(&hs, az + 32, 32);

    crypto_hash_sha512_update(&hs, m, mlen);
    crypto_hash_sha512_final(&hs, nonce);

    memmove(sig + 32, sk + 32, 32);

    sc25519_reduce(nonce);
    ge25519_scalarmult_base(&R, nonce);
    ge25519_p3_tobytes(sig, &R);

    crypto_hash_sha512_update(&hs, sig, 64);
    crypto_hash_sha512_update(&hs, m, mlen);
    crypto_hash_sha512_final(&hs, hram);

    sc25519_reduce(hram);
    _crypto_sign_ed25519_clamp(az);
    sc25519_muladd(sig + 32, hram, az, nonce);

    sodium_memzero(az, sizeof az);
    sodium_memzero(nonce, sizeof nonce);

    return 0;
}

