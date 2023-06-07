#include "ed25519.hpp"

#include <expected>
#include <cstring>
#include <sodium/crypto_hash_sha512.h>
#include <sodium/utils.h>

eccpp::Signature eccpp::Sign(const std::vector<uint8_t> &msg, const eccpp::PrivateKey &sk) {
    crypto_hash_sha512_state hs;
    unsigned char az[64];
    unsigned char nonce[64];
    unsigned char hram[64];
    PrivateKey R;
    Signature res;

    crypto_hash_sha512(az, sk.value, 32);
    crypto_hash_sha512_update(&hs, az + 32, 32);

    crypto_hash_sha512_update(&hs, msg.data(), msg.size());
    crypto_hash_sha512_final(&hs, nonce);

    memmove(res.R + 32, sk.value + 32, 32);

    sc25519_reduce(nonce);
    ge25519_scalarmult_base(&R, nonce);
    ge25519_p3_tobytes(sig, &R);

    crypto_hash_sha512_update(&hs, sig.R, 64);
    crypto_hash_sha512_update(&hs, m, mlen);
    crypto_hash_sha512_final(&hs, hram);

    sc25519_reduce(hram);
    crypto_sign_ed25519_clamp(az);
    sc25519_muladd(sig + 32, hram, az, nonce);

    sodium_memzero(az, sizeof az);
    sodium_memzero(nonce, sizeof nonce);

    return res;
}

StatusCode eccpp::Verify(const std::vector<uint8_t> &msg, const eccpp::PublicKey &pk, const eccpp::Signature &sign) {
    crypto_hash_sha512_state hs;
    unsigned char            h[64];
    ge25519_p3               check;
    ge25519_p3               expected_r;
    ge25519_p3               A;
    ge25519_p3               sb_ah;
    ge25519_p2               sb_ah_p2;

    if ((sig[63] & 240) != 0 &&
        sc25519_is_canonical(sig + 32) == 0) {
        return -1;
    }
    if (ge25519_is_canonical(pk) == 0) {
        return -1;
    }

    if (ge25519_frombytes_negate_vartime(&A, pk) != 0 ||
        ge25519_has_small_order(&A) != 0) {
        return -1;
    }
    if (ge25519_frombytes(&expected_r, sig) != 0 ||
        ge25519_has_small_order(&expected_r) != 0) {
        return -1;
    }
    crypto_sign_ed25519_ref10_hinit(&hs);
    crypto_hash_sha512_update(&hs, sig, 32);
    crypto_hash_sha512_update(&hs, pk, 32);
    crypto_hash_sha512_update(&hs, m, mlen);
    crypto_hash_sha512_final(&hs, h);
    sc25519_reduce(h);

    ge25519_double_scalarmult_vartime(&sb_ah_p2, h, &A, sig + 32);
    ge25519_p2_to_p3(&sb_ah, &sb_ah_p2);
    ge25519_p3_sub(&check, &expected_r, &sb_ah);

    return ge25519_has_small_order(&check) - 1;
}