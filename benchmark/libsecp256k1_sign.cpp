#include <sys/random.h>

#include <benchmark/benchmark.h>

#include <secp256k1.h>
#include <sodium/crypto_hash_sha256.h>
#include <sodium/core.h>

#include "common.hpp"

void secp256k1_sign_bench(benchmark::State &state) {
    sodium_init();
    for (auto _: state) {
        unsigned char msg_hash[32] = {};
        crypto_hash_sha256(msg_hash, bench_common::msg, bench_common::msg_len);
        unsigned char seckey[32];
        unsigned char randomize[32];
        unsigned char compressed_pubkey[33];
        unsigned char serialized_signature[64];
        size_t len;
        int is_signature_valid, is_signature_valid2;
        int return_val;
        secp256k1_pubkey pubkey;
        secp256k1_ecdsa_signature sig;
        secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
        if (!getrandom(randomize, sizeof(randomize), 0)) {
            printf("Failed to generate randomness\n");
            return;
        }
        return_val = secp256k1_context_randomize(ctx, randomize);
        assert(return_val);
        while (1) {
            if (!getrandom(seckey, sizeof(seckey), 0)) {
                printf("Failed to generate randomness\n");
                return;
            }
            if (secp256k1_ec_seckey_verify(ctx, seckey)) {
                break;
            }
        }
        return_val = secp256k1_ec_pubkey_create(ctx, &pubkey, seckey);
        assert(return_val);
        len = sizeof(compressed_pubkey);
        return_val = secp256k1_ec_pubkey_serialize(ctx, compressed_pubkey, &len, &pubkey, SECP256K1_EC_COMPRESSED);
        assert(return_val);
        assert(len == sizeof(compressed_pubkey));
        return_val = secp256k1_ecdsa_sign(ctx, &sig, msg_hash, seckey, NULL, NULL);
    }
}

BENCHMARK(secp256k1_sign_bench);

BENCHMARK_MAIN();