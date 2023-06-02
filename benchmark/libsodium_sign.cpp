#include <iostream>

#include <benchmark/benchmark.h>

#include <sodium/crypto_sign.h>
#include <sodium/core.h>
#include <sodium/crypto_sign_ed25519.h>

#include "common.hpp"

void benchmark_libsodium_ed25519_sign(benchmark::State &state) {
    if (sodium_init() == -1) {
        return;
    }

    for (auto _: state) {
        unsigned char pk[crypto_sign_PUBLICKEYBYTES]{};
        unsigned char sk[crypto_sign_SECRETKEYBYTES]{};
        unsigned char signed_message[crypto_sign_BYTES];
        unsigned long long signed_message_len;
        int res = crypto_sign_keypair(pk, sk);
        if(res != 0) {
            std::cout << "Error in key creation: " << res;
            return;
        }

        res = crypto_sign_detached(signed_message, &signed_message_len,
                    bench_common::msg, bench_common::msg_len, sk);
        if(res != 0) {
            std::cout << "Error in sign: " << res;
        }
    }
}

BENCHMARK(benchmark_libsodium_ed25519_sign);

BENCHMARK_MAIN();