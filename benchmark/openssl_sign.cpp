#include <iostream>

#include <benchmark/benchmark.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>

#include "common.hpp"

void openssl_ed25519_sign(const unsigned char *msg, size_t msg_len) {
    size_t signature_len = 64;
    unsigned char *signature = new unsigned char[signature_len];
    EVP_PKEY* pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        return ; // Error creating EVP_PKEY object
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    if (ctx == NULL) {
        EVP_PKEY_free(pkey);
        return ;
    }

    if (EVP_PKEY_keygen_init(ctx) != 1) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return ; // Error initializing key generation
    }

    if (EVP_PKEY_keygen(ctx, &pkey) != 1) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return ; // Error generating key pair
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return ; // Error creating EVP_MD_CTX object
    }

    if (EVP_DigestSignInit(mdctx, NULL, NULL, NULL, pkey) != 1) {
        std::cout << ERR_reason_error_string(ERR_peek_last_error()) << "\n";
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return ; // Error initializing digest signing
    }


    if (EVP_DigestSign(mdctx, signature, &signature_len, msg, msg_len) != 1) {
        std::cout << ERR_reason_error_string(ERR_peek_last_error()) << "\n";
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return ;
    }

    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_CTX_free(ctx);
}

void benchmark_openssl_ed25519_sign(benchmark::State &state) {
    for (auto _: state) {
        EVP_PKEY *pkey = NULL;
        openssl_ed25519_sign(bench_common::msg, bench_common::msg_len);
    }
}

BENCHMARK(benchmark_openssl_ed25519_sign);


BENCHMARK_MAIN();