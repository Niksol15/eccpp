#include "x25519.hpp"

#include <sodium/crypto_hash_sha256.h>
#include <sodium/crypto_scalarmult.h>

eccpp::PublicKey eccpp::X25519::GeneratePublicKey() {
    is_initialized_ = true;
    crypto_core_ed25519_scalar_random(sk_.value);
    PublicKey res{};
    crypto_scalarmult_base(res.value, sk_.value);

    return res;
}

std::expected<unsigned char[32], eccpp::StatusCode> eccpp::X25519::ComputeSecret(const eccpp::PublicKey &pk) {
    if(!is_initialized_) {
        return std::unexpected{eccpp::StatusCode::kFailure};
    }

    if(!crypto_core_ed25519_is_valid_point(pk.value)) {
        return std::unexpected{eccpp::StatusCode::kFailure};
    }

    PublicKey res_point{};

    crypto_scalarmult(res_point.value, sk_.value, pk.value);

    unsigned char res[32]{};

    crypto_hash_sha256(res, res_point.value, sizeof(res_point.value));

    return std::expected{res};
}