#include <key_pair_generate.hpp>

#include <utility>
#include <sodium/crypto_scalarmult.h>

#include "sk.hpp"
#include "pk.hpp"

std::pair<eccpp::PrivateKey, eccpp::PublicKey> eccpp::GenerateKeyPair() {
    std::pair<eccpp::PrivateKey, eccpp::PublicKey> res{};
    crypto_core_ed25519_scalar_random(res.first.value);
    crypto_scalarmult_base(res.second.value, res.first.value);
    return res; // RVO
}
