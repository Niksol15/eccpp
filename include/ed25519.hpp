#ifndef ECCPP_ED25519_HPP
#define ECCPP_ED25519_HPP

#include <expected>

#include "signature.hpp"
#include "status_code.hpp"
#include "sk.hpp"
#include "pk.hpp"

#include <vector>

namespace eccpp {
    std::expected<Signature, StatusCode> Sign(const std::vector<uint8_t> &msg, const PrivateKey &sk);

    StatusCode Verify(const std::vector<uint8_t> &msg, const PublicKey &pk, const Signature &sign);
}


#endif //ECCPP_ED25519_HPP
