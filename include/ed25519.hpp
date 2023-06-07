#ifndef ECCPP_ED25519_HPP
#define ECCPP_ED25519_HPP

#include "signature.hpp"
#include "status_code.hpp"
#include "sk.hpp"
#include "pk.hpp"

#include <vector>

namespace eccpp {
    Signature Sign(const std::vector<uint8_t> &msg, const PrivateKey &sk);

    StatusCode Verify(const std::vector<uint8_t> &msg, const PublicKey &pk, const Signature &sign);
}


#endif //ECCPP_ED25519_HPP
