#ifndef ECCPP_KEY_GENERATE_HPP
#define ECCPP_KEY_GENERATE_HPP

#include <utility>
#include "pk.hpp"
#include "sk.hpp"

namespace eccpp {
    std::pair<PrivateKey, PublicKey> GenerateKeyPair();
}

#endif //ECCPP_KEY_GENERATE_HPP
