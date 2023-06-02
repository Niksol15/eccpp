//
// Created by niksol on 6/2/23.
//

#ifndef ECCPP_KEY_GENERATE_HPP
#define ECCPP_KEY_GENERATE_HPP

#include <status_code.hpp>
#include "pk.hpp"
#include "sk.hpp"

namespace eccpp {
    StatusCode GenerateKeyPair(PrivateKey& sk, PublicKey& pk);
}

#endif //ECCPP_KEY_GENERATE_HPP
