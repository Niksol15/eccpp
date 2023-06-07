#ifndef ECCPP_PK_HPP
#define ECCPP_PK_HPP

#include "sodium/crypto_core_ed25519.h"

namespace eccpp {
    struct PublicKey {
        unsigned char value[crypto_core_ed25519_BYTES];
    };
}

#endif //ECCPP_PK_HPP
