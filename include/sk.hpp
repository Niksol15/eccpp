#ifndef ECCPP_SK_HPP
#define ECCPP_SK_HPP

#include <sodium/crypto_core_ed25519.h>

namespace eccpp {
    struct PrivateKey {
        unsigned char value[crypto_core_ed25519_SCALARBYTES];
    };
}
#endif //ECCPP_SK_HPP
