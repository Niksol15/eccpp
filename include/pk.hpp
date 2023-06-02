#ifndef ECCPP_PK_HPP
#define ECCPP_PK_HPP

#include <cstdint>
#include "internal.h"

namespace eccpp {
    struct PublicKey {
        ge25519_p3 value;
    };
}

#endif //ECCPP_PK_HPP
