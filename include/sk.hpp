#ifndef ECCPP_SK_HPP
#define ECCPP_SK_HPP

#include "cstdint"

namespace eccpp {
    struct PrivateKey {
        uint32_t value[32];
    };
}

#endif //ECCPP_SK_HPP
