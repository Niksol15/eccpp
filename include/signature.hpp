#ifndef ECCPP_SIGNATURE_HPP
#define ECCPP_SIGNATURE_HPP

#include <cstdint>

namespace eccpp {
    struct Signature {
        uint8_t R[32];
        uint8_t s[32];
    };
}

#endif //ECCPP_SIGNATURE_HPP
