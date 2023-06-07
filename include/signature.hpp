#ifndef ECCPP_SIGNATURE_HPP
#define ECCPP_SIGNATURE_HPP

#include <cstdint>

namespace eccpp {
    struct Signature {
        unsigned char R[64];
    };
}

#endif //ECCPP_SIGNATURE_HPP
