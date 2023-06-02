#ifndef ECCPP_X25519_HPP
#define ECCPP_X25519_HPP

#include <expected>

#include "sk.hpp"
#include "pk.hpp"
#include "status_code.hpp"

namespace eccpp {
    class X25519 {
    public:
        PublicKey GeneratePublicKey();
        std::expected<std::uint32_t[4], StatusCode> ComputeSeceret(const PublicKey& pk);
    private:
        PrivateKey sk_;
        bool is_initialized_;
    };
}

#endif //ECCPP_X25519_HPP
