#include "x25519.hpp"

#include <sys/random.h>

#include "internal.h"

eccpp::PublicKey eccpp::X25519::GeneratePublicKey() {
    is_initialized_ = true;
    getrandom(sk_.value, sizeof(sk_), 0);
    ge25519_p3 res;
    ge25519_scalarmult_base(res, sk_.value);
    return res;
}