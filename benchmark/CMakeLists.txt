find_package(benchmark REQUIRED)
find_package(OpenSSL REQUIRED)

add_executable(opensslbench openssl_sign.cpp)
target_link_libraries(opensslbench PRIVATE benchmark::benchmark ssl crypto)

add_executable(sodiumbench libsodium_sign.cpp)
target_link_libraries(sodiumbench PRIVATE benchmark::benchmark sodium)

add_executable(secp256k1bench libsecp256k1_sign.cpp)
target_link_libraries(secp256k1bench PRIVATE benchmark::benchmark sodium secp256k1)

