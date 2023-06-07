find_package(GTest REQUIRED)

add_executable(x25519_test x25519_test.cpp)
target_link_libraries(x25519_test eccpp gtest gtest_main)

add_executable(ed25519_test ed25519_test.cpp)
target_link_libraries(ed25519_test eccpp gtest gtest_main)