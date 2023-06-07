cmake_minimum_required(VERSION 3.25)
project(eccpp LANGUAGES CXX VERSION 0.0.1)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=native -O3")

add_library(${PROJECT_NAME} SHARED src/ed25519.cpp src/x25519.cpp src/key_pair_generate.cpp)

target_link_libraries(${PROJECT_NAME} PRIVATE sodium)
target_include_directories(${PROJECT_NAME} PUBLIC include)

add_subdirectory(benchmark)
add_subdirectory(unit)
