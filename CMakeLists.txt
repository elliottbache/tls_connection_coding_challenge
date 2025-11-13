cmake_minimum_required(VERSION 3.16)
project(pow_benchmark LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(pow_benchmark 
    src/pow_benchmark.cpp
    src/pow_core.cpp
    src/pow_core.h)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

target_link_libraries(pow_benchmark
    PRIVATE
        OpenSSL::SSL
        OpenSSL::Crypto
        Threads::Threads
)