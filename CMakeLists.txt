cmake_minimum_required(VERSION 3.16)
project(pow_benchmark LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Prefer -pthread over -lpthread when available
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

add_library(pow_core src/pow_core.cpp src/pow_core.h)
# If pow_core uses std::thread, make pthread a PUBLIC dep so executables that
# link pow_core inherit it (prevents “DSO missing from command line”).
target_link_libraries(pow_core
  PUBLIC Threads::Threads
  PRIVATE OpenSSL::Crypto
)
target_include_directories(pow_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)

add_executable(pow_benchmark src/pow_benchmark.cpp)
target_link_libraries(pow_benchmark
  PRIVATE pow_core OpenSSL::Crypto OpenSSL::SSL
)
