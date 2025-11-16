cmake_minimum_required(VERSION 3.16)
project(pow_benchmark LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Prefer -pthread over -lpthread when available
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

add_library(pow_core src/pow_core.cpp src/pow_core.h)
target_include_directories(pow_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(pow_core
  PUBLIC Threads::Threads
  PRIVATE OpenSSL::Crypto
)

add_executable(pow_benchmark src/pow_benchmark.cpp)
target_link_libraries(pow_benchmark
  PRIVATE pow_core OpenSSL::Crypto OpenSSL::SSL
)

include(FetchContent)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
)
# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

enable_testing()

add_executable(pow_core_test
  src/tests/pow_core_test.cpp
)

include(GoogleTest)
gtest_discover_tests(pow_core_test)

target_link_libraries(pow_core_test
    PRIVATE
        GTest::gtest_main
        OpenSSL::SSL
        OpenSSL::Crypto
        Threads::Threads
)