cmake_minimum_required(VERSION 3.16)
project(pow_challenge LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Prefer -pthread over -lpthread when available
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

# --- options to flip sanitizers on/off per build tree ---
option(ENABLE_ASAN "Enable AddressSanitizer (+UBSan)" OFF)
option(ENABLE_TSAN "Enable ThreadSanitizer" OFF)

# Don’t let both be on at once
if (ENABLE_ASAN AND ENABLE_TSAN)
  message(FATAL_ERROR "ENABLE_ASAN and ENABLE_TSAN are mutually exclusive")
endif()

# Helper to add sanitizer flags to a target (GCC/Clang)
function(enable_sanitizers target)
  if (MSVC)
    return()
  endif()

  if (ENABLE_ASAN)
    target_compile_options(${target} PRIVATE
      -O1 -g -fno-omit-frame-pointer
      -fsanitize=address,undefined
      -fno-sanitize-recover=undefined
    )
    target_link_options(${target} PRIVATE -fsanitize=address,undefined)
    # Optional: GCC sometimes needs explicit leak
    # target_compile_options(${target} PRIVATE -fsanitize=leak)
    # target_link_options(${target}    PRIVATE -fsanitize=leak)
  endif()

  if (ENABLE_TSAN)
    target_compile_options(${target} PRIVATE
      -O1 -g -fno-omit-frame-pointer
      -fsanitize=thread
    )
    target_link_options(${target} PRIVATE -fsanitize=thread)
  endif()
endfunction()

add_library(pow_core src/pow_core.cpp src/pow_core.h)
target_include_directories(pow_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(pow_core
  PUBLIC Threads::Threads
  PRIVATE OpenSSL::Crypto
)
enable_sanitizers(pow_core)

add_executable(pow_challenge src/pow_challenge.cpp)
target_link_libraries(pow_challenge
  PRIVATE pow_core OpenSSL::Crypto OpenSSL::SSL
)
enable_sanitizers(pow_challenge)

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
target_include_directories(pow_core_test PRIVATE ${CMAKE_SOURCE_DIR}/src)
enable_sanitizers(pow_core_test)

include(GoogleTest)
gtest_discover_tests(pow_core_test)

target_link_libraries(pow_core_test
    PRIVATE
        pow_core
        GTest::gtest_main
        OpenSSL::SSL
        OpenSSL::Crypto
        Threads::Threads
)