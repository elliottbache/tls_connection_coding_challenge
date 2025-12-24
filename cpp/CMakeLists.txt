cmake_minimum_required(VERSION 3.16)

# Only set policies your CMake actually knows about
if(POLICY CMP0135)
  cmake_policy(SET CMP0135 NEW)
endif()

project(pow_challenge LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

option(ENABLE_ASAN "Enable AddressSanitizer (+UBSan)" OFF)
option(ENABLE_TSAN "Enable ThreadSanitizer" OFF)

if (ENABLE_ASAN AND ENABLE_TSAN)
  message(FATAL_ERROR "ENABLE_ASAN and ENABLE_TSAN are mutually exclusive")
endif()

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
  endif()

  if (ENABLE_TSAN)
    target_compile_options(${target} PRIVATE
      -O1 -g -fno-omit-frame-pointer
      -fsanitize=thread
    )
    target_link_options(${target} PRIVATE -fsanitize=thread)
  endif()
endfunction()

add_library(pow_core pow_core.cpp pow_core.h)
target_include_directories(pow_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(pow_core
  PUBLIC Threads::Threads
  PRIVATE OpenSSL::Crypto
)
enable_sanitizers(pow_core)

add_executable(pow_challenge pow_challenge.cpp)
target_link_libraries(pow_challenge
  PRIVATE pow_core OpenSSL::Crypto OpenSSL::SSL
)
enable_sanitizers(pow_challenge)

include(CTest)  # defines BUILD_TESTING option

if(BUILD_TESTING)
  enable_testing()

  include(FetchContent)

  FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/releases/download/v1.17.0/googletest-1.17.0.tar.gz
  )

  if(MSVC)
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
  endif()

  FetchContent_MakeAvailable(googletest)

  add_executable(pow_core_test tests/pow_core_test.cpp)
  target_include_directories(pow_core_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
  target_link_libraries(pow_core_test
    PRIVATE
      pow_core
      GTest::gtest_main
      OpenSSL::SSL
      OpenSSL::Crypto
      Threads::Threads
  )
  enable_sanitizers(pow_core_test)

  include(GoogleTest)
  gtest_discover_tests(pow_core_test)
endif()

install(TARGETS pow_challenge
  RUNTIME DESTINATION tlslp/_bin
)