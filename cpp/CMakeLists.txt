cmake_minimum_required(VERSION 3.16)

if(POLICY CMP0135)
  cmake_policy(SET CMP0135 NEW)
endif()

project(work_challenge LANGUAGES CXX)

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

add_library(work_core work_core.cpp work_core.h)
target_include_directories(work_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(work_core
  PUBLIC Threads::Threads
  PRIVATE OpenSSL::Crypto
)
enable_sanitizers(work_core)

add_executable(work_challenge work_challenge.cpp)
target_link_libraries(work_challenge
  PRIVATE work_core OpenSSL::Crypto OpenSSL::SSL
)
enable_sanitizers(work_challenge)

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

  add_executable(work_core_test tests/work_core_test.cpp)
  target_include_directories(work_core_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
  target_link_libraries(work_core_test
    PRIVATE
      work_core
      GTest::gtest_main
      OpenSSL::SSL
      OpenSSL::Crypto
      Threads::Threads
  )
  enable_sanitizers(work_core_test)

  include(GoogleTest)
  gtest_discover_tests(work_core_test)
endif()

install(TARGETS work_challenge
  RUNTIME DESTINATION tlslp/_bin
)