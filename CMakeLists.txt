cmake_minimum_required(VERSION 3.20)
project(nyx LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

add_compile_options(-Wall -Wextra -Wpedantic)

# --- core library: DER tree, parser, serializer, mutator, scheduler ---------
add_library(nyx_core
  src/der_parser.cpp
  src/der_serializer.cpp
  src/mutator.cpp
  # src/scheduler.cpp      # phase 3
  # src/grammar_x509.cpp   # phase 2b
  # src/coverage.cpp       # phase 0-1
)
target_include_directories(nyx_core PUBLIC include)

# --- fuzzer driver ----------------------------------------------------------
add_executable(nyx src/main.cpp)
target_link_libraries(nyx PRIVATE nyx_core)

# --- tests ------------------------------------------------------------------
enable_testing()
add_executable(test_roundtrip tests/test_roundtrip.cpp)
target_link_libraries(test_roundtrip PRIVATE nyx_core)
add_test(NAME roundtrip COMMAND test_roundtrip)

# Optional: build with sanitizers for local bug-hunting on the engine itself.
option(NYX_ASAN "Build with AddressSanitizer + UBSan" OFF)
if(NYX_ASAN)
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
  add_link_options(-fsanitize=address,undefined)
endif()
