cmake_minimum_required(VERSION 3.20)
project(nyx LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

add_compile_options(-Wall -Wextra -Wpedantic)

# --- core library: DER tree, parser, serializer, mutator, coverage ----------
# NOTE: coverage.cpp is the SanitizerCoverage runtime and must NOT itself be
# instrumented. The default build adds no -fsanitize-coverage, so it is clean;
# only the fuzzing targets are compiled with instrumentation (see below).
add_library(nyx_core
  src/der_parser.cpp
  src/der_serializer.cpp
  src/mutator.cpp
  src/coverage.cpp
  src/corpus.cpp
  src/byte_mutator.cpp
  src/engine.cpp
  # src/scheduler.cpp      # phase 3
  # src/grammar_x509.cpp   # phase 2b
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

# Phase-0 coverage test needs Clang's SanitizerCoverage (-fsanitize-coverage).
# The demo target is compiled WITH instrumentation; the runtime (in nyx_core) is
# not. Skipped automatically on non-Clang compilers.
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  add_library(phase0_target STATIC tests/phase0_target.c)
  target_compile_options(phase0_target PRIVATE
    -O0 -fsanitize-coverage=trace-pc-guard,trace-cmp)
  add_executable(test_coverage tests/test_coverage.cpp)
  target_link_libraries(test_coverage PRIVATE nyx_core phase0_target)
  add_test(NAME coverage COMMAND test_coverage)

  # Phase-1: coverage-guided loop against an instrumented demo target with a bug.
  add_library(phase1_target STATIC tests/phase1_target.c)
  target_compile_options(phase1_target PRIVATE
    -O0 -fsanitize-coverage=trace-pc-guard,trace-cmp)
  add_executable(test_engine tests/test_engine.cpp)
  target_link_libraries(test_engine PRIVATE nyx_core phase1_target)
  add_test(NAME engine COMMAND test_engine)
endif()

# Optional: build with sanitizers for local bug-hunting on the engine itself.
option(NYX_ASAN "Build with AddressSanitizer + UBSan" OFF)
if(NYX_ASAN)
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
  add_link_options(-fsanitize=address,undefined)
endif()
