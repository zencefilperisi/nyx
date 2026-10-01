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
  src/grammar_x509.cpp
  # src/scheduler.cpp      # phase 3
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

# The instrumented demo targets are C files that need Clang's SanitizerCoverage
# (-fsanitize-coverage=trace-pc-guard,trace-cmp), which GCC does not support.
# Guard on the C compiler (that's what builds them), so a gcc C compiler -- even
# alongside clang++ -- correctly skips these instead of failing the build.
if(CMAKE_C_COMPILER_ID MATCHES "Clang")
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

  # Phase-2: structure-aware mutator vs byte-level on a structure-gated target.
  add_library(phase2_target STATIC tests/phase2_target.c)
  target_compile_options(phase2_target PRIVATE
    -O0 -fsanitize-coverage=trace-pc-guard,trace-cmp)
  add_executable(test_structure tests/test_structure.cpp)
  target_link_libraries(test_structure PRIVATE nyx_core phase2_target)
  add_test(NAME structure COMMAND test_structure)

  # Phase-2b: X.509 semantic grammar vs generic structure-aware.
  add_library(phase2b_target STATIC tests/phase2b_target.c)
  target_compile_options(phase2b_target PRIVATE
    -O0 -fsanitize-coverage=trace-pc-guard,trace-cmp)
  add_executable(test_x509 tests/test_x509.cpp)
  target_link_libraries(test_x509 PRIVATE nyx_core phase2b_target)
  add_test(NAME x509 COMMAND test_x509)
endif()

# Optional: build with sanitizers for local bug-hunting on the engine itself.
option(NYX_ASAN "Build with AddressSanitizer + UBSan" OFF)
if(NYX_ASAN)
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
  add_link_options(-fsanitize=address,undefined)
endif()
