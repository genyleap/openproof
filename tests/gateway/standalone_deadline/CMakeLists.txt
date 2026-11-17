cmake_minimum_required(VERSION 3.30)
project(openproof_steady_deadline_regression LANGUAGES CXX)

# Standalone production-header regression: no libpq, Boost or named-module
# dependency. Isolate compiler/clock arithmetic from the expensive gateway.
add_executable(openproof_steady_deadline_test ../steady_deadline_test.cpp)
target_compile_features(openproof_steady_deadline_test PRIVATE cxx_std_26)
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(openproof_steady_deadline_test PRIVATE
        -O2 -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Werror)
endif()
# The server's GCC 16 toolchain ships a newer C++ runtime than the host.
# Match OpenProof's existing test targets: link a self-contained test binary.
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND UNIX AND NOT APPLE)
    target_link_options(openproof_steady_deadline_test PRIVATE
        -static-libstdc++ -static-libgcc)
endif()
enable_testing()
add_test(NAME gateway.steady-deadline COMMAND openproof_steady_deadline_test)
