include(CheckCXXSourceCompiles)

set(CMAKE_REQUIRED_FLAGS "-fsanitize-coverage=trace-pc")
unset(OPENPROOF_HAS_SANITIZER_COVERAGE_TRACE_PC CACHE)
check_cxx_source_compiles([[extern "C" void __sanitizer_cov_trace_pc() {}
int main() { return 0; }]] OPENPROOF_HAS_SANITIZER_COVERAGE_TRACE_PC)
unset(CMAKE_REQUIRED_FLAGS)
if(NOT OPENPROOF_HAS_SANITIZER_COVERAGE_TRACE_PC)
    message(FATAL_ERROR
        "OPENPROOF_BUILD_COVERAGE_FUZZER requires GCC sanitizer coverage trace-pc")
endif()

# GCC module BMIs must be compiled with the same flags as every synthesized
# importer. Instrument implementation units only: that measures the actual
# parser/control-flow code while keeping exported BMI CRCs stable.
set_property(SOURCE
    "${PROJECT_SOURCE_DIR}/src/foundation/encoding.cpp"
    TARGET_DIRECTORY openproof_foundation APPEND PROPERTY
    COMPILE_OPTIONS -fsanitize-coverage=trace-pc)
set_property(SOURCE
    "${PROJECT_SOURCE_DIR}/src/security/jose.cpp"
    TARGET_DIRECTORY openproof_security APPEND PROPERTY
    COMPILE_OPTIONS -fsanitize-coverage=trace-pc)
set_property(SOURCE
    "${PROJECT_SOURCE_DIR}/src/credentials/credentials.cpp"
    TARGET_DIRECTORY openproof_credentials APPEND PROPERTY
    COMPILE_OPTIONS -fsanitize-coverage=trace-pc)
set_property(SOURCE
    "${PROJECT_SOURCE_DIR}/src/telemetry/telemetry.cpp"
    TARGET_DIRECTORY openproof_telemetry APPEND PROPERTY
    COMPILE_OPTIONS -fsanitize-coverage=trace-pc)
set_property(SOURCE
    "${PROJECT_SOURCE_DIR}/src/client/model.cpp"
    TARGET_DIRECTORY openproof_client APPEND PROPERTY
    COMPILE_OPTIONS -fsanitize-coverage=trace-pc)
set_property(SOURCE
    "${PROJECT_SOURCE_DIR}/src/gateway/gateway.cpp"
    TARGET_DIRECTORY openproof_gateway APPEND PROPERTY
    COMPILE_OPTIONS -fsanitize-coverage=trace-pc)

add_executable(openproof_boundary_fuzzer
    boundary_fuzzer.cpp
    coverage_runtime.cpp)
target_compile_features(openproof_boundary_fuzzer PRIVATE cxx_std_26)
target_compile_definitions(openproof_boundary_fuzzer PRIVATE
    OPENPROOF_FUZZ_DEFAULT_CORPUS="${CMAKE_CURRENT_SOURCE_DIR}/corpus")
set_target_properties(openproof_boundary_fuzzer PROPERTIES
    CXX_SCAN_FOR_MODULES ON
    CXX_EXTENSIONS OFF)

# The runtime callback must never instrument itself or it would recurse before
# it can record the caller. Only OpenProof parser/domain targets above receive
# trace-pc instrumentation; the mutation engine deliberately does not.
set_source_files_properties(coverage_runtime.cpp boundary_fuzzer.cpp PROPERTIES
    COMPILE_OPTIONS "-fno-sanitize-coverage=trace-pc")

target_link_libraries(openproof_boundary_fuzzer PRIVATE
    openproof_foundation
    openproof_security
    openproof_credentials
    openproof_telemetry
    openproof_client
    openproof_gateway
    openproof_test_compile_options)
