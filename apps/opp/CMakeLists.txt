add_executable(opp main.cpp)

target_compile_features(opp PRIVATE cxx_std_26)

set_target_properties(opp PROPERTIES
    CXX_SCAN_FOR_MODULES ON
    CXX_EXTENSIONS OFF
)

# The build system is the only component that knows the version, so it injects
# it. main.cpp immediately binds it to a constexpr constant; no other code sees
# the macro.
target_compile_definitions(opp PRIVATE
    OPENPROOF_VERSION="${PROJECT_VERSION}"
    OPENPROOF_CONTRACT_SEMANTIC="${OPENPROOF_CONTRACT_SEMANTIC}"
)

# C++26 #embed resolves its operand against the include path, so the directory
# holding default_config.toml must be on it. Listing the file as a dependency
# makes the build re-run when the embedded defaults change.
target_include_directories(opp PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
set_property(TARGET opp APPEND PROPERTY
    CMAKE_CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/default_config.toml")
set_source_files_properties(main.cpp PROPERTIES
    OBJECT_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/default_config.toml")

target_link_libraries(opp
    PRIVATE
        openproof_foundation
        openproof_administration
        openproof_audit
        openproof_config
        openproof_observability
        openproof_identity_provider
        openproof_identity_core
        openproof_authentication
        openproof_authentication_http
        openproof_credentials
        openproof_provider_local
        openproof_storage_postgres
        openproof_organization
        openproof_session
        openproof_gateway
        openproof_gateway_http
        openproof_security
        openproof_policy
        openproof_compile_options
)
