openproof_add_module(openproof_reference_identity_adapter
    MODULES
        identity_adapter.cppm
    SOURCES
        identity_adapter.cpp
    LINK_PUBLIC
        openproof_sdk_cpp
        openproof_foundation
)

add_executable(openproof_reference_client main.cpp)
target_compile_features(openproof_reference_client PRIVATE cxx_std_26)
set_target_properties(openproof_reference_client PROPERTIES
    CXX_SCAN_FOR_MODULES ON
    CXX_EXTENSIONS OFF
)
target_link_libraries(openproof_reference_client PRIVATE
    openproof_compile_options
    openproof_reference_identity_adapter
)
