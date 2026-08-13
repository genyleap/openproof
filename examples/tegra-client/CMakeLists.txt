openproof_add_module(openproof_tegra_identity_adapter
    MODULES
        tegra_identity.cppm
    SOURCES
        tegra_identity.cpp
    LINK_PUBLIC
        openproof_sdk_cpp
        openproof_foundation
)

add_executable(openproof_tegra_client main.cpp)
target_compile_features(openproof_tegra_client PRIVATE cxx_std_26)
set_target_properties(openproof_tegra_client PROPERTIES
    CXX_SCAN_FOR_MODULES ON
    CXX_EXTENSIONS OFF
)
target_link_libraries(openproof_tegra_client PRIVATE
    openproof_compile_options
    openproof_tegra_identity_adapter
)
