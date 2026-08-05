# toml++ is consumed in header-only mode, deliberately not through the
# `tomlplusplus::tomlplusplus` imported target.
#
# That target forces `-DTOML_HEADER_ONLY=0 -DTOML_SHARED_LIB=1` and links a
# prebuilt shared library compiled with exceptions enabled. This project needs
# the parser's non-throwing API: an exception thrown from a header-only library
# included in a named module's global module fragment is not matched by a catch
# handler inside that module's implementation unit on the supported toolchain
# (see the comment in config.cpp). toml++ selects its ABI by inline namespace
# (`ex` vs `noex`), so requesting the non-throwing API while linking the
# exception-enabled binary fails at link time with undefined `toml::v3::noex`
# symbols.
#
# Header-only is toml++'s default and fully supported mode, so the include
# directory is taken from the package while the shared library is not linked.
get_target_property(GIP_TOMLPLUSPLUS_INCLUDE_DIRS
    tomlplusplus::tomlplusplus INTERFACE_INCLUDE_DIRECTORIES)

if(NOT GIP_TOMLPLUSPLUS_INCLUDE_DIRS)
    message(FATAL_ERROR
        "tomlplusplus was found but exposes no interface include directory.\n"
        "Remediation: install a tomlplusplus package that provides its headers, or point "
        "CMAKE_PREFIX_PATH at one.")
endif()

openproof_add_module(openproof_config
    MODULES
        config.cppm
    SOURCES
        config.cpp
    LINK_PUBLIC
        openproof_foundation
        openproof_observability
)

# Target-local, and only for this module (BLD-003). No toml type crosses the
# module interface, so nothing downstream inherits the parser (MOD-008).
target_include_directories(openproof_config SYSTEM PRIVATE ${GIP_TOMLPLUSPLUS_INCLUDE_DIRS})
target_compile_definitions(openproof_config PRIVATE TOML_HEADER_ONLY=1 TOML_EXCEPTIONS=0)
