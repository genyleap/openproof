if(APPLE)
    # Keep every Darwin system dependency in the canonical SDK selected before
    # project(). Do not use FindLibXml2/FindZLIB here: depending on the host
    # developer tools those modules may return an absolute CommandLineTools SDK
    # include path while the compiler/frameworks use the Xcode SDK, which is not
    # safe for GCC C++ module BMIs.
    if(NOT DEFINED OPENPROOF_MACOS_SDKROOT OR OPENPROOF_MACOS_SDKROOT STREQUAL "")
        message(FATAL_ERROR "OpenProof canonical macOS SDK was not configured.")
    endif()

    set(OPENPROOF_LIBXML2_INCLUDE_DIR "${OPENPROOF_MACOS_SDKROOT}/usr/include/libxml2")
    if(NOT EXISTS "${OPENPROOF_LIBXML2_INCLUDE_DIR}/libxml/parser.h")
        message(FATAL_ERROR
            "libxml2 headers are missing from the canonical macOS SDK: "
            "${OPENPROOF_LIBXML2_INCLUDE_DIR}")
    endif()
    openproof_require_path_in_macos_sdk("libxml2 headers" "${OPENPROOF_LIBXML2_INCLUDE_DIR}")

    set(OPENPROOF_LIBXML2_LIBRARY "${OPENPROOF_MACOS_SDKROOT}/usr/lib/libxml2.tbd")
    set(OPENPROOF_ZLIB_LIBRARY "${OPENPROOF_MACOS_SDKROOT}/usr/lib/libz.tbd")
    set(OPENPROOF_LDAP_FRAMEWORK
        "${OPENPROOF_MACOS_SDKROOT}/System/Library/Frameworks/LDAP.framework")

    foreach(required_native_path
            "${OPENPROOF_LIBXML2_LIBRARY}"
            "${OPENPROOF_ZLIB_LIBRARY}"
            "${OPENPROOF_LDAP_FRAMEWORK}")
        if(NOT EXISTS "${required_native_path}")
            message(FATAL_ERROR
                "Required Enterprise dependency is missing from the canonical macOS SDK: "
                "${required_native_path}")
        endif()
    endforeach()

    openproof_require_path_in_macos_sdk("libxml2 library" "${OPENPROOF_LIBXML2_LIBRARY}")
    openproof_require_path_in_macos_sdk("zlib library" "${OPENPROOF_ZLIB_LIBRARY}")
    openproof_require_path_in_macos_sdk("LDAP framework" "${OPENPROOF_LDAP_FRAMEWORK}")

    set(OPENPROOF_ENTERPRISE_NATIVE_LIBRARIES
        "${OPENPROOF_LIBXML2_LIBRARY}"
        "${OPENPROOF_ZLIB_LIBRARY}"
        "${OPENPROOF_LDAP_FRAMEWORK}"
    )
else()
    find_package(LibXml2 REQUIRED)
    find_package(ZLIB REQUIRED)
    find_path(OPENPROOF_LDAP_INCLUDE_DIR ldap.h REQUIRED)
    find_library(OPENPROOF_LDAP_LIBRARY NAMES ldap REQUIRED)
    find_library(OPENPROOF_LBER_LIBRARY NAMES lber REQUIRED)
    set(OPENPROOF_ENTERPRISE_NATIVE_LIBRARIES
        LibXml2::LibXml2
        ZLIB::ZLIB
        "${OPENPROOF_LDAP_LIBRARY}"
        "${OPENPROOF_LBER_LIBRARY}"
    )
endif()

openproof_add_module(openproof_provider_enterprise
    MODULES
        enterprise.cppm
    SOURCES
        enterprise.cpp
    LINK_PUBLIC
        openproof_foundation
        openproof_identity_provider
    LINK_PRIVATE
        openproof_security
        OpenSSL::Crypto
        ${OPENPROOF_ENTERPRISE_NATIVE_LIBRARIES}
)

if(APPLE)
    target_compile_definitions(openproof_provider_enterprise PRIVATE
        OPENPROOF_PLATFORM_APPLE=1
    )
    target_include_directories(openproof_provider_enterprise SYSTEM PRIVATE
        "${OPENPROOF_LIBXML2_INCLUDE_DIR}"
    )
else()
    target_compile_definitions(openproof_provider_enterprise PRIVATE
        OPENPROOF_PLATFORM_APPLE=0
    )
    target_include_directories(openproof_provider_enterprise SYSTEM PRIVATE
        "${OPENPROOF_LDAP_INCLUDE_DIR}"
    )
endif()
