# Trusted authentication orchestration. Concrete providers remain behind the
# provider SPI; transport code depends on this target, not on provider methods.
openproof_add_module(openproof_authentication
    MODULES
        authentication.cppm
        service.cppm
    SOURCES
        service.cpp
        ${PROJECT_SOURCE_DIR}/src/gateway/asio_thread_context.cpp
    LINK_PUBLIC
        Boost::headers
        openproof_foundation
        openproof_security
        openproof_identity_provider
        openproof_identity_core
        openproof_identity_profile
)

# GCC 16.2's inliner misdiagnoses Boost.Asio's aligned coroutine-frame
# allocator as mismatched new/delete. Preserve -Werror globally and scope
# this workaround strictly to the coroutine authentication implementation.
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set_source_files_properties(service.cpp
        PROPERTIES COMPILE_OPTIONS "-fno-inline")
endif()
