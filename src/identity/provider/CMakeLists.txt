# The SPI depends only on shared foundation/security primitives and the
# provider-neutral Boost.Asio coroutine type. Never link a concrete provider.
openproof_add_module(openproof_identity_provider
    MODULES
        provider.cppm
        assurance.cppm
        outcome.cppm
        authenticator.cppm
        transaction.cppm
        registry.cppm
    SOURCES
        assurance.cpp
        outcome.cpp
        authenticator.cpp
        transaction.cpp
        registry.cpp
    LINK_PUBLIC
        openproof_foundation
        # Public coroutine awaitable types must use the exact same Boost.Asio
        # headers as concrete providers. System Boost and pinned Boost 1.88
        # cannot coexist inside GCC16 C++ module BMIs.
        Boost::headers
        # openproof_security is a downward, non-domain dependency: the transaction
        # model compares nonces and bindings in constant time, and that check
        # belongs with the invariant rather than duplicated in every provider.
        openproof_security
)
