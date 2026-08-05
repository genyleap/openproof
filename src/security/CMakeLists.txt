# OpenSSL is linked PRIVATE: its headers appear only in the global module
# fragment of the implementation units, and no OpenSSL type crosses this
# module's exported interface. Consumers of openproof.security never see the
# cryptographic provider (MOD-008, ARC-004).
openproof_add_module(openproof_security
    MODULES
        security.cppm
        random.cppm
        hash.cppm
    SOURCES
        random.cpp
        hash.cpp
    LINK_PUBLIC
        openproof_foundation
    LINK_PRIVATE
        OpenSSL::Crypto
)
