openproof_add_module(openproof_account_delivery
    MODULES
        delivery.cppm
    PRIVATE_MODULES
        delivery_impl.cppm
    LINK_PUBLIC
        openproof_account
        openproof_foundation
        openproof_gateway
        openproof_gateway_http
        Boost::headers
    LINK_PRIVATE
        openproof_security
)

# Match the Boost.Config correction used by the native Gateway target.
target_compile_definitions(openproof_account_delivery PRIVATE BOOST_HAS_LONG_LONG=1)
