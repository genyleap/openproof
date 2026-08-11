openproof_add_module(openproof_telemetry
    MODULES telemetry.cppm
    SOURCES telemetry.cpp
    LINK_PUBLIC
        openproof_foundation
        openproof_security
)
