# Layering is enforced by the link graph: every edge below points downward.
#
#   identity.provider ──┐
#   storage ────────────┤
#   config ─────────────┼──> observability ──> foundation
#   security ───────────┘
#
# foundation depends on nothing. No layer imports a layer above it, and the
# identity provider SPI never imports a concrete provider (brief section 2).
add_subdirectory(foundation)
add_subdirectory(security)
add_subdirectory(observability)
add_subdirectory(audit)
add_subdirectory(telemetry)
add_subdirectory(config)
add_subdirectory(identity/provider)
add_subdirectory(identity/core)
add_subdirectory(authentication)
add_subdirectory(session)
add_subdirectory(credentials)
add_subdirectory(providers/local)
add_subdirectory(organization)
add_subdirectory(policy)
add_subdirectory(gateway)
add_subdirectory(authentication/http)
add_subdirectory(storage/postgres)
