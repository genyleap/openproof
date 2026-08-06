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
add_subdirectory(config)
add_subdirectory(identity/provider)
add_subdirectory(identity/core)
add_subdirectory(policy)
add_subdirectory(organization)
