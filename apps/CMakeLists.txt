# opp is the unified platform process. Identity, policy and the gateway are
# separate modules inside one deployable (brief section 72); their boundaries are
# enforced by the module graph, so extracting them into separate processes later
# does not require redesigning the domain.
#
# opp also owns the deliberately narrow offline bootstrap ceremony. Broader
# management commands arrive with the authenticated administrative API so they
# cannot develop a separate policy path.
add_subdirectory(opp)
