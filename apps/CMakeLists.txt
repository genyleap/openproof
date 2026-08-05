# opp is the unified platform process. Identity, policy and the gateway are
# separate modules inside one deployable (brief section 72); their boundaries are
# enforced by the module graph, so extracting them into separate processes later
# does not require redesigning the domain.
#
# opp, the administrative CLI, arrives once there is an administrative API
# for it to call. It is not stubbed here: an executable that does nothing would
# be a claim of progress rather than progress.
add_subdirectory(opp)
