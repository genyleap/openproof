#pragma once
#include <optional>

import openproof.foundation;
import openproof.session;
import openproof.identity.profile;

namespace openproof::storage::postgres {
namespace async_detail { struct QueryRows; }

// Decode only the already-bounded result of the authoritative SQL snapshot.
// The caller retains lease ownership and maps exceptions to Unavailable.
[[nodiscard]] foundation::Result<session::DelegatedAccess> decodeDelegatedAccess(
    const async_detail::QueryRows& result, foundation::Instant now,
    foundation::Instant* issuedAt,
    std::optional<identity::profile::IdentityProfile>* selectedProfile);
}
