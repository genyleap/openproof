#pragma once

#include <boost/json.hpp>

namespace openproof::oauth::http::detail {

[[nodiscard]] inline bool joseProtectedHeaderUsesSupportedExtensions(
    const boost::json::object& header) noexcept
{
    return !header.contains("crit") && !header.contains("b64");
}

} // namespace openproof::oauth::http::detail
