#pragma once
#include <optional>
#include <string_view>
import openproof.gateway;
namespace openproof::account::http {
[[nodiscard]] gateway::HttpResponse renderRecoveryPage();
[[nodiscard]] gateway::HttpResponse renderSecurityPage(std::optional<bool> enabled,bool ial2,std::string_view assuranceName);
}
