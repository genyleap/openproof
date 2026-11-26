#pragma once
#include <optional>
import openproof.gateway;
namespace openproof::account::http {
[[nodiscard]] gateway::HttpResponse renderRecoveryPage();
[[nodiscard]] gateway::HttpResponse renderSecurityPage(std::optional<bool> enabled,bool ial2);
}
