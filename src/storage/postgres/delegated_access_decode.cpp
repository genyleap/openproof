#include "async_connection.hpp"
#include <algorithm>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>
#include <vector>
#include "delegated_access_decode.hpp"

import openproof.identity.core;
import openproof.identity.provider;

namespace openproof::storage::postgres {
namespace core=identity::core;
namespace idp=identity::provider;
namespace profile=identity::profile;
namespace {
using Row=std::vector<std::optional<std::string>>;
// Borrow only within the decoder; all domain objects own their fields.
[[nodiscard]] const std::string& required(const std::optional<std::string>& field)
{
    if (!field) throw std::runtime_error{"Malformed canonical identity row"};
    return *field;
}
[[nodiscard]] std::int64_t milliseconds(const std::optional<std::string>& field)
{
    const auto& value=required(field);
    std::int64_t parsed{};
    const auto [end,error]=std::from_chars(value.data(),value.data()+value.size(),parsed);
    if (error!=std::errc{} || end!=value.data()+value.size() || parsed<0)
        throw std::runtime_error{"Malformed canonical profile timestamp"};
    return parsed;
}
[[nodiscard]] bool boolean(const std::optional<std::string>& field)
{
    const auto& value=required(field);
    if (value=="t") return true;
    if (value=="f") return false;
    throw std::runtime_error{"Malformed canonical profile boolean"};
}
[[nodiscard]] std::optional<std::string> text(const Row& row,std::size_t index)
{
    return row.at(index);
}
}

foundation::Result<session::DelegatedAccess> decodeDelegatedAccess(
    const async_detail::QueryRows& result,foundation::Instant now,
    foundation::Instant* issuedAt,std::optional<profile::IdentityProfile>* selectedProfile)
{
    constexpr std::size_t maximumGrants=256U;
    if (result.rows.empty())
        return foundation::fail(foundation::ErrorCode::AuthenticationFailed);
    const std::size_t expectedFields=selectedProfile?25U:13U;
    if (result.rows.size()>maximumGrants || result.rows.front().size()!=expectedFields)
        return foundation::fail(foundation::ErrorCode::Unavailable);
    const auto& row=result.rows.front();
    const auto assurance=milliseconds(row[2]);
    const auto factors=milliseconds(row[3]);
    if (assurance>4 || factors>7 || row[8].has_value()!=row[9].has_value())
        return foundation::fail(foundation::ErrorCode::AuthenticationFailed);
    std::optional<session::DelegatedSenderConstraint> sender;
    if (row[8]) {
        const auto kind=milliseconds(row[8]);
        if (kind>1 || row[9]->empty() || row[9]->size()>256U)
            return foundation::fail(foundation::ErrorCode::AuthenticationFailed);
        sender.emplace(kind==0?session::DelegatedSenderConstraintKind::Dpop
            :session::DelegatedSenderConstraintKind::Mtls,*row[9]);
    }
    std::vector<std::string> scopes,audiences;
    const Row* profileRow=nullptr;
    for (const auto& grant:result.rows) {
        if (grant.size()!=expectedFields || !std::equal(row.begin(),row.begin()+10,grant.begin())
            || grant[12]!=row[12])
            return foundation::fail(foundation::ErrorCode::Unavailable);
        if (selectedProfile) {
            if (grant[13]) {
                if (profileRow || sender || grant[13]!=row[0]
                    || grant[10]!=std::optional<std::string>{"0"}
                    || grant[11]!=std::optional<std::string>{"openid"})
                    return foundation::fail(foundation::ErrorCode::Unavailable);
                profileRow=&grant;
            } else if (std::any_of(grant.begin()+14,grant.end(),
                [](const auto& field){return field.has_value();})) {
                return foundation::fail(foundation::ErrorCode::Unavailable);
            }
        }
        if (!grant[10] && !grant[11]) {
            if (result.rows.size()!=1U) return foundation::fail(foundation::ErrorCode::Unavailable);
            continue;
        }
        if (!grant[10] || !grant[11])
            return foundation::fail(foundation::ErrorCode::Unavailable);
        const auto kind=milliseconds(grant[10]);
        const auto& value=*grant[11];
        if (kind==0 && !value.empty() && value.size()<=128U
            && std::ranges::all_of(value,[](char ch){
                const auto byte=static_cast<unsigned char>(ch);
                return byte==0x21U || (byte>=0x23U && byte<=0x5BU)
                    || (byte>=0x5DU && byte<=0x7EU);
            })) {
            scopes.push_back(value);
        } else if (kind==1 && !value.empty() && value.size()<=2048U
            && std::ranges::none_of(value,[](char ch){
                const auto byte=static_cast<unsigned char>(ch);
                return byte<0x20U || byte==0x7fU;
            })) {
            audiences.push_back(value);
        } else return foundation::fail(foundation::ErrorCode::Unavailable);
    }
    auto authorized=session::AuthenticatedSession::fromDelegatedAccess(
        core::IdentityId{required(row[0])},idp::ProviderId{required(row[1])},
        static_cast<idp::AssuranceLevel>(assurance),
        idp::AuthenticationStrength{static_cast<idp::AuthenticationFactor>(factors),boolean(row[4])},
        foundation::Instant{foundation::Duration{milliseconds(row[5])}},now,
        foundation::Instant{foundation::Duration{milliseconds(row[6])}});
    if (!authorized) return foundation::fail(authorized.error());
    const auto issued=foundation::Instant{foundation::Duration{milliseconds(row[12])}};
    if (issued>now || issued>=foundation::Instant{foundation::Duration{milliseconds(row[6])}})
        return foundation::fail(foundation::ErrorCode::Unavailable);
    auto access=session::DelegatedAccess{std::move(authorized).value(),required(row[7]),
        std::move(scopes),std::move(audiences),std::move(sender)};
    if (profileRow) {
        // Do not restore or expose a profile unless the fully decoded
        // live access grant independently authorizes those claims.
        if (!selectedProfile || access.senderConstraint() || !access.permits("openid")
            || (!access.permits("profile") && !access.permits("email")))
            return foundation::fail(foundation::ErrorCode::Unavailable);
        const auto& fields=*profileRow;
        auto value=profile::IdentityProfile::restore(
            access.authenticated().session().identity(),
            text(fields,14),text(fields,15),text(fields,16),boolean(fields[17]),
            text(fields,18),boolean(fields[19]),text(fields,20),text(fields,21),
            foundation::Instant{foundation::Duration{milliseconds(fields[23])}},
            foundation::Instant{foundation::Duration{milliseconds(fields[24])}},
            required(fields[22]));
        if (!value) return foundation::fail(foundation::ErrorCode::Unavailable);
        selectedProfile->emplace(std::move(value).value());
    }
    if (issuedAt) *issuedAt=issued;
    return foundation::Result<session::DelegatedAccess>{std::move(access)};
}
}
