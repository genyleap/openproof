module;

#include <cstddef>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

module openproof.identity.provider;

namespace openproof::identity::provider {

std::string_view transactionStateName(TransactionState state) noexcept
{
    switch (state) {
    case TransactionState::Pending:
        return "pending";
    case TransactionState::Consumed:
        return "consumed";
    case TransactionState::Failed:
        return "failed";
    case TransactionState::Expired:
        return "expired";
    }
    return "failed";
}

AuthenticationTransaction::AuthenticationTransaction(TransactionId id, ProviderId provider,
                                                     InteractionModel model,
                                                     security::Sha256Digest nonceDigest,
                                                     BindingDigest binding,
                                                     foundation::CorrelationId correlation,
                                                     foundation::Instant createdAt,
                                                     foundation::Instant expiresAt)
    : m_id(std::move(id))
    , m_provider(std::move(provider))
    , m_interactionModel(model)
    , m_nonceDigest(nonceDigest)
    , m_binding(binding)
    , m_correlation(std::move(correlation))
    , m_createdAt(createdAt)
    , m_expiresAt(expiresAt)
{
}

foundation::Result<AuthenticationTransaction>
AuthenticationTransaction::create(TransactionId id, ProviderId provider, InteractionModel model,
                                  foundation::SecretString nonce, BindingDigest binding,
                                  foundation::CorrelationId correlation,
                                  foundation::Instant createdAt, foundation::Duration lifetime)
{
    if (id.empty()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "An authentication transaction must have an identifier.");
    }
    if (provider.empty()) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "An authentication transaction must name its provider.");
    }
    if (nonce.empty()) {
        // An empty nonce makes the constant-time comparison in consume() succeed
        // for an empty presented value, which removes the protection entirely.
        return foundation::fail(
            foundation::ErrorCode::InvalidArgument,
            "An authentication transaction must carry a nonce.",
            "A transaction was created with an empty nonce; every redemption check "
            "against it would be trivially satisfiable.");
    }
    if (lifetime <= foundation::Duration::zero()) {
        return foundation::fail(
            foundation::ErrorCode::InvalidArgument,
            "An authentication transaction must have a positive lifetime.",
            "A non-positive lifetime yields a transaction that is expired at issue time.");
    }

    const foundation::Result<security::Sha256Digest> nonceDigest =
        security::sha256(nonce.expose());
    if (!nonceDigest.has_value()) {
        return foundation::fail(nonceDigest.error());
    }

    return AuthenticationTransaction{std::move(id),          std::move(provider),
                                     model,                  nonceDigest.value(),
                                     binding,                std::move(correlation),
                                     createdAt,              createdAt + lifetime};
}

foundation::Result<AuthenticationTransaction> AuthenticationTransaction::restore(
    TransactionId id, ProviderId provider, InteractionModel model,
    security::Sha256Digest nonceDigest, BindingDigest binding,
    foundation::CorrelationId correlation, TransactionState state,
    foundation::Instant createdAt, foundation::Instant expiresAt,
    AttributeMap metadata)
{
    if (id.empty() || provider.empty() || correlation.empty() || expiresAt <= createdAt) {
        return foundation::fail(foundation::ErrorCode::InvalidArgument,
                                "The persisted authentication transaction is invalid.");
    }
    AuthenticationTransaction restored{
        std::move(id), std::move(provider), model, nonceDigest, binding,
        std::move(correlation), createdAt, expiresAt};
    restored.m_state = state;
    restored.m_metadata = std::move(metadata);
    return restored;
}

const TransactionId& AuthenticationTransaction::id() const noexcept
{
    return m_id;
}

const ProviderId& AuthenticationTransaction::provider() const noexcept
{
    return m_provider;
}

InteractionModel AuthenticationTransaction::interactionModel() const noexcept
{
    return m_interactionModel;
}

const foundation::CorrelationId& AuthenticationTransaction::correlation() const noexcept
{
    return m_correlation;
}

TransactionState AuthenticationTransaction::state() const noexcept
{
    return m_state;
}

foundation::Instant AuthenticationTransaction::createdAt() const noexcept
{
    return m_createdAt;
}

foundation::Instant AuthenticationTransaction::expiresAt() const noexcept
{
    return m_expiresAt;
}

const security::Sha256Digest& AuthenticationTransaction::nonceDigest() const noexcept
{
    return m_nonceDigest;
}

const BindingDigest& AuthenticationTransaction::binding() const noexcept
{
    return m_binding;
}

bool AuthenticationTransaction::isExpiredAt(foundation::Instant now) const noexcept
{
    // Inclusive: a transaction presented exactly at its deadline is rejected.
    // The boundary is resolved in the safe direction.
    return now >= m_expiresAt;
}

bool AuthenticationTransaction::isPendingAt(foundation::Instant now) const noexcept
{
    return m_state == TransactionState::Pending && !isExpiredAt(now);
}

const AttributeMap& AuthenticationTransaction::metadata() const noexcept
{
    return m_metadata;
}

void AuthenticationTransaction::setMetadata(std::string key, std::string value)
{
    m_metadata.insert_or_assign(std::move(key), std::move(value));
}

foundation::Status AuthenticationTransaction::consume(
                                                      const foundation::SecretString& presentedNonce,
                                                      const BindingDigest& presentedBinding,
                                                      foundation::Instant now)
{
    // Replay: the state has already left Pending, so this is a second redemption.
    if (m_state != TransactionState::Pending) {
        return foundation::fail(
            foundation::ErrorCode::FailedPrecondition,
            "This authentication request is no longer valid.",
            std::string{"Transaction redemption refused; state is "}
                + std::string{transactionStateName(m_state)}
                + ". A transaction is redeemable exactly once.");
    }

    if (isExpiredAt(now)) {
        m_state = TransactionState::Expired;
        return foundation::fail(foundation::ErrorCode::FailedPrecondition,
                                "This authentication request has expired.",
                                "Transaction redemption refused: deadline passed.");
    }

    // Both comparisons run in constant time and both are evaluated before any
    // decision is returned, so the failure path does not reveal which check
    // failed through timing or through the message.
    const foundation::Result<security::Sha256Digest> presentedNonceDigest =
        security::sha256(presentedNonce.expose());
    if (!presentedNonceDigest.has_value()) {
        m_state = TransactionState::Failed;
        return foundation::fail(presentedNonceDigest.error());
    }

    const bool nonceMatches =
        security::constantTimeEquals(m_nonceDigest, presentedNonceDigest.value());
    const bool bindingMatches = security::constantTimeEquals(m_binding, presentedBinding);

    if (!nonceMatches || !bindingMatches) {
        // Terminal on failure. Leaving it Pending would turn the transaction
        // into an oracle that an attacker could probe repeatedly.
        m_state = TransactionState::Failed;
        return foundation::fail(
            foundation::ErrorCode::AuthenticationFailed,
            std::string{
                foundation::defaultErrorMessage(foundation::ErrorCode::AuthenticationFailed)},
            nonceMatches ? "Transaction binding mismatch: the answer was presented by a "
                           "different agent than the one that started it."
                         : "Transaction nonce mismatch.");
    }

    m_state = TransactionState::Consumed;
    return foundation::ok();
}

void AuthenticationTransaction::markFailed() noexcept
{
    if (m_state == TransactionState::Pending) {
        m_state = TransactionState::Failed;
    }
}

void AuthenticationTransaction::markExpired() noexcept
{
    if (m_state == TransactionState::Pending) {
        m_state = TransactionState::Expired;
    }
}

foundation::Status InMemoryAuthenticationTransactionStore::begin(
    AuthenticationTransaction transaction)
{
    const std::lock_guard<std::mutex> guard{m_mutex};

    if (m_transactions.contains(transaction.id())) {
        return foundation::fail(
            foundation::ErrorCode::AlreadyExists,
            "This authentication request could not be started.",
            "A transaction identifier was reused. Overwriting the existing entry would "
            "discard an in-flight transaction belonging to another subject.");
    }

    const TransactionId id = transaction.id();
    m_transactions.emplace(id, std::move(transaction));
    return foundation::ok();
}

foundation::Result<AuthenticationTransaction> InMemoryAuthenticationTransactionStore::consume(
    const TransactionId& id, const foundation::SecretString& presentedNonce,
    const BindingDigest& presentedBinding, foundation::Instant now)
{
    // The lock spans validation and state change together. Splitting them would
    // let two concurrent redemptions both observe Pending and both succeed,
    // which is exactly the property this store exists to prevent.
    const std::lock_guard<std::mutex> guard{m_mutex};

    const auto position = m_transactions.find(id);
    if (position == m_transactions.end()) {
        return foundation::fail(
            foundation::ErrorCode::AuthenticationFailed,
            std::string{
                foundation::defaultErrorMessage(foundation::ErrorCode::AuthenticationFailed)},
            "Transaction redemption refused: unknown identifier.");
    }

    const foundation::Status outcome =
        position->second.consume(presentedNonce, presentedBinding, now);
    if (!outcome.has_value()) {
        return foundation::fail(outcome.error());
    }

    return position->second;
}

foundation::Result<std::optional<AuthenticationTransaction>>
InMemoryAuthenticationTransactionStore::find(const TransactionId& id) const
{
    const std::lock_guard<std::mutex> guard{m_mutex};

    const auto position = m_transactions.find(id);
    if (position == m_transactions.end()) {
        return std::optional<AuthenticationTransaction>{};
    }
    return std::optional<AuthenticationTransaction>{position->second};
}

std::size_t InMemoryAuthenticationTransactionStore::purgeExpired(foundation::Instant now)
{
    const std::lock_guard<std::mutex> guard{m_mutex};

    std::size_t removed = 0;
    for (auto position = m_transactions.begin(); position != m_transactions.end();) {
        if (position->second.isExpiredAt(now)) {
            position = m_transactions.erase(position);
            ++removed;
        } else {
            ++position;
        }
    }
    return removed;
}

std::size_t InMemoryAuthenticationTransactionStore::size() const
{
    const std::lock_guard<std::mutex> guard{m_mutex};
    return m_transactions.size();
}

}
