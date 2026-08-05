module;

#include <cstddef>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>

export module openproof.identity.provider:transaction;

import openproof.foundation;
import openproof.security;

import :assurance;
import :authenticator;
import :outcome;

export namespace openproof::identity::provider {

/** @brief Tag for the identifier of an authentication transaction. */
struct TransactionIdTag {};

/**
 * @brief Identifies one authentication transaction. Server-issued and single-use.
 */
using TransactionId = foundation::StrongId<TransactionIdTag>;

/**
 * @brief Ties a transaction to the agent that started it.
 *
 * A digest rather than the raw value, so the store never holds the binding
 * secret itself. Typically derived from the caller's pre-authentication session
 * cookie: whatever the deployment chooses, it must be something an attacker
 * cannot supply on the victim's behalf.
 */
using BindingDigest = security::Sha256Digest;

/**
 * @brief Lifecycle of an authentication transaction.
 *
 * The states are deliberately few and the transitions one-way. A transaction
 * leaves @c Pending exactly once and never returns to it, which is what makes
 * replay detectable rather than merely unlikely.
 */
enum class TransactionState {
    Pending,  ///< Issued, awaiting the subject's response.
    Consumed, ///< Successfully completed. Terminal; a second attempt is a replay.
    Failed,   ///< Verification failed. Terminal.
    Expired,  ///< Deadline passed before completion. Terminal.
};

/** @brief Returns the stable wire name of @p state, for example "consumed". */
[[nodiscard]] std::string_view transactionStateName(TransactionState state) noexcept;

/**
 * @brief A provider-neutral, server-side authentication transaction.
 *
 * Every protocol this platform must support has the same dangerous shape: the
 * server issues something, the subject goes away, and something comes back
 * claiming to answer it. OIDC calls the pieces `state` and `nonce`, WebAuthn
 * calls it a challenge, a wallet flow calls it a SIWE nonce, a magic link calls
 * it a token, USSD calls it a session. They share the same four failure modes,
 * so those are closed here once rather than in each provider:
 *
 *  - **Replay.** A completed transaction is terminal. Presenting it again fails
 *    because the state has already left @c Pending.
 *  - **Nonce reuse or substitution.** The presented nonce is compared with the
 *    issued one in constant time; a mismatch fails the transaction outright
 *    rather than merely being ignored.
 *  - **Expired acceptance.** Expiry is evaluated against an injected clock at
 *    the moment of consumption, not at issue time.
 *  - **Cross-session substitution.** The transaction is bound to the agent that
 *    started it. An attacker who steals a valid callback cannot redeem it in
 *    their own session, which is the classic OAuth login-CSRF.
 *
 * A failed attempt is terminal on purpose. Allowing a transaction to stay
 * @c Pending after a bad nonce would turn it into an oracle an attacker could
 * probe repeatedly.
 *
 * @note Not thread-safe by itself. Concurrency is the store's responsibility,
 *       because single-use enforcement is only meaningful if the check and the
 *       state change are atomic together -- see
 *       @ref AuthenticationTransactionStore.
 */
class AuthenticationTransaction final {
public:
    /**
     * @brief Validates and creates a pending transaction.
     *
     * @param id           Server-issued, unpredictable identifier.
     * @param provider     The provider that will complete this transaction.
     * @param model        The provider's interaction shape, recorded for audit.
     * @param nonce        Server-issued single-use value. Must be unpredictable;
     *                     generate it with openproof::security::randomTokenBase64Url.
     * @param binding      Digest tying the transaction to the initiating agent.
     * @param correlation  Correlates this transaction with the request that began it.
     * @param createdAt    Issue time, from the injected clock.
     * @param lifetime     How long the transaction may be redeemed. Must be positive.
     *
     * @return ErrorCode::InvalidArgument when the identifier, provider or nonce
     *         is empty, or the lifetime is not positive. An empty nonce would
     *         make every comparison below trivially satisfiable.
     */
    [[nodiscard]] static foundation::Result<AuthenticationTransaction>
    create(TransactionId id, ProviderId provider, InteractionModel model, std::string nonce,
           BindingDigest binding, foundation::CorrelationId correlation,
           foundation::Instant createdAt, foundation::Duration lifetime);

    [[nodiscard]] const TransactionId& id() const noexcept;
    [[nodiscard]] const ProviderId& provider() const noexcept;
    [[nodiscard]] InteractionModel interactionModel() const noexcept;
    [[nodiscard]] const foundation::CorrelationId& correlation() const noexcept;
    [[nodiscard]] TransactionState state() const noexcept;
    [[nodiscard]] foundation::Instant createdAt() const noexcept;
    [[nodiscard]] foundation::Instant expiresAt() const noexcept;

    /** @brief Returns whether the deadline has passed at @p now. Inclusive. */
    [[nodiscard]] bool isExpiredAt(foundation::Instant now) const noexcept;

    /** @brief Returns whether the transaction is still redeemable at @p now. */
    [[nodiscard]] bool isPendingAt(foundation::Instant now) const noexcept;

    /**
     * @brief Provider-specific data carried alongside the transaction.
     *
     * Redirect URIs, PKCE challenges, RP identifiers, chain identifiers. Never
     * credential material: the store persists this verbatim.
     */
    [[nodiscard]] const AttributeMap& metadata() const noexcept;
    void setMetadata(std::string key, std::string value);

    /**
     * @brief Validates a presented answer and consumes the transaction.
     *
     * On success the transaction becomes @c Consumed. On any failure it becomes
     * @c Failed. Either way it is terminal, so this function can succeed at most
     * once for the lifetime of the object.
     *
     * @return ErrorCode::FailedPrecondition when the transaction is not pending
     *         or has expired; ErrorCode::AuthenticationFailed when the nonce or
     *         binding does not match. The two are distinguished for operators in
     *         the internal detail, never in the client-facing message.
     */
    [[nodiscard]] foundation::Status consume(std::string_view presentedNonce,
                                             const BindingDigest& presentedBinding,
                                             foundation::Instant now);

    /** @brief Marks the transaction failed without a redemption attempt. */
    void markFailed() noexcept;

    /** @brief Marks the transaction expired. */
    void markExpired() noexcept;

private:
    AuthenticationTransaction(TransactionId id, ProviderId provider, InteractionModel model,
                              std::string nonce, BindingDigest binding,
                              foundation::CorrelationId correlation,
                              foundation::Instant createdAt, foundation::Instant expiresAt);

    TransactionId m_id;
    ProviderId m_provider;
    InteractionModel m_interactionModel{InteractionModel::ChallengeResponse};
    std::string m_nonce;
    BindingDigest m_binding{};
    foundation::CorrelationId m_correlation;
    TransactionState m_state{TransactionState::Pending};
    foundation::Instant m_createdAt{};
    foundation::Instant m_expiresAt{};
    AttributeMap m_metadata;
};

/**
 * @brief Server-side custody of in-flight authentication transactions.
 *
 * This interface exists because single-use enforcement cannot be implemented
 * correctly by a caller that reads a transaction, checks it, and writes it back:
 * two concurrent redemptions of the same transaction would both observe
 * @c Pending and both succeed. @ref consume therefore performs validation and
 * state change as one atomic operation, and is the only supported way to redeem
 * a transaction.
 *
 * @note Implementations must be safe to call concurrently.
 */
class AuthenticationTransactionStore {
public:
    AuthenticationTransactionStore(const AuthenticationTransactionStore&) = delete;
    AuthenticationTransactionStore& operator=(const AuthenticationTransactionStore&) = delete;
    AuthenticationTransactionStore(AuthenticationTransactionStore&&) = delete;
    AuthenticationTransactionStore& operator=(AuthenticationTransactionStore&&) = delete;

    virtual ~AuthenticationTransactionStore() = default;

    /**
     * @brief Records a newly issued transaction.
     * @return ErrorCode::AlreadyExists when the identifier is already in flight.
     *         Reusing an identifier is either a generator defect or an attempt to
     *         overwrite someone else's transaction; neither may be accepted.
     */
    [[nodiscard]] virtual foundation::Status begin(AuthenticationTransaction transaction) = 0;

    /**
     * @brief Atomically validates and consumes the transaction named by @p id.
     *
     * @return The consumed transaction on success. ErrorCode::NotFound when the
     *         identifier is unknown, and the same failures as
     *         @ref AuthenticationTransaction::consume otherwise.
     */
    [[nodiscard]] virtual foundation::Result<AuthenticationTransaction>
    consume(const TransactionId& id, std::string_view presentedNonce,
            const BindingDigest& presentedBinding, foundation::Instant now) = 0;

    /** @brief Returns a snapshot of a transaction, for diagnostics and audit. */
    [[nodiscard]] virtual foundation::Result<std::optional<AuthenticationTransaction>>
    find(const TransactionId& id) const = 0;

    /**
     * @brief Removes transactions whose deadline has passed.
     * @return How many were removed.
     */
    [[nodiscard]] virtual std::size_t purgeExpired(foundation::Instant now) = 0;

    /** @brief Number of transactions currently retained. */
    [[nodiscard]] virtual std::size_t size() const = 0;

protected:
    AuthenticationTransactionStore() = default;
};

/**
 * @brief In-memory transaction store.
 *
 * Correct for a single process. A multi-node deployment needs a shared store,
 * because single-use enforcement that is local to one node is not enforcement at
 * all -- an attacker simply redeems the same transaction on a different node.
 * That adapter arrives with the cache backend; this class deliberately does not
 * pretend to be it.
 *
 * @note Thread-safe.
 */
class InMemoryAuthenticationTransactionStore final : public AuthenticationTransactionStore {
public:
    InMemoryAuthenticationTransactionStore() = default;

    [[nodiscard]] foundation::Status begin(AuthenticationTransaction transaction) override;

    [[nodiscard]] foundation::Result<AuthenticationTransaction>
    consume(const TransactionId& id, std::string_view presentedNonce,
            const BindingDigest& presentedBinding, foundation::Instant now) override;

    [[nodiscard]] foundation::Result<std::optional<AuthenticationTransaction>>
    find(const TransactionId& id) const override;

    [[nodiscard]] std::size_t purgeExpired(foundation::Instant now) override;

    [[nodiscard]] std::size_t size() const override;

private:
    mutable std::mutex m_mutex;
    std::map<TransactionId, AuthenticationTransaction> m_transactions;
};

}
