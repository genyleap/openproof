#include <boost/asio/co_spawn.hpp>
#include <boost/asio/thread_pool.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <atomic>
#include <exception>
#include <memory>
#include <string>
#include <utility>
#include "bounded_password_executor.hpp"

namespace openproof::credentials {
namespace asio = boost::asio;
namespace {
struct State final {
    State(PasswordHasher value, PasswordHash dummyValue, std::size_t count)
        : hasher(std::move(value)), dummy(std::move(dummyValue)), capacity(count) {}
    const PasswordHasher hasher;
    const PasswordHash dummy;
    const std::size_t capacity;
    std::atomic<std::size_t> active{0U};
};

// A permit travels with the worker coroutine frame, not the awaiting
// request. A cancelled waiter cannot release capacity while a KDF runs.
struct Permit final {
    explicit Permit(std::shared_ptr<State> value) noexcept : state(std::move(value)) {}
    Permit(Permit&&) noexcept = default;
    Permit(const Permit&) = delete;
    Permit& operator=(const Permit&) = delete;
    ~Permit() { if (state) state->active.fetch_sub(1U, std::memory_order_release); }
    std::shared_ptr<State> state;
};

std::optional<Permit> admit(const std::shared_ptr<State>& state)
{
    auto active = state->active.load(std::memory_order_relaxed);
    while (active < state->capacity) {
        if (state->active.compare_exchange_weak(active, active + 1U,
                std::memory_order_acq_rel, std::memory_order_relaxed))
            return std::optional<Permit>{std::in_place, state};
    }
    return std::nullopt;
}

asio::awaitable<foundation::Result<bool>> verifyWorker(
    Permit permit, foundation::SecretString password, std::optional<PasswordHash> expected)
{
    auto result = permit.state->hasher.verify(password,
        expected ? *expected : permit.state->dummy);
    if (!result) co_return foundation::fail(result.error());
    co_return expected.has_value() && result.value();
}

asio::awaitable<foundation::Result<std::optional<PasswordHash>>> rehashWorker(
    Permit permit, foundation::SecretString password, PasswordHash verified, bool requireProof)
{
    auto needed = permit.state->hasher.needsRehash(verified);
    if (!needed) co_return foundation::fail(needed.error());
    if (!needed.value() && !requireProof) co_return std::optional<PasswordHash>{};
    auto matches = permit.state->hasher.verify(password, verified);
    if (!matches) co_return foundation::fail(matches.error());
    if (!matches.value()) co_return foundation::fail(foundation::ErrorCode::AuthenticationFailed);
    if (!needed.value()) co_return std::optional<PasswordHash>{};
    auto replacement = permit.state->hasher.hash(password);
    if (!replacement) co_return foundation::fail(replacement.error());
    co_return std::optional<PasswordHash>{std::move(replacement).value()};
}
}

class BoundedPasswordExecutor::Impl final {
public:
    Impl(PasswordHasher hasher, PasswordHash dummy, std::size_t workers)
        : state(std::make_shared<State>(std::move(hasher), std::move(dummy), workers)),
          pool(workers) {}
    ~Impl() { pool.join(); }
    std::shared_ptr<State> state;
    asio::thread_pool pool;
};

BoundedPasswordExecutor::BoundedPasswordExecutor(std::unique_ptr<Impl> implementation)
    : m_impl(std::move(implementation)) {}
BoundedPasswordExecutor::~BoundedPasswordExecutor() = default;

foundation::Result<std::unique_ptr<BoundedPasswordExecutor>>
BoundedPasswordExecutor::create(PasswordHasher hasher, std::size_t workers)
{
    // Stored scrypt/Argon2id work factors are already bounded at 256 MiB
    // per derivation by PasswordHasher. Limit concurrent KDFs to two.
    if (workers == 0U || workers > 2U)
        return foundation::fail(foundation::ErrorCode::InvalidArgument);
    try {
        auto dummy = hasher.hash(foundation::SecretString{std::string(32U, 'x')});
        if (!dummy) return foundation::fail(dummy.error());
        return std::unique_ptr<BoundedPasswordExecutor>{new BoundedPasswordExecutor{
            std::make_unique<Impl>(std::move(hasher), std::move(dummy).value(), workers)}};
    } catch (const std::exception&) {
        return foundation::fail(foundation::ErrorCode::Unavailable);
    }
}

bool BoundedPasswordExecutor::prefersArgon2id() const noexcept
{
    return m_impl->state->hasher.prefersArgon2id();
}

foundation::Result<bool> BoundedPasswordExecutor::upgradeNeeded(const PasswordHash& hash) const
{
    if (!prefersArgon2id()) return false;
    return m_impl->state->hasher.needsRehash(hash);
}

asio::awaitable<foundation::Result<bool>> BoundedPasswordExecutor::verifyAsync(
    foundation::SecretString password, std::optional<PasswordHash> expected)
{
    auto permit = admit(m_impl->state);
    if (!permit) co_return foundation::fail(foundation::ErrorCode::RateLimited);
    try {
        co_return co_await asio::co_spawn(m_impl->pool,
            verifyWorker(std::move(*permit), std::move(password), std::move(expected)),
            asio::use_awaitable);
    } catch (const std::exception&) {
        co_return foundation::fail(foundation::ErrorCode::Unavailable);
    }
}

asio::awaitable<foundation::Result<std::optional<PasswordHash>>> BoundedPasswordExecutor::rehashAsync(
    foundation::SecretString password, PasswordHash verified)
{
    auto permit = admit(m_impl->state);
    if (!permit) co_return foundation::fail(foundation::ErrorCode::RateLimited);
    try {
        co_return co_await asio::co_spawn(m_impl->pool,
            rehashWorker(std::move(*permit), std::move(password), std::move(verified), false),
            asio::use_awaitable);
    } catch (const std::exception&) {
        co_return foundation::fail(foundation::ErrorCode::Unavailable);
    }
}

asio::awaitable<foundation::Result<std::optional<PasswordHash>>> BoundedPasswordExecutor::confirmUpgradeAsync(
    foundation::SecretString password, PasswordHash expected)
{
    if (!prefersArgon2id())
        co_return foundation::fail(foundation::ErrorCode::FailedPrecondition);
    auto permit = admit(m_impl->state);
    if (!permit) co_return foundation::fail(foundation::ErrorCode::RateLimited);
    try {
        co_return co_await asio::co_spawn(m_impl->pool,
            rehashWorker(std::move(*permit), std::move(password), std::move(expected), true),
            asio::use_awaitable);
    } catch (const std::exception&) {
        co_return foundation::fail(foundation::ErrorCode::Unavailable);
    }
}

}
