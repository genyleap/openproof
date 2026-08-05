module;

#include <string>
#include <string_view>

export module openproof.foundation:error;

export namespace openproof::foundation {

/**
 * @brief Stable, transport-neutral classification of a recoverable failure.
 *
 * These codes form the public error contract described in the platform error
 * model. Domain code selects a code; only the edge translates it to a transport
 * status. Codes may be appended over time, but an existing code must never be
 * renamed or repurposed because clients branch on its serialized name.
 */
enum class ErrorCode {
    Unknown,
    InvalidArgument,
    FailedPrecondition,
    NotFound,
    AlreadyExists,
    Conflict,
    AuthenticationRequired,
    AuthenticationFailed,
    PermissionDenied,
    AssuranceInsufficient,
    RateLimited,
    Timeout,
    Unavailable,
    NotImplemented,
    Internal,
};

/**
 * @brief Returns the stable wire name of @p code, for example "NOT_FOUND".
 *
 * The returned view refers to static storage and outlives any caller.
 */
[[nodiscard]] std::string_view errorCodeName(ErrorCode code) noexcept;

/**
 * @brief Returns a client-safe default message for @p code.
 *
 * The message is deliberately generic. It must never describe internal state,
 * and it must not let a caller distinguish "no such account" from "wrong
 * credential", which would enable account enumeration.
 *
 * The returned view refers to static storage and outlives any caller.
 */
[[nodiscard]] std::string_view defaultErrorMessage(ErrorCode code) noexcept;

/**
 * @brief Maps @p code to the HTTP status the edge should emit.
 *
 * Provided so that no route handler invents its own status mapping.
 */
[[nodiscard]] int errorHttpStatus(ErrorCode code) noexcept;

/**
 * @brief A recoverable failure carrying a client-safe message and, optionally,
 *        an operator-only detail.
 *
 * The two message channels are separate on purpose. @ref message() is safe to
 * serialize to an untrusted client. @ref internalDetail() is for logs, audit
 * records and operator tooling only, and is never included in the client
 * representation produced by @ref toClientJson().
 *
 * Neither channel may carry a credential. Secret-bearing values use
 * openproof::foundation::Secret, which has no formatter and cannot be stringified
 * into either field by accident.
 *
 * @note Values of this type are immutable after construction and are safe to
 *       copy across threads.
 */
class Error final {
public:
    /**
     * @brief Constructs an error using the client-safe default message for @p code.
     */
    explicit Error(ErrorCode code);

    /**
     * @brief Constructs an error with an explicit client-safe message.
     * @param code    Stable classification.
     * @param message Text that may be returned to an untrusted client.
     */
    Error(ErrorCode code, std::string message);

    /**
     * @brief Constructs an error with a client-safe message and an operator-only detail.
     * @param code           Stable classification.
     * @param message        Text that may be returned to an untrusted client.
     * @param internalDetail Text for logs and audit records only. Never serialized
     *                       to a client. Must not contain credentials.
     */
    Error(ErrorCode code, std::string message, std::string internalDetail);

    [[nodiscard]] ErrorCode code() const noexcept;

    /** @brief Client-safe message. Always populated. */
    [[nodiscard]] std::string_view message() const noexcept;

    /** @brief Operator-only detail, empty when none was supplied. */
    [[nodiscard]] std::string_view internalDetail() const noexcept;

    [[nodiscard]] bool hasInternalDetail() const noexcept;

    /**
     * @brief Returns a copy of this error carrying @p detail as operator-only context.
     *
     * Used to add diagnostic context while propagating a failure outward without
     * changing what the client is told.
     */
    [[nodiscard]] Error withInternalDetail(std::string detail) const;

    [[nodiscard]] friend bool operator==(const Error& left, const Error& right) noexcept
    {
        return left.m_code == right.m_code && left.m_message == right.m_message;
    }

private:
    ErrorCode m_code;
    std::string m_message;
    std::string m_internalDetail;
};

/**
 * @brief Serializes @p error into the platform's client error envelope.
 *
 * Produces exactly the documented shape, and deliberately omits
 * @ref Error::internalDetail():
 * @code
 * {"error":{"code":"AUTHENTICATION_REQUIRED","message":"...","request_id":"..."}}
 * @endcode
 *
 * @param error     The failure to render.
 * @param requestId Correlation identifier echoed to the client so an operator can
 *                  find the corresponding log record. May be empty, in which case
 *                  the field is omitted.
 */
[[nodiscard]] std::string toClientJson(const Error& error, std::string_view requestId);

}
