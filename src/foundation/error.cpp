module;

#include <string>
#include <string_view>
#include <utility>

module openproof.foundation;

namespace openproof::foundation {

std::string_view errorCodeName(ErrorCode code) noexcept
{
    switch (code) {
    case ErrorCode::Unknown:
        return "UNKNOWN";
    case ErrorCode::InvalidArgument:
        return "INVALID_ARGUMENT";
    case ErrorCode::FailedPrecondition:
        return "FAILED_PRECONDITION";
    case ErrorCode::NotFound:
        return "NOT_FOUND";
    case ErrorCode::AlreadyExists:
        return "ALREADY_EXISTS";
    case ErrorCode::Conflict:
        return "CONFLICT";
    case ErrorCode::AuthenticationRequired:
        return "AUTHENTICATION_REQUIRED";
    case ErrorCode::AuthenticationFailed:
        return "AUTHENTICATION_FAILED";
    case ErrorCode::PermissionDenied:
        return "PERMISSION_DENIED";
    case ErrorCode::AssuranceInsufficient:
        return "ASSURANCE_INSUFFICIENT";
    case ErrorCode::RateLimited:
        return "RATE_LIMITED";
    case ErrorCode::Timeout:
        return "TIMEOUT";
    case ErrorCode::Unavailable:
        return "UNAVAILABLE";
    case ErrorCode::NotImplemented:
        return "NOT_IMPLEMENTED";
    case ErrorCode::Internal:
        return "INTERNAL";
    }
    return "UNKNOWN";
}

std::string_view defaultErrorMessage(ErrorCode code) noexcept
{
    switch (code) {
    case ErrorCode::Unknown:
        return "An unexpected error occurred.";
    case ErrorCode::InvalidArgument:
        return "The request was not valid.";
    case ErrorCode::FailedPrecondition:
        return "The request cannot be performed in the current state.";
    case ErrorCode::NotFound:
        return "The requested resource was not found.";
    case ErrorCode::AlreadyExists:
        return "The resource already exists.";
    case ErrorCode::Conflict:
        return "The request conflicts with the current state of the resource.";
    case ErrorCode::AuthenticationRequired:
        return "Authentication is required.";
    // Deliberately identical in shape to AuthenticationRequired: the response
    // must not let a caller distinguish an unknown subject from a bad
    // credential, which is the account-enumeration oracle.
    case ErrorCode::AuthenticationFailed:
        return "Authentication failed.";
    case ErrorCode::PermissionDenied:
        return "The request was denied.";
    case ErrorCode::AssuranceInsufficient:
        return "A stronger authentication is required for this operation.";
    case ErrorCode::RateLimited:
        return "Too many requests.";
    case ErrorCode::Timeout:
        return "The request timed out.";
    case ErrorCode::Unavailable:
        return "The service is temporarily unavailable.";
    case ErrorCode::NotImplemented:
        return "The requested operation is not supported.";
    case ErrorCode::Internal:
        return "An internal error occurred.";
    }
    return "An unexpected error occurred.";
}

int errorHttpStatus(ErrorCode code) noexcept
{
    switch (code) {
    case ErrorCode::InvalidArgument:
        return 400;
    case ErrorCode::AuthenticationRequired:
    case ErrorCode::AuthenticationFailed:
        return 401;
    case ErrorCode::PermissionDenied:
    case ErrorCode::AssuranceInsufficient:
        return 403;
    case ErrorCode::NotFound:
        return 404;
    case ErrorCode::Conflict:
    case ErrorCode::AlreadyExists:
        return 409;
    case ErrorCode::FailedPrecondition:
        return 412;
    case ErrorCode::RateLimited:
        return 429;
    case ErrorCode::NotImplemented:
        return 501;
    case ErrorCode::Unavailable:
        return 503;
    case ErrorCode::Timeout:
        return 504;
    case ErrorCode::Unknown:
    case ErrorCode::Internal:
        return 500;
    }
    return 500;
}

Error::Error(ErrorCode code)
    : m_code(code)
    , m_message(defaultErrorMessage(code))
{
}

Error::Error(ErrorCode code, std::string message)
    : m_code(code)
    , m_message(std::move(message))
{
    if (m_message.empty()) {
        m_message = defaultErrorMessage(code);
    }
}

Error::Error(ErrorCode code, std::string message, std::string internalDetail)
    : m_code(code)
    , m_message(std::move(message))
    , m_internalDetail(std::move(internalDetail))
{
    if (m_message.empty()) {
        m_message = defaultErrorMessage(code);
    }
}

ErrorCode Error::code() const noexcept
{
    return m_code;
}

std::string_view Error::message() const noexcept
{
    return m_message;
}

std::string_view Error::internalDetail() const noexcept
{
    return m_internalDetail;
}

bool Error::hasInternalDetail() const noexcept
{
    return !m_internalDetail.empty();
}

Error Error::withInternalDetail(std::string detail) const
{
    return Error{m_code, m_message, std::move(detail)};
}

std::string toClientJson(const Error& error, std::string_view requestId)
{
    JsonObjectWriter body;
    body.add("code", errorCodeName(error.code()));
    body.add("message", error.message());
    if (!requestId.empty()) {
        body.add("request_id", requestId);
    }

    JsonObjectWriter envelope;
    envelope.add("error", body);
    return envelope.build();
}

}
