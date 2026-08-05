#include <gtest/gtest.h>

#include <string>
#include <string_view>

import openproof.foundation;

namespace fnd = openproof::foundation;

namespace {

TEST(ErrorTest, DefaultsToClientSafeMessageForCode)
{
    const fnd::Error error{fnd::ErrorCode::NotFound};

    EXPECT_EQ(error.code(), fnd::ErrorCode::NotFound);
    EXPECT_EQ(error.message(), fnd::defaultErrorMessage(fnd::ErrorCode::NotFound));
    EXPECT_FALSE(error.hasInternalDetail());
}

TEST(ErrorTest, EmptyExplicitMessageFallsBackToDefault)
{
    const fnd::Error error{fnd::ErrorCode::Internal, std::string{}};

    EXPECT_FALSE(error.message().empty());
    EXPECT_EQ(error.message(), fnd::defaultErrorMessage(fnd::ErrorCode::Internal));
}

TEST(ErrorTest, InternalDetailIsSeparateFromClientMessage)
{
    const fnd::Error error{fnd::ErrorCode::Internal, "An internal error occurred.",
                           "connection pool exhausted on shard 4"};

    EXPECT_EQ(error.message(), "An internal error occurred.");
    EXPECT_EQ(error.internalDetail(), "connection pool exhausted on shard 4");
    EXPECT_TRUE(error.hasInternalDetail());
}

TEST(ErrorTest, WithInternalDetailPreservesClientFacingFields)
{
    const fnd::Error original{fnd::ErrorCode::PermissionDenied};
    const fnd::Error annotated = original.withInternalDetail("policy rbac.admin denied");

    EXPECT_EQ(annotated.code(), original.code());
    EXPECT_EQ(annotated.message(), original.message());
    EXPECT_EQ(annotated.internalDetail(), "policy rbac.admin denied");
    EXPECT_FALSE(original.hasInternalDetail());
}

// The client envelope is a security boundary, not a formatting detail: the
// operator-only diagnostic must not cross it.
TEST(ErrorTest, ClientJsonNeverLeaksInternalDetail)
{
    const fnd::Error error{fnd::ErrorCode::AuthenticationRequired,
                           "Authentication is required.",
                           "no session cookie; upstream identity service returned 503"};

    const std::string envelope = fnd::toClientJson(error, "req-42");

    EXPECT_EQ(envelope,
              R"({"error":{"code":"AUTHENTICATION_REQUIRED",)"
              R"("message":"Authentication is required.","request_id":"req-42"}})");
    EXPECT_EQ(envelope.find("upstream identity service"), std::string::npos);
    EXPECT_EQ(envelope.find("503"), std::string::npos);
}

TEST(ErrorTest, ClientJsonOmitsRequestIdWhenAbsent)
{
    const fnd::Error error{fnd::ErrorCode::RateLimited};
    const std::string envelope = fnd::toClientJson(error, "");

    EXPECT_EQ(envelope.find("request_id"), std::string::npos);
}

TEST(ErrorTest, ClientJsonEscapesUntrustedMessageContent)
{
    const fnd::Error error{fnd::ErrorCode::InvalidArgument, R"(quote " and backslash \)"};
    const std::string envelope = fnd::toClientJson(error, R"(req"1)");

    // The envelope must remain a single well-formed JSON object; an unescaped
    // quotation mark in a message would let a caller inject structure.
    EXPECT_NE(envelope.find(R"(quote \" and backslash \\)"), std::string::npos);
    EXPECT_NE(envelope.find(R"(req\"1)"), std::string::npos);
}

TEST(ErrorTest, EveryCodeHasStableNameAndStatus)
{
    constexpr fnd::ErrorCode kAllCodes[] = {
        fnd::ErrorCode::Unknown,
        fnd::ErrorCode::InvalidArgument,
        fnd::ErrorCode::FailedPrecondition,
        fnd::ErrorCode::NotFound,
        fnd::ErrorCode::AlreadyExists,
        fnd::ErrorCode::Conflict,
        fnd::ErrorCode::AuthenticationRequired,
        fnd::ErrorCode::AuthenticationFailed,
        fnd::ErrorCode::PermissionDenied,
        fnd::ErrorCode::AssuranceInsufficient,
        fnd::ErrorCode::RateLimited,
        fnd::ErrorCode::Timeout,
        fnd::ErrorCode::Unavailable,
        fnd::ErrorCode::NotImplemented,
        fnd::ErrorCode::Internal,
    };

    for (const fnd::ErrorCode code : kAllCodes) {
        EXPECT_FALSE(fnd::errorCodeName(code).empty());
        EXPECT_FALSE(fnd::defaultErrorMessage(code).empty());
        EXPECT_GE(fnd::errorHttpStatus(code), 400);
        EXPECT_LT(fnd::errorHttpStatus(code), 600);
    }
}

// Distinguishing "no such account" from "wrong credential" is an account
// enumeration oracle. The two client-facing messages must not diverge in a way
// that reveals which happened.
TEST(ErrorTest, AuthenticationFailuresDoNotRevealWhichCheckFailed)
{
    const fnd::Error required{fnd::ErrorCode::AuthenticationRequired};
    const fnd::Error failed{fnd::ErrorCode::AuthenticationFailed};

    EXPECT_EQ(fnd::errorHttpStatus(required.code()), 401);
    EXPECT_EQ(fnd::errorHttpStatus(failed.code()), 401);
    EXPECT_EQ(failed.message().find("account"), std::string_view::npos);
    EXPECT_EQ(failed.message().find("password"), std::string_view::npos);
    EXPECT_EQ(failed.message().find("user"), std::string_view::npos);
}

}
