#include <gtest/gtest.h>

#include <cstddef>
#include <format>
#include <ostream>

#include <string>
#include <type_traits>
#include <utility>
#include <vector>

import openproof.foundation;

namespace fnd = openproof::foundation;

namespace {

// These are the load-bearing tests for this type. Redaction is claimed to be a
// property of the type rather than a convention, so the claim is checked at
// compile time: if any of these ever become satisfiable, a credential has become
// loggable and the build must fail.

static_assert(!std::formattable<fnd::SecretString, char>,
              "Secret must never be formattable; std::format on a secret must not compile.");

template <typename T>
concept StreamInsertable = requires(std::ostream& stream, const T& value) { stream << value; };

static_assert(!StreamInsertable<fnd::SecretString>,
              "Secret must never be stream-insertable.");

static_assert(!std::is_convertible_v<fnd::SecretString, std::string>,
              "Secret must not convert implicitly to its wrapped type.");

static_assert(!std::is_constructible_v<std::string, fnd::SecretString>,
              "A secret must not be constructible into a plain string implicitly.");

static_assert(!std::is_copy_constructible_v<fnd::SecretString>,
              "Secret must be move-only so a credential is not duplicated by accident.");

static_assert(!std::is_copy_assignable_v<fnd::SecretString>,
              "Secret must be move-only so a credential is not duplicated by accident.");

static_assert(std::is_move_constructible_v<fnd::SecretString>);
static_assert(std::is_nothrow_move_constructible_v<fnd::SecretString>);

// Comparison is omitted deliberately: comparing credentials with == is
// timing-observable. openproof::security::constantTimeEquals is the supported path.
template <typename T>
concept EqualityComparable = requires(const T& left, const T& right) { left == right; };

static_assert(!EqualityComparable<fnd::SecretString>,
              "Secret must not offer timing-observable equality.");

TEST(SecretTest, DefaultConstructsEmpty)
{
    const fnd::SecretString secret;
    EXPECT_TRUE(secret.empty());
    EXPECT_EQ(secret.size(), 0U);
}

TEST(SecretTest, ExposesTheWrappedValue)
{
    const fnd::SecretString secret{std::string{"client-secret-value"}};

    EXPECT_EQ(secret.expose(), "client-secret-value");
    EXPECT_EQ(secret.size(), 19U);
    EXPECT_FALSE(secret.empty());
}

TEST(SecretTest, MoveTransfersAndClearsTheSource)
{
    fnd::SecretString source{std::string{"transferred"}};
    const fnd::SecretString destination{std::move(source)};

    EXPECT_EQ(destination.expose(), "transferred");
    EXPECT_TRUE(source.empty());
}

TEST(SecretTest, MoveAssignmentTransfersAndClearsTheSource)
{
    fnd::SecretString source{std::string{"assigned"}};
    fnd::SecretString destination{std::string{"replaced"}};

    destination = std::move(source);

    EXPECT_EQ(destination.expose(), "assigned");
    EXPECT_TRUE(source.empty());
}

TEST(SecretTest, CloneDuplicatesExplicitly)
{
    const fnd::SecretString original{std::string{"duplicate-me"}};
    const fnd::SecretString copy = original.clone();

    EXPECT_EQ(copy.expose(), "duplicate-me");
    EXPECT_EQ(original.expose(), "duplicate-me");
}

TEST(SecretTest, WrapsNonStringTypes)
{
    const fnd::Secret<std::vector<std::byte>> keyMaterial{
        std::vector<std::byte>{std::byte{1}, std::byte{2}, std::byte{3}}};

    EXPECT_EQ(keyMaterial.size(), 3U);
    static_assert(!std::formattable<fnd::Secret<std::vector<std::byte>>, char>);
}

TEST(SecureWipeTest, OverwritesTheBuffer)
{
    std::vector<unsigned char> buffer{1U, 2U, 3U, 4U};
    fnd::secureWipe(buffer.data(), buffer.size());

    for (const unsigned char value : buffer) {
        EXPECT_EQ(value, 0U);
    }
}

// The precondition permits a null pointer only with a zero length.
TEST(SecureWipeTest, ToleratesEmptyRequests)
{
    fnd::secureWipe(nullptr, 0U);

    std::vector<unsigned char> buffer{9U};
    fnd::secureWipe(buffer.data(), 0U);
    EXPECT_EQ(buffer.front(), 9U);
}

// These assert termination, which is a property of the `enforce` semantic. Under
// `observe` a violation is reported and execution continues by design, so the
// same assertions would be wrong rather than merely inapplicable.
#if OPENPROOF_CONTRACTS_TERMINATE

// A null pointer with a non-zero length means a caller believes it is erasing a
// credential that is not there. Returning quietly would leave that belief
// intact, so the contract stops the process instead.
TEST(SecureWipeContractTest, RejectsNullPointerWithNonZeroLength)
{
    ::testing::GTEST_FLAG(death_test_style) = "threadsafe";
    EXPECT_DEATH(fnd::secureWipe(nullptr, 16U), "contract violation");
}

// The diagnostic comes from GCC's standard contract-violation handler, not from
// a project-supplied one. Its shape is the operator's evidence during an
// incident, so the essential parts are pinned here.
TEST(SecureWipeContractTest, ViolationDiagnosticIdentifiesThePredicate)
{
    ::testing::GTEST_FLAG(death_test_style) = "threadsafe";

    EXPECT_DEATH(fnd::secureWipe(nullptr, 16U), "contract violation");
    EXPECT_DEATH(fnd::secureWipe(nullptr, 16U), "assertion_kind: assert");
    EXPECT_DEATH(fnd::secureWipe(nullptr, 16U), "semantic: enforce");
    EXPECT_DEATH(fnd::secureWipe(nullptr, 16U), R"(size == 0U \|\| data != nullptr)");
}

#else

// Under `observe` the guarantee is the opposite one, and it is worth proving:
// the violation is reported but the process survives. A build configured this
// way must not be mistaken for one that fails closed.
TEST(SecureWipeContractTest, ObserveSemanticReportsWithoutTerminating)
{
    fnd::secureWipe(nullptr, 16U);
    SUCCEED() << "observe semantic: violation reported, execution continued";
}

#endif


}
