module;

#include <compare>
#include <cstddef>
#include <functional>
#include <string>
#include <string_view>
#include <utility>

export module openproof.foundation:id;

export namespace openproof::foundation {

/**
 * @brief A phantom-typed identifier.
 *
 * Identifiers in this platform are not interchangeable strings. A session
 * identifier, an organization identifier and a provider identifier are distinct
 * types, so passing one where another is expected is a compile error rather
 * than a cross-tenant or cross-object defect discovered in production.
 *
 * The identifier is intentionally opaque: it carries no format, no ordering
 * meaning beyond byte order, and no embedded provider data. An identifier
 * supplied by an external identity provider is never used as a OpenProof primary
 * key; it is linked to one.
 *
 * @tparam Tag An empty type that gives the identifier its identity. Each domain
 *             declares its own tags.
 */
template <typename Tag>
class StrongId final {
public:
    /** @brief Constructs an empty identifier. */
    StrongId() = default;

    /** @brief Wraps @p value. No format is imposed at this layer. */
    explicit StrongId(std::string value)
        : m_value(std::move(value))
    {
    }

    [[nodiscard]] std::string_view value() const noexcept
    {
        return m_value;
    }

    /** @brief Returns the owning string, for storage layers that need one. */
    [[nodiscard]] const std::string& str() const noexcept
    {
        return m_value;
    }

    [[nodiscard]] bool empty() const noexcept
    {
        return m_value.empty();
    }

    [[nodiscard]] friend bool operator==(const StrongId& left, const StrongId& right) = default;

    [[nodiscard]] friend std::strong_ordering operator<=>(const StrongId& left,
                                                          const StrongId& right) = default;

private:
    std::string m_value;
};

/** @brief Tag for the per-request identifier carried through the pipeline. */
struct RequestIdTag {};

/** @brief Identifies a single inbound request, echoed to clients in errors. */
using RequestId = StrongId<RequestIdTag>;

/** @brief Tag for the identifier that correlates work across services. */
struct CorrelationIdTag {};

/** @brief Correlates a request with related work in other services. */
using CorrelationId = StrongId<CorrelationIdTag>;

}

// Declared in the module purview rather than exported: a specialization is found
// through the primary template from <functional>, and reachability is what the
// standard requires here. This lets any StrongId be used as a key in an
// unordered container without each domain repeating the hash.
namespace std {

template <typename Tag>
struct hash<openproof::foundation::StrongId<Tag>> {
    [[nodiscard]] std::size_t
    operator()(const openproof::foundation::StrongId<Tag>& id) const noexcept
    {
        return std::hash<std::string_view>{}(id.value());
    }
};

}
