/**
 * @file
 * @brief Primary interface of openproof.foundation.
 *
 * openproof.foundation is the platform's stable base layer. It depends on nothing
 * else in the project, and every other layer depends on it. It owns only
 * cross-cutting vocabulary: failure representation, identifiers, time, secret
 * handling, and the encodings used by the wire formats.
 *
 * It deliberately does not own domain concepts. There is no identity, session,
 * policy or transport type here, and there is no "utils" partition (ARC-005).
 *
 * The layer is expressed as one module with partitions rather than several
 * dotted modules so that the namespace mirrors the module identity exactly
 * (NAM-002) and callers write `openproof::foundation::Error` rather than a repeated
 * sub-namespace. Independently pluggable components -- authentication
 * providers, gateway subsystems -- are separate dotted modules instead, because
 * they are meant to be swapped, not merely organized.
 */
export module openproof.foundation;

export import :error;
export import :result;
export import :json;
export import :encoding;
export import :secret;
export import :id;
export import :time;
