/**
 * @file
 * @brief Primary interface of openproof.observability.
 *
 * Owns how the platform describes itself to operators: structured logs today,
 * and metrics, tracing, audit events and security events as later partitions of
 * this same module.
 *
 * Logging and auditing are kept distinct on purpose. A log record is
 * operational and may be sampled or dropped under load. An audit event is a
 * security record that must not be lost. They will therefore have different
 * durability guarantees even though both live in this layer.
 */
export module openproof.observability;

export import :log;
