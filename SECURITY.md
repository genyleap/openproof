# Security Policy

OpenProof is security-sensitive identity infrastructure.

## Reporting a vulnerability

Please **do not open a public issue** for an undisclosed vulnerability.

Use GitHub's private vulnerability reporting when it is enabled for the
repository. Otherwise, contact the maintainers through a private channel before
public disclosure.

Include, when possible:

- the affected version or commit;
- the impacted endpoint, module or trust boundary;
- reproduction steps or a minimal proof of concept;
- expected versus observed behavior;
- any evidence of credential, identity or tenant-boundary impact.

Do not include real user credentials, production tokens, private keys or
unrelated personal data in a report.

## Scope

Security-sensitive areas include authentication ceremonies, provider callbacks,
OAuth/OIDC, passkeys, Web3 proofs, session/token lifecycle, tenant isolation,
SCIM/SAML/LDAP boundaries, secret handling, PostgreSQL persistence and trusted
reverse-proxy behavior.

The repository threat model and explicit invariants are documented in:

- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)
- [docs/SECURITY_INVARIANTS.md](docs/SECURITY_INVARIANTS.md)
