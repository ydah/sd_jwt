# Security policy

Report suspected vulnerabilities privately through [GitHub security advisories](https://github.com/ydah/sd_jwt/security/advisories/new).
If private reporting is unavailable, email t.yudai92@gmail.com. Do not include live credentials, private keys, or personal disclosures in a public issue.

Security fixes target the latest published release. Upgrade to the latest release before reporting an already resolved issue.

`SDJWT.parse` and `Token#unverified_claims` do not authenticate credentials. Only consume trusted claims from `Verifier#verify`.
The application must establish issuer trust, restrict algorithms, require the validity claims its profile needs, and decide whether holder key binding is mandatory.
Use fresh unpredictable nonces, enforce one-time transaction use, keep signing keys out of logs, and validate the credential's profile and issuer-supplied metadata separately.

No independent external human security audit has been completed for this initial release. Automated negative tests and RFC conformance checks do not replace that audit.

An independent implementation review on 2026-10-11 added regression tests and fixes for asymmetric key encodings used as HMAC secrets, undersized HMAC/RSA keys, invalid RSA public exponents, and nonstandard RSA-PSS salt lengths. It also checked disclosure reconstruction, transaction binding, time boundaries, and parser limits. This review did not audit OpenSSL or ruby-jwt internals, perform timing analysis, or assess an application's issuer trust and replay controls.

Dependency policy: added runtime and development libraries, including transitive
dependencies, must offer MIT terms. Ruby runtimes, standard libraries, and bundled
tools are explicit exceptions. Externally downloaded RFC/registry test data retain
their own notices and stay outside the repository and gem package. Dependency
license review does not constitute a cryptographic or application security audit.
See [provenance and dependency review](docs/provenance.md) for the review scope.
