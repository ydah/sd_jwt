# SDJWT

Issue, selectively present, and verify [RFC 9901](https://www.rfc-editor.org/rfc/rfc9901.html) SD-JWTs in Ruby. Signatures use [ruby-jwt](https://github.com/jwt/ruby-jwt) and OpenSSL; this gem implements disclosures, recursive claim processing, and holder key binding.

## Install

```ruby
gem "sd_jwt", "~> 0.1.0"
```

Ruby 3.3 or later, JRuby, and TruffleRuby are tested in CI. Runtime dependencies are `json` (2.19.4 or later, including 3.x) and `jwt` (3.3.x). No other gem in the JSON formats family is required.

## Issue and verify

```ruby
require "sd_jwt"

issuer_key = OpenSSL::PKey::EC.generate("prime256v1")
holder_key = OpenSSL::PKey::EC.generate("prime256v1")
holder_jwk = JWT::JWK.new(holder_key).export.transform_keys(&:to_s)

issuer = SDJWT::Issuer.new(signing_key: issuer_key, alg: "ES256")
credential = issuer.issue(
  { "iss" => "https://issuer.example", "exp" => Time.now.to_i + 3600,
    "name" => "Example", "address" => { "street" => "Harbor Street", "city" => "Port" } },
  disclose: ["/name", "/address", "/address/street"],
  decoys: 2,
  holder_jwk: holder_jwk,
  header: { "typ" => "example+sd-jwt", "kid" => "key-1" }
)

held = SDJWT.parse(credential.to_s) # Unauthenticated holder-side parsing.
presentation = held.present(
  only: ["/name"],
  key_binding: { key: holder_key, alg: "ES256", aud: "https://verifier.example", nonce: "transaction-nonce" }
)

verifier = SDJWT::Verifier.new(
  algorithms: ["ES256"],
  issuer_key: issuer_key, # Or ->(untrusted_header, untrusted_payload) { trusted_key_lookup(...) }
  issuer: "https://issuer.example",
  required_claims: ["iss", "exp", "cnf"],
  require_key_binding: true,
  audience: "https://verifier.example",
  nonce: "transaction-nonce",
  max_kb_age: 300
)
result = verifier.verify(presentation)
result.claims                    # Immutable, authenticated disclosed claims.
result.key_binding_verified      # true
```

Keys in claim and header hashes must be strings. Values must be JSON data. Generation rejects reserved `_sd`, `_sd_alg`, and `...` members. `SdJwt` is a compatibility alias for `SDJWT`.

Use `token.disclosed_paths` to enumerate available disclosure paths. `present(only:)` automatically includes disclosed parents needed by a selected child. Selecting a parent includes its directly visible contents, but does not select separately hidden children. Array indices refer to the original issuer payload: hidden array entries disappear from the verified result. Selecting no paths sends no disclosures. Creating a new presentation removes an existing KB-JWT; pass `key_binding:` to bind the new presentation.

`decoys:` adds that many digests to each object `_sd` array, including arrays within parent disclosures. It does not add dummy array elements. Digest arrays are sorted. Salts contain 128 random bits. The total number of issued disclosures and decoys is bounded by `max_disclosures`.

## Supported scope

| Feature | Support |
| --- | --- |
| RFC 9901 Compact, Flattened JSON, General JSON | Read, write, present, verify |
| Object claims, array entries, recursive disclosure | Supported |
| Unknown application claims and header parameters | Preserved |
| Hashes | `sha-256` default; `sha-384` and `sha-512` require verifier opt-in |
| Issuer signatures | ES256/384/512, RS256/384/512, PS256/384/512; HS256/384/512 only when explicitly configured |
| Holder key binding | `cnf.jwk` with public EC or RSA keys, KB-JWT type/time/audience/nonce/presentation digest |
| JSON duplicate names, non-finite values, invalid UTF-8 | Rejected with both json 2.x and 3.x |
| SD-JWT VC / W3C VC profile rules, revocation, trust discovery | Application responsibility |
| EdDSA, symmetric holder keys, other `cnf` methods, custom JOSE critical extensions, unencoded payloads | Unsupported |
| CBOR SD-CWT | Unsupported |

`none` is always rejected. Holder keys are P-256/P-384/P-521 or RSA with a 2048–8192 bit odd modulus and an odd public exponent of at least 3. RSA issuer keys also require at least 2048 bits and a valid public exponent. HMAC requires random secrets of at least 32/48/64 bytes for HS256/384/512; PEM, DER, and SSH asymmetric key encodings are rejected as HMAC secrets. Applications may restrict holder signature algorithms further with `key_binding_algorithms:`. Signing uses jwt's token API; JSON signatures, including unprotected `alg`, use its JWA implementation over the unchanged encoded input. PSS verification calls OpenSSL directly to enforce JOSE's exact salt length, which ruby-jwt's permissive PSS verification does not enforce. No signature primitive is implemented here.

## JWS JSON

```ruby
flattened = credential.to_json(format: :flattened)
general = credential.to_json(format: :general)
verifier.verify(SDJWT.parse(flattened).present(only: ["/name"], key_binding: {
  key: holder_key, alg: "ES256", aud: "https://verifier.example", nonce: "transaction-nonce"
}))
```

General JSON verification requires **every signature** to pass. RFC 9901 section 8.3 places `disclosures` and `kb_jwt` only in the first signature's unprotected header; the same disclosure set is processed for all signatures, and key binding covers the first signature's Compact representation. Additional signatures are preserved when presenting. A multi-signature token must be written as General JSON. A token with other unprotected headers must remain JSON because Compact cannot retain those headers. Issuance creates one signature; externally co-signed General tokens are accepted.

Unprotected headers are not trustworthy identity evidence. Even protected headers and payloads passed to a key resolver have not yet been authenticated. Restrict `iss`/`kid` resolution to an explicit trust configuration; never fetch arbitrary header URLs. `headers` contains the merged headers for each verified signature; use the original `signatures` representation to distinguish protected from unprotected metadata.

## Verification policy and limits

`Verifier.new` requires a nonempty signing algorithm allowlist. `required_claims:` defines validity claims that must survive disclosure; hidden `exp`, `aud`, or `cnf` claims cannot otherwise be detected. `issuer:` requires an exact issuer match. A present credential `aud` must match `audience:`; to require its presence, add `aud` to `required_claims`. `exp` and `nbf` are checked after disclosure reconstruction; `leeway:` defaults to zero.

Set `require_key_binding: true` based on your application's policy, not on whether a KB-JWT happens to arrive. With it enabled, a nonempty `audience:` and `nonce:` are required, and `iat` must fall between the current time minus `max_kb_age` and the current time. Without it, any supplied KB-JWT is structurally parsed but does not establish holder authentication; `result.key_binding_verified` remains false. Nonce generation, transaction replay storage, key revocation, credential profile rules, and required `typ` values belong to the application.

Default limits are 1 MiB serialized input, 1000 disclosures, nesting depth 32, and 16 General signatures. Configure `max_bytes:`, `max_disclosures:`, `max_depth:`, and `max_signatures:` on parsing/verifying; issuance accepts the first three. Verifying an existing `Token` reapplies the verifier's limits. Cryptographic inputs always use strict parsing; `strict: false` is rejected rather than downgrading errors to warnings.

Failures use `SDJWT::ParseError`, `ValidationError` (with `pointer` for disclosure path failures), `ConversionError`, or `VerificationError`, all under `SDJWT::Error`. Library errors omit claim values and salts. Application callback errors remain the application's responsibility.

## Development and reference data

```sh
bundle install
bundle exec rake test
COVERAGE=1 bundle exec rake test
bundle exec rbs -I sig validate
bundle exec ruby script/check_syntax.rb
bundle exec ruby script/check_licenses.rb
bundle exec ruby script/benchmark.rb
```

Tests fetch RFC 9901 by a pinned SHA-256 into ignored `tmp/rfc/sources`, then extract all 57 source/artwork blocks and 87 fixed disclosure/digest pairs into ignored `tmp/rfc/fixtures`, with the source notices and Revised BSD notification. Nothing fetched is committed or packaged. The package includes only this project's MIT implementation, original protocol metadata, types, and documentation.

Display line wrapping is removed inside encoded strings and token blocks. Original text and the extraction inventory are retained next to each fixture. Illustrative snippets with ellipses remain text. The section 8.3 General example uses two illustrative signatures that do not verify with the Appendix A.5 key; it is tested for structural preservation and disclosure reconstruction, with signature rejection explicitly checked. Generated two-key General tokens test successful all-signature verification. Issuance uses compact JSON, while RFC disclosures often contain spaces; original RFC disclosures and digests are checked byte-for-byte, and deterministic issuance is tested separately with compact encoding.

The Ruby suite verifies all eight complete RFC tokens and covers nested claims, array entries, decoys, selective presentations, and key binding. Issuance and holder-binding contract tests also inspect signatures and digest relationships through ruby-jwt and Ruby standard libraries. The Python comparison stack has been removed; current checks do not claim independent implementation interoperability. Previous Python and JavaScript reference use is recorded in [provenance and dependency review](docs/provenance.md). RFC errata were checked on 2026-10-11; none were listed. `script/update_registry.rb` audits the IANA JWT claim registrations without importing registry documents into the package.

For deterministic tests only, explicitly require `sd_jwt/testing` and wrap issuance in `SDJWT::Testing.with_salts([...])`. Never use supplied salts in production.

Added runtime and development libraries must offer MIT terms, including transitive dependencies; Ruby runtimes, standard libraries, and bundled tools are explicit exceptions. RFC test inputs keep their own notices and are excluded from the gem.

See [SECURITY.md](SECURITY.md) for reporting and audit status. Released under the [MIT license](LICENSE.txt).
