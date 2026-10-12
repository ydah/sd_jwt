<h1 align="center">SDJWT</h1>

<p align="center">Selective disclosure and holder key binding for Ruby.</p>

<p align="center">
  <a href="https://rubygems.org/gems/sd_jwt"><img src="https://img.shields.io/gem/v/sd_jwt" alt="Gem version"></a>
  <a href="https://github.com/ydah/sd_jwt/actions/workflows/main.yml"><img src="https://github.com/ydah/sd_jwt/actions/workflows/main.yml/badge.svg?branch=main" alt="CI"></a>
  <a href="https://www.ruby-lang.org/"><img src="https://img.shields.io/badge/Ruby-%3E%3D%203.3-CC342D?logo=ruby&amp;logoColor=white" alt="Ruby 3.3 or later"></a>
  <a href="LICENSE.txt"><img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT License"></a>
</p>

<p align="center">
  <a href="https://ydah.github.io/sd_jwt/">Website</a> &middot;
  <a href="#installation">Installation</a> &middot;
  <a href="#quick-start">Quick start</a> &middot;
  <a href="#supported-scope">Supported scope</a> &middot;
  <a href="#development">Development</a> &middot;
  <a href="#license">License</a>
</p>

Issue, selectively present, and verify [RFC 9901](https://www.rfc-editor.org/rfc/rfc9901.html) SD-JWTs in Ruby, with signatures provided by [ruby-jwt](https://github.com/jwt/ruby-jwt) and OpenSSL.

## Installation

Add the gem to your Gemfile:

```ruby
gem "sd_jwt"
```

Then run `bundle install`.

Requires Ruby 3.3 or later, `json` >= 2.19.4, < 4, and `jwt` 3.3.x.

## Quick start

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

Claim and header hashes require string keys and JSON values. Generation rejects reserved `_sd`, `_sd_alg`, and `...` members. `SdJwt` is an alias for `SDJWT`.

Use `token.disclosed_paths` to list available disclosures. `present(only:)` includes parents required by selected children, but selecting a parent does not reveal separately hidden children. Array indices refer to the original payload; hidden entries disappear from the verified result. An empty selection sends no disclosures. Each new presentation removes any existing KB-JWT; pass `key_binding:` to bind it again.

`decoys:` adds digests to each object's `_sd` array, including disclosed objects, without adding dummy array elements. Digest arrays are sorted, salts contain 128 random bits, and `max_disclosures` bounds the combined disclosure and decoy count.

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

`none` is always rejected. Holder keys must be P-256/P-384/P-521 or RSA with a 2048–8192 bit odd modulus and an odd exponent of at least 3. RSA issuer keys require at least 2048 bits and a valid exponent. HMAC requires random secrets of at least 32/48/64 bytes for HS256/384/512; PEM, DER, and SSH asymmetric key encodings are rejected as HMAC secrets. Use `key_binding_algorithms:` to further restrict holder algorithms.

## JWS JSON

```ruby
flattened = credential.to_json(format: :flattened)
general = credential.to_json(format: :general)
verifier.verify(SDJWT.parse(flattened).present(only: ["/name"], key_binding: {
  key: holder_key, alg: "ES256", aud: "https://verifier.example", nonce: "transaction-nonce"
}))
```

General JSON verification requires **every signature** to pass. Disclosures and `kb_jwt` belong to the first signature's unprotected header; all signatures share those disclosures, and key binding covers the first signature's Compact representation. Presentations retain additional signatures. Multi-signature tokens require General JSON; tokens with other unprotected headers must also remain JSON. Issuance creates one signature; externally co-signed tokens are accepted.

Unprotected headers are not identity evidence, and key resolver inputs are not yet authenticated. Resolve `iss`/`kid` against an explicit trust configuration; never fetch arbitrary header URLs. `headers` merges verified signature headers; inspect `signatures` to distinguish protected from unprotected metadata.

## Verification policy and limits

`Verifier.new` requires a nonempty signing algorithm allowlist. `required_claims:` defines validity claims that must survive disclosure; hidden `exp`, `aud`, or `cnf` claims cannot otherwise be detected. `issuer:` requires an exact issuer match. A present credential `aud` must match `audience:`; to require its presence, add `aud` to `required_claims`. `exp` and `nbf` are checked after disclosure reconstruction; `leeway:` defaults to zero.

Set `require_key_binding: true` based on your application's policy, not on whether a KB-JWT happens to arrive. With it enabled, a nonempty `audience:` and `nonce:` are required, and `iat` must fall between the current time minus `max_kb_age` and the current time. Without it, any supplied KB-JWT is structurally parsed but does not establish holder authentication; `result.key_binding_verified` remains false. Nonce generation, transaction replay storage, key revocation, credential profile rules, and required `typ` values belong to the application.

Default limits are 1 MiB serialized input, 1000 disclosures, nesting depth 32, and 16 General signatures. Configure `max_bytes:`, `max_disclosures:`, `max_depth:`, and `max_signatures:` on parsing/verifying; issuance accepts the first three. Verifying an existing `Token` reapplies the verifier's limits. Cryptographic inputs always use strict parsing; `strict: false` is rejected rather than downgrading errors to warnings.

Failures use `SDJWT::ParseError`, `ValidationError` (with `pointer` for disclosure path failures), `ConversionError`, or `VerificationError`, all under `SDJWT::Error`. Library errors omit claim values and salts. Application callback errors remain the application's responsibility.

## Development

```sh
bundle install
bundle exec rake test
COVERAGE=1 bundle exec rake test
bundle exec rbs -I sig validate
bundle exec ruby script/check_syntax.rb
bundle exec ruby script/check_licenses.rb
bundle exec ruby script/benchmark.rb
```

The first test run downloads checksum-pinned RFC fixtures into ignored `tmp/` directories and requires network access.

For deterministic tests only, explicitly require `sd_jwt/testing` and wrap issuance in `SDJWT::Testing.with_salts([...])`. Never use supplied salts in production.

## Contributing

Bug reports and pull requests are welcome on [GitHub](https://github.com/ydah/sd_jwt/issues). See [Development](#development) for local checks and [SECURITY.md](SECURITY.md) for private vulnerability reporting and audit status.

## License

Released under the [MIT License](LICENSE.txt).
