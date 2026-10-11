# Implementation provenance and dependency review

Reviewed 2026-10-12. The project licenses its Ruby implementation under MIT.
This record distinguishes implementation, protocol facts, external test material,
and separately installed libraries. It is not a claim that no external
implementation was ever consulted, or an independent legal audit.

## Implementation and protocol facts

The runtime code implements the requirements of [RFC 9901](https://www.rfc-editor.org/rfc/rfc9901.html):

| Files | Requirements used |
| --- | --- |
| `disclosure.rb`, `hash_alg.rb`, `issuer.rb` | Section 4 disclosure encoding, digests, recursive object/array redaction and decoys; section 9 salt requirements |
| `processor.rb` | Section 7.1 reconstruction, duplicate digest checks, claim collision checks and rejection of unused disclosures |
| `token.rb`, `serialization.rb` | Sections 4 and 8 compact/JWS JSON representations and selective presentation |
| `key_binding.rb`, `verifier.rb` | Sections 4.3 and 7 issuer verification, holder signature, presentation hash and transaction binding |
| `codec.rb`, `pointer.rb` | Ruby-specific input limits, JSON validation, key/algorithm checks and JSON Pointer API support |

Signing and signature verification use the MIT `jwt` gem and Ruby's OpenSSL
integration. Security review added stricter key and RSA-PSS checks through those
APIs; this project does not implement RSA or elliptic-curve primitives.

`data/protocol.yml` is an authored table of four claim identifiers and their
validation categories/section references, three hash identifiers and output
lengths, and three media type identifiers. It contains protocol facts, not an
imported CDDL/ABNF grammar, RFC prose, or reference implementation source.

The previous development notes recorded consultation of the OpenWallet Foundation
JavaScript implementation's RFC coverage. Python `sd-jwt` 0.10.4 was installed and
called through a small project-authored API wrapper for bidirectional comparisons.
The retained development record does not identify every source file viewed, so
it does not support a claim that reference implementation code was never read.
The implementation author does not recall porting or translating Python or
JavaScript functions into the runtime. The current Ruby code was reviewed against
the requirements above; no specific copied implementation fragment was identified.
That review is narrower than proving the provenance of every expression.

## Dependency changes

The Python comparison job, its API wrappers and pinned dependency requirements
were removed on 2026-10-12. The installed distributions showed these non-MIT
terms: `sd-jwt` 0.10.4 Apache-2.0; `jwcrypto` 1.6.1 LGPL-3.0-or-later;
`cryptography` 50.0.2 Apache-2.0 OR BSD-3-Clause; `pycparser` 3.11 BSD-3-Clause;
`typing_extensions` 4.16.0 PSF-2.0. `cffi` 2.1.1 declares MIT-0, a distinct license.
No Python environment is needed by the current build or tests.

Runtime dependencies are `jwt` (MIT) and `json` (Ruby standard library exception).
Ruby runtimes, standard libraries and bundled tools, including OpenSSL, JSON,
IRB, REXML and RBS, are explicit project-policy exceptions. Additional libraries
must offer MIT terms, including their transitive dependencies. A dual license with
MIT as an alternative may be used under MIT; this does not waive separate notices
for bundled components or data. Installed gemspec metadata and shipped license
files are reviewed separately from the project license.

## External conformance data and retained coverage

RFC source documents, examples and notices remain in ignored `tmp/rfc/` only.
Their source hashes and the extraction inventory are pinned. They retain their
own IETF terms, are not relicensed as MIT, and are excluded from the gem allowlist.
IANA registry downloads are likewise external test inputs.

The Ruby suite retains all eight complete RFC tokens, 87 exact disclosure/digest
vectors, JWS JSON examples, nested/array/decoy issuance, selected presentations,
key binding and negative security regressions. Additional contract tests inspect
issuer and holder signatures using `jwt`, and compute encoding/digests through
Ruby standard libraries instead of using SDJWT's decoder or reconstruction as
both the actual result and expected result. These are conformance checks, not
an independent SD-JWT implementation comparison.

Rubocop was also removed from development dependencies. Its transitive
`unicode-display_width` 3.3.0 and `unicode-emoji` 4.3.0 declare MIT for their code
but separately identify Unicode data terms in their README files. Gem metadata
alone therefore does not establish MIT-only terms for all bundled material.
Ruby syntax checks, RSpec and RBS remain in the verification workflow.

`bundle exec ruby script/check_licenses.rb` checks the resolved Bundler graph
against this policy in CI and release jobs. It has an explicit standard-library
allowlist, selects diff-lcs's documented MIT alternative, rejects missing or
unreviewed license metadata, and blocks the known Unicode-data gems above. It
does not replace reviewing the actual contents and notices of a new dependency.
