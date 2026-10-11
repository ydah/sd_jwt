# frozen_string_literal: true

require_relative "sd_jwt/version"
require_relative "sd_jwt/errors"
require_relative "sd_jwt/codec"
require_relative "sd_jwt/hash_alg"
require_relative "sd_jwt/disclosure"
require_relative "sd_jwt/pointer"
require_relative "sd_jwt/processor"
require_relative "sd_jwt/token"
require_relative "sd_jwt/serialization"
require_relative "sd_jwt/key_binding"
require_relative "sd_jwt/issuer"
require_relative "sd_jwt/verifier"

module SDJWT
  # Parse holder input without authenticating it. Verification is always explicit.
  def self.parse(source, max_bytes: Codec::MAX_BYTES, max_depth: Codec::MAX_DEPTH,
                 max_disclosures: Codec::MAX_DISCLOSURES, max_signatures: Codec::MAX_SIGNATURES, strict: true)
    raise ArgumentError, "Cryptographic inputs require strict parsing" unless strict

    limits = Codec.limits(max_bytes: max_bytes, max_depth: max_depth, max_disclosures: max_disclosures, max_signatures: max_signatures)
    Serialization.parse(source, limits: limits)
  end
end
