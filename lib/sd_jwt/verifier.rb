# frozen_string_literal: true

module SDJWT
  class Result
    attr_reader :claims, :headers, :key_binding_verified

    def initialize(claims:, headers:, key_binding_verified:)
      @claims = Codec.freeze_tree(claims)
      @headers = Codec.freeze_tree(headers)
      @key_binding_verified = key_binding_verified
      freeze
    end
  end

  class Verifier
    def initialize(algorithms:, issuer_key:, hash_algorithms: ["sha-256"], require_key_binding: false,
                   audience: nil, nonce: nil, max_kb_age: 300, key_binding_algorithms: %w[ES256 ES384 ES512 RS256 RS384 RS512 PS256 PS384 PS512],
                   required_claims: [], issuer: nil, leeway: 0, max_bytes: Codec::MAX_BYTES, max_depth: Codec::MAX_DEPTH,
                   max_disclosures: Codec::MAX_DISCLOSURES, max_signatures: Codec::MAX_SIGNATURES)
      @algorithms = Codec.allowlist(algorithms)
      @kb_algorithms = Codec.allowlist(key_binding_algorithms)
      raise ArgumentError, "Holder signatures must be asymmetric" if @kb_algorithms.any? { |algorithm| algorithm.start_with?("HS") }
      unless hash_algorithms.is_a?(Array) && !hash_algorithms.empty? && hash_algorithms.all? { |alg| HashAlg::ALGORITHMS.key?(alg) }
        raise ArgumentError, "A nonempty supported hash algorithm allowlist is required"
      end
      raise ArgumentError, "Required claim names must be strings" unless required_claims.is_a?(Array) && required_claims.all?(String)
      raise ArgumentError, "Invalid key binding policy" unless [true, false].include?(require_key_binding)
      unless max_kb_age.is_a?(Numeric) && max_kb_age.finite? && max_kb_age.positive? && leeway.is_a?(Numeric) && leeway.finite? && leeway >= 0
        raise ArgumentError, "Invalid time policy"
      end
      if require_key_binding && (!audience.is_a?(String) || audience.empty? || !nonce.is_a?(String) || nonce.empty?)
        raise ArgumentError, "Key binding requires a nonempty audience and nonce"
      end

      @key = issuer_key
      @hash_algorithms = hash_algorithms.map(&:dup).each(&:freeze).freeze
      @require_key_binding = require_key_binding
      @audience = audience
      @nonce = nonce
      @max_kb_age = max_kb_age
      @required_claims = required_claims.map(&:dup).each(&:freeze).freeze
      @issuer = issuer
      @leeway = leeway
      @limits = Codec.limits(max_bytes: max_bytes, max_depth: max_depth, max_disclosures: max_disclosures, max_signatures: max_signatures)
    end

    def verify(source)
      token = split(source)
      now = Time.now.to_f
      results = token.signatures.each_with_index.map do |signature, index|
        payload, header = verify_issuer_jwt(signature)
        processed = Processor.new(payload, signature.fetch("disclosures"), max_depth: @limits[:max_depth], hash_algorithms: @hash_algorithms)
        check_validity_claims(processed.claims, now)
        if @require_key_binding && index.zero?
          raise VerificationError, "Missing required key binding" unless signature["kb_jwt"]

          KeyBinding.verify(signature, claims: processed.claims, hash_algorithm: processed.hash_algorithm, algorithms: @kb_algorithms,
                                       audience: @audience, nonce: @nonce, max_age: @max_kb_age, now: now, max_depth: @limits[:max_depth])
        end
        [processed.claims, header]
      end
      raise VerificationError, "General JWS signatures disclose different claims" unless results.all? { |claims, _| claims == results.first[0] }

      Result.new(claims: results.first[0], headers: results.map(&:last), key_binding_verified: @require_key_binding)
    rescue ParseError, ValidationError, JWT::DecodeError, JWT::EncodeError
      raise VerificationError, "Invalid SD-JWT", cause: nil
    end

    def self.check_times(claims, now, leeway = 0)
      Codec.validate_claim_types(claims)
      raise VerificationError, "Expired credential" if claims.key?("exp") && now >= claims["exp"] + leeway
      raise VerificationError, "Credential is not yet valid" if claims.key?("nbf") && now + leeway < claims["nbf"]
    end

    private

    # RFC 9901 section 7.1 step 1. Reparse Token inputs under this verifier's limits.
    def split(source)
      source = source.to_json(format: :general) if source.is_a?(Token)
      SDJWT.parse(source, **@limits)
    end

    # RFC 9901 section 7.1 step 2. The callback is responsible for issuer/key trust.
    def verify_issuer_jwt(signature)
      _, header, payload = Codec.jwt_parts(signature.fetch("jwt"), max_depth: @limits[:max_depth])
      merged_header = header.merge(signature.fetch("unprotected"))
      raise VerificationError, "Signing algorithm is not allowed" unless @algorithms.include?(merged_header["alg"])

      key = @key.respond_to?(:call) ? @key.call(Codec.freeze_tree(Codec.copy(merged_header)), Codec.freeze_tree(Codec.copy(payload))) : @key
      Codec.verify_signature(signature.fetch("jwt"), key: key, algorithms: @algorithms,
                                                     unprotected: signature.fetch("unprotected"), max_depth: @limits[:max_depth])
    end

    # RFC 9901 section 7.1 step 6: check validity after selective disclosure.
    def check_validity_claims(claims, now)
      raise VerificationError, "Required validity claim missing" unless @required_claims.all? { |name| claims.key?(name) }
      raise VerificationError, "Issuer mismatch" if @issuer && claims["iss"] != @issuer

      if claims.key?("aud")
        audience = claims["aud"]
        audiences = audience.is_a?(String) ? [audience] : audience
        unless audiences.is_a?(Array) && !audiences.empty? && audiences.all?(String) && @audience && audiences.include?(@audience)
          raise VerificationError, "Audience mismatch"
        end
      end
      self.class.check_times(claims, now, @leeway)
    end
  end
end
