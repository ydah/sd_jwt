# frozen_string_literal: true

require "base64"
require "json"
require "openssl"
require "jwt"
require "set" # Required by Ruby 3.3 and 3.4.

module SDJWT
  module Codec
    MAX_BYTES = 1_048_576
    MAX_DEPTH = 32
    MAX_DISCLOSURES = 1000
    MAX_SIGNATURES = 16
    ALGORITHMS = %w[ES256 ES384 ES512 RS256 RS384 RS512 PS256 PS384 PS512 HS256 HS384 HS512].freeze

    # Keep JSON generation local: some TruffleRuby versions round Float#to_s incorrectly.
    class SigningToken < JWT::Token
      def encoded_header
        @encoded_header ||= Codec.encode(Codec.generate(header))
      end

      def encoded_payload
        @encoded_payload ||= Codec.encode(Codec.generate(payload))
      end
    end

    module_function

    def limits(max_bytes:, max_depth:, max_disclosures:, max_signatures: MAX_SIGNATURES)
      values = { max_bytes: max_bytes, max_depth: max_depth, max_disclosures: max_disclosures, max_signatures: max_signatures }
      raise ArgumentError, "Limits must be positive integers" unless values.values.all? { |n| n.is_a?(Integer) && n.positive? }

      values.freeze
    end

    def parse_json(source, max_depth: MAX_DEPTH)
      raise ParseError, "JSON input must be a string" unless source.is_a?(String)

      source = source.dup.force_encoding(Encoding::UTF_8)
      raise ParseError, "Invalid UTF-8 JSON" unless source.valid_encoding?

      value = JSON.parse(source, allow_duplicate_key: false, max_nesting: max_depth, allow_nan: false)
      copy(value, max_depth: max_depth)
    rescue JSON::ParserError, ValidationError, EncodingError, ArgumentError
      raise ParseError, "Invalid JSON", cause: nil
    end

    def generate(value)
      JSON.generate(precise(value), max_nesting: false, allow_nan: false)
    rescue JSON::GeneratorError, EncodingError, ArgumentError
      raise ValidationError, "Invalid JSON value", cause: nil
    end

    def precise(value)
      case value
      when Hash then value.transform_values { |item| precise(item) }
      when Array then value.map { |item| precise(item) }
      when Float
        raise ValidationError, "Non-finite number" unless value.finite?
        return value unless RUBY_ENGINE == "truffleruby"

        number = format("%.17g", value)
        number += ".0" unless number.match?(/[.eE]/)
        JSON::Fragment.new(number)
      else value
      end
    end

    def copy(value, max_depth: MAX_DEPTH, depth: 0)
      raise ValidationError, "Nesting limit exceeded" if depth > max_depth

      case value
      when Hash
        raise ValidationError, "JSON members must be strings" unless value.keys.all?(String)

        value.to_h { |key, item| [key.dup, copy(item, max_depth: max_depth, depth: depth + 1)] }
      when Array then value.map { |item| copy(item, max_depth: max_depth, depth: depth + 1) }
      when String
        raise ValidationError, "Invalid UTF-8 string" unless value.encoding == Encoding::UTF_8 || value.ascii_only?
        raise ValidationError, "Invalid UTF-8 string" unless value.valid_encoding?

        value.dup
      when Float
        raise ValidationError, "Non-finite number" unless value.finite?

        value
      when Integer, TrueClass, FalseClass, NilClass then value
      else raise ValidationError, "Unsupported JSON value"
      end
    end

    def freeze_tree(value)
      case value
      when Hash then value.each do |key, item|
        key.freeze
        freeze_tree(item)
      end
      when Array then value.each { |item| freeze_tree(item) }
      end
      value.freeze
    end

    def encode(bytes)
      Base64.urlsafe_encode64(bytes, padding: false)
    end

    def decode(value, empty: false)
      raise ParseError, "Invalid base64url" unless value.is_a?(String) && value.match?(/\A[A-Za-z0-9_-]*\z/) && (empty || !value.empty?)

      decoded = Base64.urlsafe_decode64(value)
      raise ParseError, "Noncanonical base64url" unless encode(decoded) == value

      decoded
    rescue ArgumentError
      raise ParseError, "Invalid base64url", cause: nil
    end

    def signing_algorithm(algorithm)
      raise ValidationError, "Unsupported signing algorithm" unless ALGORITHMS.include?(algorithm)

      algorithm
    end

    def allowlist(algorithms)
      unless algorithms.is_a?(Array) && !algorithms.empty? && algorithms.all? { |alg| ALGORITHMS.include?(alg) }
        raise ArgumentError, "A nonempty supported signing algorithm allowlist is required"
      end

      algorithms.map(&:dup).each(&:freeze).freeze
    end

    def validate_claim_types(claims)
      %w[iss sub jti].each do |name|
        raise ValidationError, "Invalid registered claim type" if claims.key?(name) && !claims[name].is_a?(String)
      end
      %w[exp nbf iat].each do |name|
        next unless claims.key?(name)

        value = claims[name]
        raise ValidationError, "Invalid NumericDate claim" unless value.is_a?(Numeric) && value.finite?
      end
      if claims.key?("aud")
        audience = claims["aud"]
        unless audience.is_a?(String) || (audience.is_a?(Array) && !audience.empty? && audience.all?(String))
          raise ValidationError, "Invalid audience claim type"
        end
      end
      raise ValidationError, "Invalid confirmation claim type" if claims.key?("cnf") && !claims["cnf"].is_a?(Hash)
    end

    def sign(payload, key:, algorithm:, header: {})
      signing_algorithm(algorithm)
      validate_hmac_key(key, algorithm)
      validate_rsa_key(key.is_a?(JWT::JWK::KeyBase) ? key.verify_key : key) if algorithm.start_with?("RS", "PS")
      raise ValidationError, "Protected header algorithm mismatch" if header.key?("alg") && header["alg"] != algorithm
      raise ValidationError, "Unsupported protected header" if header.keys.intersect?(%w[crit b64 disclosures kb_jwt])

      token = SigningToken.new(payload: payload, header: header)
      token.sign!(key: key, algorithm: algorithm)
      token.jwt
    rescue JWT::EncodeError, JWT::DecodeError, OpenSSL::OpenSSLError, ArgumentError
      raise ValidationError, "Signing failed", cause: nil
    end

    def validate_hmac_key(key, algorithm)
      return unless algorithm.start_with?("HS")

      secret = key.is_a?(JWT::JWK::KeyBase) ? key.verify_key : key
      minimum = algorithm.delete_prefix("HS").to_i / 8
      raise ValidationError, "HMAC requires a secret at least as long as the hash output" unless secret.is_a?(String) && secret.bytesize >= minimum
      raise ValidationError, "Asymmetric key material cannot be an HMAC secret" if asymmetric_key_material?(secret)
    end

    def asymmetric_key_material?(secret)
      return true if secret.b.include?("-----BEGIN ") || secret.b.match?(/\A\s*(?:ssh-|ecdsa-sha2-)/n)

      # Also recognize DER encodings. Supplying a password prevents terminal prompts.
      OpenSSL::PKey.read(secret, "")
      true
    rescue OpenSSL::OpenSSLError, ArgumentError
      false
    end

    def validate_rsa_key(key)
      return if key.is_a?(OpenSSL::PKey::RSA) && key.n.num_bits >= 2048 && key.n.to_i.odd? && key.e.to_i >= 3 && key.e.to_i.odd? && key.e < key.n

      raise ValidationError, "RSA requires a valid public exponent and an odd modulus of at least 2048 bits"
    end

    def jwt_parts(compact, max_depth: MAX_DEPTH)
      raise ParseError, "Invalid JWS" unless compact.is_a?(String)

      parts = compact.split(".", -1)
      raise ParseError, "Invalid JWS" unless parts.length == 3

      header = parts[0].empty? ? {} : parse_json(decode(parts[0]), max_depth: max_depth)
      payload = parse_json(decode(parts[1]), max_depth: max_depth)
      decode(parts[2])
      raise ParseError, "JWS header and payload must be objects" unless header.is_a?(Hash) && payload.is_a?(Hash)

      [parts, header, payload]
    end

    def verify_signature(compact, key:, algorithms:, unprotected: {}, max_depth: MAX_DEPTH)
      parts, protected_header, payload = jwt_parts(compact, max_depth: max_depth)
      raise VerificationError, "Overlapping JWS headers" if protected_header.keys.intersect?(unprotected.keys)
      raise VerificationError, "Unsupported critical or unencoded JWS" if protected_header.keys.intersect?(%w[crit b64])
      raise VerificationError, "Unsupported unprotected security header" if unprotected.keys.intersect?(%w[crit b64])

      header = protected_header.merge(unprotected)
      algorithm = header["alg"]
      raise VerificationError, "Signing algorithm is not allowed" unless algorithms.include?(algorithm)
      raise VerificationError, "Missing verification key" if key.nil?

      if key.is_a?(JWT::JWK::KeyBase)
        raise VerificationError, "Verification JWK algorithm mismatch" if key[:alg] && key[:alg] != algorithm
        raise VerificationError, "Verification JWK use mismatch" if key[:use] && key[:use] != "sig"
        if key[:key_ops] && (!key[:key_ops].is_a?(Array) || !key[:key_ops].include?("verify"))
          raise VerificationError, "Verification JWK does not permit verification"
        end

        key = key.verify_key
      end
      validate_hmac_key(key, algorithm)
      validate_rsa_key(key) if algorithm.start_with?("RS", "PS")
      signature = decode(parts[2])
      expected_bytes = { "ES256" => 64, "ES384" => 96, "ES512" => 132 }[algorithm]
      raise VerificationError, "Invalid ECDSA signature length" if expected_bytes && signature.bytesize != expected_bytes

      data = parts.first(2).join(".")
      valid = if algorithm.start_with?("PS")
                # ruby-jwt accepts arbitrary PSS salt lengths; JOSE requires the hash length.
                digest = algorithm.sub("PS", "SHA")
                key.verify_pss(digest, signature, data, salt_length: :digest, mgf1_hash: digest)
              else
                verifiers = JWT::JWA.create_verifiers(algorithms: [algorithm], keys: [key], preferred_algorithm: algorithm)
                verifiers.any? { |verifier| verifier.verify(data: data, signature: signature) }
              end
      raise VerificationError, "Invalid signature" unless valid

      [payload, header]
    rescue JWT::DecodeError, JWT::EncodeError, OpenSSL::OpenSSLError, ArgumentError, TypeError, NoMethodError
      raise VerificationError, "Signature verification failed", cause: nil
    end
  end
end
