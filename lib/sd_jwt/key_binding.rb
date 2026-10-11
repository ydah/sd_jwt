# frozen_string_literal: true

module SDJWT
  module KeyBinding
    module_function

    def public_jwk(jwk)
      raise ValidationError, "Holder JWK must be an object" unless jwk.is_a?(Hash)

      object = Codec.copy(jwk)
      unless %w[EC RSA].include?(object["kty"]) && !object.keys.intersect?(%w[d p q dp dq qi oth k])
        raise ValidationError, "Holder JWK must contain only an asymmetric public key"
      end
      raise ValidationError, "Holder JWK does not permit signatures" if object.key?("use") && object["use"] != "sig"
      if object.key?("key_ops") && (!object["key_ops"].is_a?(Array) || !object["key_ops"].include?("verify"))
        raise ValidationError, "Holder JWK does not permit verification"
      end

      validate_key_size(object)
      key = import_public_key(object)
      Codec.validate_rsa_key(key) if object["kty"] == "RSA"
      object
    rescue ParseError, JWT::JWKError, OpenSSL::OpenSSLError, ArgumentError, TypeError
      raise ValidationError, "Invalid holder public key", cause: nil
    end

    def import_public_key(object)
      JWT::JWK.import(object).public_key
    rescue StandardError
      # JRuby's crypto provider can raise Java exceptions for invalid key material.
      raise ValidationError, "Invalid holder public key", cause: nil
    end

    def validate_key_size(jwk)
      if jwk["kty"] == "EC"
        size = { "P-256" => 32, "P-384" => 48, "P-521" => 66 }[jwk["crv"]]
        unless size && %w[x y].all? { |coordinate| Codec.decode(jwk[coordinate]).bytesize == size }
          raise ValidationError, "Unsupported holder elliptic curve or coordinate size"
        end
      else
        modulus = Codec.decode(jwk["n"])
        exponent = Codec.decode(jwk["e"])
        unless (256..1024).cover?(modulus.bytesize) && modulus.getbyte(0) >= 128 && (1..8).cover?(exponent.bytesize) && exponent.getbyte(0).positive?
          raise ValidationError, "Holder RSA key must use a 2048 to 8192 bit modulus and bounded exponent"
        end
        unless modulus.getbyte(-1).odd? && exponent.getbyte(-1).odd? && exponent.unpack1("H*").to_i(16) >= 3
          raise ValidationError, "Invalid holder RSA modulus or exponent"
        end
      end
    end

    def create(sd_jwt, key:, alg:, aud:, nonce:, hash_algorithm: "sha-256", iat: Time.now.to_i)
      raise ValidationError, "Holder signatures must be asymmetric" if alg.to_s.start_with?("HS")
      unless aud.is_a?(String) && !aud.empty? && nonce.is_a?(String) && !nonce.empty? && iat.is_a?(Integer)
        raise ValidationError, "Invalid key binding transaction"
      end

      payload = { "iat" => iat, "aud" => aud, "nonce" => nonce, "sd_hash" => HashAlg.digest(sd_jwt, hash_algorithm) }
      Codec.sign(payload, key: key, algorithm: alg, header: { "typ" => "kb+jwt" })
    end

    def verify(signature, claims:, hash_algorithm:, algorithms:, audience:, nonce:, max_age:, now:, max_depth:)
      jwk = claims.dig("cnf", "jwk") if claims["cnf"].is_a?(Hash)
      public_jwk(jwk)
      key = JWT::JWK.import(jwk)
      kb_payload, kb_header = Codec.verify_signature(signature.fetch("kb_jwt"), key: key, algorithms: algorithms, max_depth: max_depth)
      raise VerificationError, "Invalid key binding type" unless kb_header["typ"] == "kb+jwt"

      iat = kb_payload["iat"]
      raise VerificationError, "Invalid key binding issuance time" unless iat.is_a?(Numeric) && iat.finite? && iat <= now && iat >= now - max_age
      raise VerificationError, "Key binding transaction mismatch" unless kb_payload["aud"] == audience && kb_payload["nonce"] == nonce

      sd_jwt = ([signature.fetch("jwt")] + signature.fetch("disclosures") + [""]).join("~")
      expected = HashAlg.digest(sd_jwt, hash_algorithm)
      actual = kb_payload["sd_hash"]
      unless actual.is_a?(String) && actual.bytesize == expected.bytesize && OpenSSL.fixed_length_secure_compare(actual, expected)
        raise VerificationError, "Key binding digest mismatch"
      end

      Verifier.check_times(kb_payload, now)
      true
    rescue JWT::JWKError, KeyError, OpenSSL::OpenSSLError, ArgumentError, TypeError
      raise VerificationError, "Invalid key binding", cause: nil
    end
  end
end
