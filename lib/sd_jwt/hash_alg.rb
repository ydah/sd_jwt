# frozen_string_literal: true

module SDJWT
  module HashAlg
    ALGORITHMS = { "sha-256" => "SHA256", "sha-384" => "SHA384", "sha-512" => "SHA512" }.freeze

    module_function

    def validate(name, allowed: ALGORITHMS.keys)
      raise ValidationError, "Unsupported disclosure hash algorithm" unless ALGORITHMS.key?(name) && allowed.include?(name)

      name
    end

    def digest(value, algorithm = "sha-256")
      validate(algorithm)
      raise ValidationError, "Digest input must be ASCII" unless value.is_a?(String) && value.ascii_only?

      Codec.encode(OpenSSL::Digest.digest(ALGORITHMS.fetch(algorithm), value))
    end
  end
end
