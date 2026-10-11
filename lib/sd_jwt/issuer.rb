# frozen_string_literal: true

module SDJWT
  class Issuer
    def initialize(signing_key:, alg: "ES256", hash_alg: "sha-256", max_bytes: Codec::MAX_BYTES,
                   max_depth: Codec::MAX_DEPTH, max_disclosures: Codec::MAX_DISCLOSURES)
      @key = signing_key
      @algorithm = Codec.signing_algorithm(alg)
      @hash_algorithm = HashAlg.validate(hash_alg)
      @limits = Codec.limits(max_bytes: max_bytes, max_depth: max_depth, max_disclosures: max_disclosures)
    end

    def issue(claims, disclose: [], decoys: 0, holder_jwk: nil, header: {})
      raise ValidationError, "Claims and header must be objects" unless claims.is_a?(Hash) && header.is_a?(Hash)
      raise ArgumentError, "Decoys must be a nonnegative integer" unless decoys.is_a?(Integer) && decoys >= 0
      unless disclose.is_a?(Array) && disclose.length <= @limits[:max_disclosures] && decoys <= @limits[:max_disclosures]
        raise ValidationError, "Disclosure limit exceeded"
      end
      raise ValidationError, "Duplicate disclosure path" unless disclose.uniq.length == disclose.length

      payload = Codec.copy(claims, max_depth: @limits[:max_depth])
      reject_reserved(payload)
      Codec.validate_claim_types(payload)

      if holder_jwk
        raise ValidationError, "Confirmation claim already exists" if payload.key?("cnf")

        payload["cnf"] = { "jwk" => KeyBinding.public_jwk(holder_jwk) }
      end
      finalized = Set.new
      object_parents = disclose.map { |path| Pointer.locate(payload, path).first }.grep(Hash).map(&:object_id).uniq
      raise ValidationError, "Disclosure and decoy limit exceeded" if disclose.length + (decoys * object_parents.length) > @limits[:max_disclosures]

      disclosures = disclose.sort_by { |path| -Pointer.tokens(path).length }.map do |path|
        parent, name = Pointer.locate(payload, path)
        add_decoys(parent[name], decoys, finalized)
        raw = parent.is_a?(Array) ? [salt, parent[name]] : [salt, name, parent.delete(name)]
        disclosure = Disclosure.new(raw, max_depth: @limits[:max_depth] + 2)
        digest = disclosure.digest(@hash_algorithm)
        if parent.is_a?(Array)
          parent[name] = { "..." => digest }
        else
          (parent["_sd"] ||= []) << digest
        end
        disclosure.encoded
      end
      add_decoys(payload, decoys, finalized)
      payload["_sd_alg"] = @hash_algorithm
      compact = Codec.sign(payload, key: @key, algorithm: @algorithm, header: Codec.copy(header))
      SDJWT.parse(([compact] + disclosures + [""]).join("~"), **@limits)
    end

    private

    def salt
      if defined?(Testing) && Thread.current[:sd_jwt_test_salts]
        return Thread.current[:sd_jwt_test_salts].shift || raise(ValidationError, "Test salts exhausted")
      end

      Codec.encode(SecureRandom.random_bytes(16))
    end

    def reject_reserved(value)
      case value
      when Hash
        raise ValidationError, "Reserved claim name" if value.keys.intersect?(%w[_sd _sd_alg ...])

        value.each_value { |item| reject_reserved(item) }
      when Array then value.each { |item| reject_reserved(item) }
      end
    end

    def add_decoys(value, count, finalized)
      case value
      when Hash
        value.each_value { |item| add_decoys(item, count, finalized) }
        return unless value.key?("_sd") && finalized.add?(value.object_id)

        count.times { value["_sd"] << HashAlg.digest(Codec.encode(SecureRandom.random_bytes(32)), @hash_algorithm) }
        value["_sd"].sort!
      when Array then value.each { |item| add_decoys(item, count, finalized) }
      end
    end
  end
end
