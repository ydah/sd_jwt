# frozen_string_literal: true

module SDJWT
  class Token
    attr_reader :signatures, :warnings

    def initialize(signatures, limits:)
      @limits = limits
      @signatures = Codec.freeze_tree(signatures)
      @warnings = [].freeze
      freeze
    end

    def disclosures
      signatures.first.fetch("disclosures").dup
    end

    def issuer_jwt
      signatures.first.fetch("jwt")
    end

    def key_binding_jwt
      signatures.first["kb_jwt"]
    end

    # This payload is NOT authenticated. Use Verifier#verify for trusted claims.
    def unverified_claims
      processor(signatures.first).claims
    end

    def disclosed_paths
      processor(signatures.first).paths.keys
    end

    def to_s
      raise ConversionError, "Multiple signatures require General JSON serialization" unless signatures.length == 1

      raise ConversionError, "Unprotected JWS headers require JSON serialization" unless signatures.first.fetch("unprotected").empty?

      compact(signatures.first)
    end

    def to_json(*, format: :flattened)
      raise ArgumentError, "Unknown JWS JSON format" unless %i[flattened general].include?(format)
      raise ConversionError, "Multiple signatures require General JSON serialization" if format == :flattened && signatures.length != 1

      entries = signatures.each_with_index.map do |signature, index|
        protected_header, payload, encoded_signature = signature.fetch("jwt").split(".", -1)
        header = signature.fetch("unprotected").dup
        header["disclosures"] = signature.fetch("disclosures") if index.zero?
        header["kb_jwt"] = signature["kb_jwt"] if signature["kb_jwt"]
        { "protected" => protected_header, "payload" => payload, "signature" => encoded_signature, "header" => header }
      end
      if format == :general
        entries.each { |entry| entry.delete("payload") }
        Codec.generate({ "payload" => signatures.first.fetch("jwt").split(".", -1)[1], "signatures" => entries })
      else
        Codec.generate(entries.first)
      end
    end

    def present(only:, key_binding: nil)
      raise ArgumentError, "Disclosure paths must be an array" unless only.is_a?(Array)

      selected = signatures.each_with_index.map do |signature, index|
        processed = processor(signature)
        requested = only.flat_map do |path|
          Pointer.tokens(path)
          processed.paths.fetch(path) { raise ValidationError.new("Path is not selectively disclosable", pointer: path) }
        end.uniq
        entry = Codec.copy(signature)
        entry["disclosures"] = signature.fetch("disclosures").select { |encoded| requested.include?(encoded) }
        entry.delete("kb_jwt")
        if key_binding && index.zero?
          raise ArgumentError, "Key binding options must be a hash" unless key_binding.is_a?(Hash)

          entry["kb_jwt"] = KeyBinding.create(compact(entry), hash_algorithm: processed.hash_algorithm, **key_binding)
        end
        entry
      end
      token = self.class.new(selected, limits: @limits)
      serialized = selected.length == 1 && selected.first.fetch("unprotected").empty? ? token.to_s : token.to_json(format: :general)
      SDJWT.parse(serialized, **@limits)
    end

    private

    def compact(signature)
      ([signature.fetch("jwt")] + signature.fetch("disclosures") + [signature.fetch("kb_jwt", "")]).join("~")
    end

    def processor(signature)
      _, _, payload = Codec.jwt_parts(signature.fetch("jwt"), max_depth: @limits[:max_depth])
      Processor.new(payload, signature.fetch("disclosures"), max_depth: @limits[:max_depth])
    end
  end
end
