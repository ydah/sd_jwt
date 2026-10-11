# frozen_string_literal: true

module SDJWT
  class Processor
    attr_reader :claims, :paths, :hash_algorithm

    def initialize(payload, disclosures, max_depth: Codec::MAX_DEPTH, hash_algorithms: HashAlg::ALGORITHMS.keys)
      @max_depth = max_depth
      @hash_algorithm = HashAlg.validate(payload.fetch("_sd_alg", "sha-256"), allowed: hash_algorithms)
      @digests = compute_digests(disclosures)
      @seen = Set.new
      @used = Set.new
      @paths = {}
      @claims = embed_disclosures(payload, "", [], 0)
      check_unreferenced
    end

    private

    # RFC 9901 section 7.1 step 3.a: hash the original encoded disclosures.
    def compute_digests(disclosures)
      disclosures.each_with_object({}) do |encoded, result|
        disclosure = Disclosure.parse(encoded, max_depth: @max_depth + 2)
        digest = disclosure.digest(@hash_algorithm)
        raise VerificationError, "Duplicate disclosure" if result.key?(digest)

        result[digest] = disclosure
      end
    end

    # RFC 9901 section 7.1 step 3.b-f: recursively restore disclosed claims.
    def embed_disclosures(value, path, dependencies, depth)
      raise VerificationError, "Nesting limit exceeded" if depth > @max_depth

      case value
      when Hash then embed_object(value, path, dependencies, depth)
      when Array
        value.each_with_index.with_object([]) do |(item, index), result|
          child_path = Pointer.append(path, index)
          if item.is_a?(Hash) && item.key?("...")
            raise VerificationError, "Invalid array placeholder" unless item.keys == ["..."]

            disclosure = find_disclosure(item["..."])
            next unless disclosure
            raise VerificationError, "Invalid array disclosure" unless disclosure.array_element?

            chain = dependencies + [disclosure.encoded]
            @paths[child_path] = chain
            result << embed_disclosures(disclosure.value, child_path, chain, depth + 1)
          else
            result << embed_disclosures(item, child_path, dependencies, depth + 1)
          end
        end
      else value
      end
    end

    def embed_object(value, path, dependencies, depth)
      raise VerificationError, "Reserved object member" if value.key?("...")
      raise VerificationError, "Hash algorithm must be a root claim" if depth.positive? && value.key?("_sd_alg")

      result = value.each_with_object({}) do |(name, item), output|
        next if %w[_sd _sd_alg].include?(name)

        output[name] = embed_disclosures(item, Pointer.append(path, name), dependencies, depth + 1)
      end
      digests = value.fetch("_sd", [])
      raise VerificationError, "Invalid digest array" unless digests.is_a?(Array)

      digests.each do |digest|
        disclosure = find_disclosure(digest)
        next unless disclosure
        raise VerificationError, "Invalid object disclosure" if disclosure.array_element?
        raise VerificationError, "Disclosed claim collision" if result.key?(disclosure.name) || %w[_sd_alg].include?(disclosure.name)

        child_path = Pointer.append(path, disclosure.name)
        chain = dependencies + [disclosure.encoded]
        @paths[child_path] = chain
        result[disclosure.name] = embed_disclosures(disclosure.value, child_path, chain, depth + 1)
      end
      result
    end

    def find_disclosure(digest)
      raise VerificationError, "Invalid embedded digest" unless digest.is_a?(String)

      raw = Codec.decode(digest)
      expected_length = { "sha-256" => 32, "sha-384" => 48, "sha-512" => 64 }.fetch(@hash_algorithm)
      raise VerificationError, "Invalid embedded digest length" unless raw.bytesize == expected_length

      check_duplicates(digest)
      disclosure = @digests[digest]
      @used << digest if disclosure
      disclosure
    end

    # RFC 9901 section 7.1 step 4: includes undisclosed and decoy digests.
    def check_duplicates(digest)
      raise VerificationError, "Duplicate embedded digest" unless @seen.add?(digest)
    end

    # RFC 9901 section 7.1 step 5: no extraneous disclosures are accepted.
    def check_unreferenced
      raise VerificationError, "Unreferenced disclosure" unless @used.length == @digests.length
    end
  end
end
