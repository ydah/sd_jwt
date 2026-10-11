# frozen_string_literal: true

require "securerandom"

module SDJWT
  class Disclosure
    attr_reader :encoded, :salt, :name, :value

    def self.parse(encoded, max_depth: Codec::MAX_DEPTH)
      raw = Codec.parse_json(Codec.decode(encoded), max_depth: max_depth)
      new(raw, encoded: encoded, max_depth: max_depth)
    end

    def initialize(raw, encoded: nil, max_depth: Codec::MAX_DEPTH)
      raise ParseError, "Invalid disclosure structure" unless raw.is_a?(Array) && [2, 3].include?(raw.length) && raw[0].is_a?(String)
      raise ParseError, "Invalid disclosure claim name" if raw.length == 3 && (!raw[1].is_a?(String) || %w[_sd ...].include?(raw[1]))

      raw = Codec.copy(raw, max_depth: max_depth)
      @salt = raw[0].freeze
      @name = raw.length == 3 ? raw[1].freeze : nil
      @value = Codec.freeze_tree(raw.last)
      @encoded = (encoded || Codec.encode(Codec.generate(raw))).dup.freeze
      freeze
    end

    def array_element?
      name.nil?
    end

    def digest(algorithm = "sha-256")
      HashAlg.digest(encoded, algorithm)
    end

    def to_s
      encoded
    end
  end
end
