# frozen_string_literal: true

module SDJWT
  module Serialization
    module_function

    def parse(source, limits:)
      raise ParseError, "Input must be a string" unless source.is_a?(String)
      raise ParseError, "Input size limit exceeded" if source.bytesize > limits[:max_bytes]

      source = source.dup.force_encoding(Encoding::UTF_8)
      raise ParseError, "Invalid UTF-8 input" unless source.valid_encoding?

      entries = if source.lstrip.start_with?("{")
                  parse_json(source, limits)
                else
                  parse_compact(source)
                end
      raise ParseError, "Signature limit exceeded" if entries.length > limits[:max_signatures]

      entries.each do |entry|
        validate_entry(entry, limits)
      end
      Token.new(entries, limits: limits)
    end

    def parse_compact(source)
      raise ParseError, "Invalid compact serialization" unless source.ascii_only? && source.include?("~")

      pieces = source.split("~", -1)
      jwt = pieces.shift
      kb_jwt = pieces.pop
      entry = { "jwt" => jwt, "disclosures" => pieces, "unprotected" => {} }
      entry["kb_jwt"] = kb_jwt unless kb_jwt.empty?
      [entry]
    end

    def parse_json(source, limits)
      object = Codec.parse_json(source, max_depth: limits[:max_depth] + 4)
      raise ParseError, "JWS serialization must be an object" unless object.is_a?(Hash)

      if object.key?("signatures")
        unless !object.keys.intersect?(%w[signature protected header]) && object["signatures"].is_a?(Array) && !object["signatures"].empty?
          raise ParseError, "Invalid General JWS serialization"
        end

        entries = object["signatures"]
      else
        entries = [object]
      end
      raise ParseError, "Signature limit exceeded" if entries.length > limits[:max_signatures]

      first_header = entries.first.is_a?(Hash) ? entries.first.fetch("header", {}) : {}
      raise ParseError, "Invalid first unprotected header" unless first_header.is_a?(Hash)

      entries.each_with_index.map do |entry, index|
        raise ParseError, "Invalid JWS signature entry" unless entry.is_a?(Hash)

        header = entry.fetch("header", {})
        raise ParseError, "Invalid unprotected header" unless header.is_a?(Hash)

        if index.positive? && header.keys.intersect?(%w[disclosures kb_jwt])
          raise ParseError, "General JWS disclosure metadata is permitted only on the first signature"
        end

        parts = [entry.fetch("protected", ""), object["payload"], entry["signature"]]
        raise ParseError, "Invalid JWS members" unless parts.all?(String)

        result = { "jwt" => parts.join("."), "disclosures" => first_header.fetch("disclosures", []),
                   "unprotected" => header.except("disclosures", "kb_jwt") }
        result["kb_jwt"] = header["kb_jwt"] if header.key?("kb_jwt")
        result
      end
    end

    def validate_entry(entry, limits)
      _, header, = Codec.jwt_parts(entry.fetch("jwt"), max_depth: limits[:max_depth])
      raise ParseError, "Disclosure metadata must be unprotected" if header.keys.intersect?(%w[disclosures kb_jwt])
      raise ParseError, "Overlapping JWS headers" if header.keys.intersect?(entry.fetch("unprotected").keys)
      if header.keys.intersect?(%w[crit b64]) || entry.fetch("unprotected").keys.intersect?(%w[crit b64])
        raise ParseError, "Unsupported critical or unencoded JWS"
      end

      disclosures = entry.fetch("disclosures")
      raise ParseError, "Invalid disclosures" unless disclosures.is_a?(Array)
      raise ParseError, "Disclosure limit exceeded" if disclosures.length > limits[:max_disclosures]

      disclosures.each { |encoded| Disclosure.parse(encoded, max_depth: limits[:max_depth] + 2) }
      Codec.jwt_parts(entry["kb_jwt"], max_depth: limits[:max_depth]) if entry.key?("kb_jwt")
    end
  end
end
