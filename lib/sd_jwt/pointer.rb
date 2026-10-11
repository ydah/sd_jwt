# frozen_string_literal: true

module SDJWT
  module Pointer
    module_function

    def tokens(path)
      unless path.is_a?(String) && path.start_with?("/") && !path.match?(/~(?:[^01]|$)/)
        raise ValidationError.new("Invalid disclosure JSON Pointer", pointer: path.is_a?(String) ? path : "")
      end

      path.split("/", -1).drop(1).map { |part| part.gsub("~1", "/").gsub("~0", "~") }
    end

    def append(path, name)
      "#{path}/#{name.to_s.gsub("~", "~0").gsub("/", "~1")}"
    end

    def locate(root, path)
      parts = tokens(path)
      parent = parts[0...-1].reduce(root) { |value, name| value_at(value, name, path) }
      name = parts.last
      value_at(parent, name, path)
      [parent, parent.is_a?(Array) ? Integer(name, 10) : name]
    end

    def value_at(value, name, path)
      if value.is_a?(Hash) && value.key?(name)
        value[name]
      elsif value.is_a?(Array) && name.match?(/\A(?:0|[1-9][0-9]*)\z/) && name.to_i < value.length
        value[name.to_i]
      else
        raise ValidationError.new("Disclosure path does not exist", pointer: path)
      end
    end
  end
end
