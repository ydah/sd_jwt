# frozen_string_literal: true

module SDJWT
  class Error < StandardError; end
  class ParseError < Error; end

  class ValidationError < Error
    attr_reader :pointer

    def initialize(message, pointer: "")
      @pointer = pointer
      super(message)
    end
  end

  class ConversionError < Error; end
  class VerificationError < Error; end
end
