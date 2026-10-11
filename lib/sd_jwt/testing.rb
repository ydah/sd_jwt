# frozen_string_literal: true

require "sd_jwt"

module SDJWT
  # Deterministic salts are available only when this test-only file is explicitly required.
  module Testing
    module_function

    def with_salts(salts)
      previous = Thread.current[:sd_jwt_test_salts]
      raise ArgumentError, "Salts must be strings" unless salts.is_a?(Array) && salts.all?(String)

      Thread.current[:sd_jwt_test_salts] = salts.map(&:dup)
      yield
    ensure
      Thread.current[:sd_jwt_test_salts] = previous
    end
  end
end
