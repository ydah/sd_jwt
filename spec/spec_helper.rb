# frozen_string_literal: true

if ENV["COVERAGE"]
  require "simplecov"
  SimpleCov.start do
    add_filter "/spec/"
    add_filter "/vendor/"
    minimum_coverage 90
  end
end

require "sd_jwt"
require "sd_jwt/testing"

module Helpers
  def key
    @key ||= OpenSSL::PKey::EC.generate("prime256v1")
  end

  def holder_key
    @holder_key ||= OpenSSL::PKey::EC.generate("prime256v1")
  end

  def issuer(**)
    SDJWT::Issuer.new(signing_key: key, **)
  end

  def verifier(**)
    SDJWT::Verifier.new(algorithms: ["ES256"], issuer_key: key, **)
  end

  def disclosure(*values)
    SDJWT::Disclosure.new(values)
  end

  def signed(payload, disclosures = [], header: {}, key_binding: "")
    token = JWT::Token.new(payload: payload, header: header)
    token.sign!(key: key, algorithm: "ES256")
    jwt = token.jwt
    ([jwt] + disclosures.map(&:to_s) + [key_binding]).join("~")
  end

  def b64(value)
    SDJWT::Codec.encode(value)
  end
end

RSpec.configure do |config|
  config.include Helpers
  config.disable_monkey_patching!
  config.expect_with(:rspec) { |expectations| expectations.syntax = :expect }
end
