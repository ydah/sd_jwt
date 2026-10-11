# frozen_string_literal: true

require_relative "lib/sd_jwt/version"

Gem::Specification.new do |spec|
  spec.name = "sd_jwt"
  spec.version = SDJWT::VERSION
  spec.authors = ["Yudai Takada"]
  spec.email = ["t.yudai92@gmail.com"]
  spec.summary = "Issue, present, and verify selectively disclosed JSON Web Tokens"
  spec.description = "RFC 9901 selective disclosure, recursive claims, JWS JSON serialization, and holder key binding, using ruby-jwt for signatures."
  spec.homepage = "https://github.com/ydah/sd_jwt"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.3"
  spec.metadata["allowed_push_host"] = "https://rubygems.org"
  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "#{spec.homepage}/tree/main"
  spec.metadata["changelog_uri"] = "#{spec.homepage}/blob/main/CHANGELOG.md"
  spec.metadata["rubygems_mfa_required"] = "true"
  spec.files = Dir["lib/**/*.rb", "sig/**/*.rbs", "data/*.yml", "README.md", "CHANGELOG.md", "LICENSE.txt", "SECURITY.md"]
  spec.require_paths = ["lib"]
  spec.add_dependency "json", ">= 2.19.4", "< 4"
  spec.add_dependency "jwt", ">= 3.3", "< 4"
end
