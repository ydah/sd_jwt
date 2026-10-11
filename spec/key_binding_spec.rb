# frozen_string_literal: true

RSpec.describe "Holder key binding" do
  let(:public_jwk) { JWT::JWK.new(holder_key).export.transform_keys(&:to_s) }
  let(:token) { issuer.issue({ "x" => 1, "y" => 2 }, disclose: ["/x", "/y"], holder_jwk: public_jwk) }
  let(:options) { { key: holder_key, alg: "ES256", aud: "recipient", nonce: "challenge" } }
  let(:kb_verifier) { verifier(require_key_binding: true, audience: "recipient", nonce: "challenge") }

  it "binds the exact disclosure order and trailing tilde" do
    presentation = token.present(only: ["/x"], key_binding: options)
    result = kb_verifier.verify(presentation)
    expect(result.claims).to include("x" => 1)
    expect(result.claims).not_to have_key("y")
    expect(result.key_binding_verified).to be(true)
    expect(verifier.verify(presentation).key_binding_verified).to be(false)
    selected = presentation.present(only: [])
    expect(selected.key_binding_jwt).to be_nil
    expect { kb_verifier.verify(selected) }.to raise_error(SDJWT::VerificationError)
  end

  %i[flattened general].each do |format|
    it "verifies KB-JWT in #{format} JSON serialization" do
      presentation = token.present(only: ["/x"], key_binding: options)
      expect(kb_verifier.verify(presentation.to_json(format: format)).claims).to include("x" => 1)
    end
  end

  it "rejects absent key binding regardless of cnf" do
    expect { kb_verifier.verify(token) }.to raise_error(SDJWT::VerificationError)
    expect { kb_verifier.verify(issuer.issue({})) }.to raise_error(SDJWT::VerificationError)
  end

  { "typ" => "JWT", "iat" => 0, "aud" => "other", "nonce" => "other", "sd_hash" => "x" }.each do |claim, value|
    it "rejects an invalid #{claim}" do
      presentation = token.present(only: ["/x"], key_binding: options)
      parts = presentation.to_s.split("~", -1)
      payload, header = JWT.decode(parts.pop, nil, false)
      (claim == "typ" ? header : payload)[claim] = value
      parts << JWT.encode(payload, holder_key, "ES256", header)
      expect { kb_verifier.verify(parts.join("~")) }.to raise_error(SDJWT::VerificationError)
    end
  end

  %w[iat aud nonce sd_hash].each do |claim|
    it "rejects a missing #{claim}" do
      presentation = token.present(only: [], key_binding: options)
      parts = presentation.to_s.split("~", -1)
      payload, header = JWT.decode(parts.pop, nil, false)
      payload.delete(claim)
      parts << JWT.encode(payload, holder_key, "ES256", header)
      expect { kb_verifier.verify(parts.join("~")) }.to raise_error(SDJWT::VerificationError)
    end
  end

  it "rejects future, nonnumeric, and expired key binding dates" do
    [Time.now.to_i + 600, "now", nil].each do |iat|
      payload = { "iat" => iat, "aud" => "recipient", "nonce" => "challenge", "sd_hash" => SDJWT::HashAlg.digest(token.to_s) }
      kb = SDJWT::Codec.sign(payload, key: holder_key, algorithm: "ES256", header: { "typ" => "kb+jwt" })
      expect { kb_verifier.verify(token.to_s + kb) }.to raise_error(SDJWT::VerificationError)
    end
    expired = token.present(only: [], key_binding: options.merge(iat: Time.now.to_i - 600))
    expect { kb_verifier.verify(expired) }.to raise_error(SDJWT::VerificationError)
  end

  it "rejects replay with reordered or removed disclosures" do
    presentation = token.present(only: ["/x", "/y"], key_binding: options).to_s
    parts = presentation.split("~")
    parts[1], parts[2] = parts[2], parts[1]
    expect { kb_verifier.verify(parts.join("~")) }.to raise_error(SDJWT::VerificationError)
    parts.delete_at(1)
    expect { kb_verifier.verify(parts.join("~")) }.to raise_error(SDJWT::VerificationError)
  end

  it "rejects a signature from a different holder" do
    other = OpenSSL::PKey::EC.generate("prime256v1")
    presentation = token.present(only: [], key_binding: options.merge(key: other))
    expect { kb_verifier.verify(presentation) }.to raise_error(SDJWT::VerificationError)
  end

  it "rejects missing, symmetric, private, or unsuitable confirmation keys" do
    invalid_keys = [nil, {}, { "kty" => "oct", "k" => b64("secret") }, public_jwk.merge("d" => "secret"),
                    public_jwk.merge("use" => "enc"), public_jwk.merge("key_ops" => ["sign"]), public_jwk.merge("x" => "x")]
    invalid_keys.each do |jwk|
      bad = issuer.issue({ "cnf" => { "jwk" => jwk } })
      kb = SDJWT::KeyBinding.create(bad.to_s, **options)
      expect { kb_verifier.verify(bad.to_s + kb) }.to raise_error(SDJWT::VerificationError)
    end
    expect { issuer.issue({}, holder_jwk: { "kty" => "oct", "k" => "x" }) }.to raise_error(SDJWT::ValidationError)
  end

  it "rejects invalid holder signing requests and confirmation overwrites" do
    expect { issuer.issue({ "cnf" => {} }, holder_jwk: public_jwk) }.to raise_error(SDJWT::ValidationError)
    expect { token.present(only: [], key_binding: options.merge(alg: "HS256")) }.to raise_error(SDJWT::ValidationError)
    expect { token.present(only: [], key_binding: options.merge(aud: "")) }.to raise_error(SDJWT::ValidationError)
    expect { token.present(only: [], key_binding: []) }.to raise_error(ArgumentError)
  end
end
