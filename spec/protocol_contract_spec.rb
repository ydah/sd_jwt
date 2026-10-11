# frozen_string_literal: true

require "base64"
require "digest"

RSpec.describe "RFC 9901 issuance contracts through JWT and standard-library primitives" do
  def unpack_disclosures(token)
    token.disclosures.to_h do |encoded|
      digest = Base64.urlsafe_encode64(Digest::SHA256.digest(encoded), padding: false)
      [digest, JSON.parse(Base64.urlsafe_decode64(encoded))]
    end
  end

  let(:claims) do
    { "iss" => "contract.example", "profile" => { "name" => "Example", "active" => true },
      "items" => ["alpha", nil, 3], "extension" => { "雪" => false } }
  end
  let(:token) { issuer.issue(claims, disclose: ["/profile", "/profile/name", "/items/0", "/items/1"], decoys: 2) }

  it "signs nested disclosure digests, array placeholders and decoys with the issuer key" do
    payload, header = JWT.decode(token.issuer_jwt, key, true, algorithms: ["ES256"])
    disclosures = unpack_disclosures(token)
    expect(header.fetch("alg")).to eq("ES256")
    expect(payload.slice("iss", "extension", "_sd_alg")).to eq(claims.slice("iss", "extension").merge("_sd_alg" => "sha-256"))
    expect(payload).not_to have_key("profile")
    profile_digest, profile = disclosures.find { |_digest, value| value.length == 3 && value[1] == "profile" }
    name_digest, name = disclosures.find { |_digest, value| value.length == 3 && value[1] == "name" }
    expect(payload.fetch("_sd")).to include(profile_digest)
    expect(profile[2].fetch("_sd")).to include(name_digest)
    expect(profile[2].slice("active")).to eq("active" => true)
    expect(profile[2]).not_to have_key("name")
    expect(name[2]).to eq("Example")
    expect(payload.fetch("_sd").length).to eq(3)
    expect(profile[2].fetch("_sd").length).to eq(3)
    [payload.fetch("_sd"), profile[2].fetch("_sd")].each do |digests|
      decoys = digests - disclosures.keys
      expect(decoys.length).to eq(2)
      expect(decoys.map { |digest| Base64.urlsafe_decode64(digest).bytesize }).to eq([32, 32])
    end
    expect(payload.fetch("items")[0, 2].map { |item| disclosures.fetch(item.fetch("..."))[1] }).to eq(["alpha", nil])
    expect(payload.fetch("items")[2]).to eq(3)
    expect(disclosures.values.map { |value| Base64.urlsafe_decode64(value.first).bytesize }.uniq).to eq([16])
  end

  it "selects exactly the requested disclosures and ancestors without modifying the issuer signature" do
    selected = token.present(only: ["/profile/name", "/items/1"])
    values = unpack_disclosures(selected).values
    expect(selected.issuer_jwt).to eq(token.issuer_jwt)
    expect(values.select { |value| value.length == 3 }.map { |value| value[1] }).to contain_exactly("profile", "name")
    expect(values.select { |value| value.length == 2 }.map { |value| value[1] }).to eq([nil])
    empty = token.present(only: [])
    expect(empty.to_s).to eq("#{token.issuer_jwt}~")
    expect(empty.disclosures).to be_empty
  end

  it "binds a separately verifiable holder signature to the exact presentation bytes" do
    holder_jwk = JWT::JWK.new(holder_key).export.transform_keys(&:to_s)
    issued = issuer.issue(claims, disclose: ["/profile/name"], holder_jwk: holder_jwk)
    presentation = issued.present(only: ["/profile/name"],
                                  key_binding: { key: holder_key, alg: "ES256", aud: "recipient", nonce: "transaction", iat: 100 })
    issuer_payload, = JWT.decode(presentation.issuer_jwt, key, true, algorithms: ["ES256"])
    expect(issuer_payload.fetch("cnf").fetch("jwk")).to eq(holder_jwk)
    bound_payload, header = JWT.decode(presentation.key_binding_jwt, holder_key, true, algorithms: ["ES256"])
    unsigned_presentation = presentation.to_s.delete_suffix(presentation.key_binding_jwt)
    expect(unsigned_presentation).to end_with("~")
    expected_digest = Base64.urlsafe_encode64(Digest::SHA256.digest(unsigned_presentation), padding: false)
    expect(header.fetch("typ")).to eq("kb+jwt")
    expect(bound_payload).to eq("iat" => 100, "aud" => "recipient", "nonce" => "transaction", "sd_hash" => expected_digest)
  end
end
