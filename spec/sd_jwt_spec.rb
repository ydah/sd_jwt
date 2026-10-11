# frozen_string_literal: true

RSpec.describe SDJWT do
  it "has a release version and compatibility namespace" do
    expect(SDJWT::VERSION).to eq("0.1.0")
    expect(SdJwt).to equal(SDJWT)
  end

  it "issues, presents, and verifies nested object and array claims" do
    claims = { "iss" => "issuer", "address" => { "street" => "Harbor", "city" => "Port" }, "items" => [nil, false, 7], "open" => "yes" }
    token = issuer.issue(claims, disclose: ["/address", "/address/street", "/items/0", "/items/1"], decoys: 2)
    expect(verifier.verify(token).claims).to eq(claims)
    selected = token.present(only: ["/address/street", "/items/0"])
    expect(verifier.verify(selected).claims).to eq("iss" => "issuer", "address" => { "street" => "Harbor", "city" => "Port" }, "items" => [nil, 7],
                                                   "open" => "yes")
    expect(token.disclosed_paths).to contain_exactly("/address", "/address/street", "/items/0", "/items/1")
    expect(claims.dig("address", "street")).to eq("Harbor")
  end

  it "sorts and adds decoys inside recursively disclosed parents" do
    token = issuer.issue({ "a" => { "b" => 1, "c" => 2 } }, disclose: ["/a", "/a/b", "/a/c"], decoys: 2)
    parent = token.disclosures.map { |value| SDJWT::Disclosure.parse(value) }.find { |value| value.name == "a" }
    expect(parent.value["_sd"].length).to eq(4)
    expect(parent.value["_sd"]).to eq(parent.value["_sd"].sort)
    expect(verifier.verify(token).claims).to eq("a" => { "b" => 1, "c" => 2 })
  end

  it "supports escaped and empty property names" do
    claims = { "a/b" => { "~" => { "" => "x" } } }
    token = issuer.issue(claims, disclose: ["/a~1b/~0/"])
    expect(verifier.verify(token.present(only: ["/a~1b/~0/"])).claims).to eq(claims)
  end

  it "preserves unknown JSON values and floating point bits in randomized round trips" do
    random = Random.new(804)
    120.times do
      value = [random.rand(2**64)].pack("Q>").unpack1("G")
      next unless value.finite?

      claims = { "n" => value, "ext" => [nil, false, "雪", random.rand(10**30)] }
      token = issuer.issue(claims, disclose: ["/n", "/ext/2"])
      result = verifier.verify(token).claims
      expect([result["n"]].pack("G")).to eq([value].pack("G"))
      expect(result["ext"]).to eq(claims["ext"])
    end
  end

  %w[sha-256 sha-384 sha-512].each do |algorithm|
    it "supports explicitly allowed #{algorithm}" do
      token = issuer(hash_alg: algorithm).issue({ "a" => 1 }, disclose: ["/a"])
      expect(verifier(hash_algorithms: [algorithm]).verify(token).claims).to eq("a" => 1)
    end
  end

  it "requires explicit HMAC authorization and supports RSA and PSS" do
    { "HS256" => "s" * 32, "RS256" => OpenSSL::PKey::RSA.generate(2048), "PS256" => OpenSSL::PKey::RSA.generate(2048) }.each do |algorithm, signing_key|
      token = SDJWT::Issuer.new(signing_key: signing_key, alg: algorithm).issue({ "x" => 1 })
      expect(SDJWT::Verifier.new(algorithms: [algorithm], issuer_key: signing_key).verify(token).claims).to eq("x" => 1)
      expect { verifier.verify(token) }.to raise_error(SDJWT::VerificationError)
    end
  end

  it "provides immutable verified results and tokens" do
    token = issuer.issue({ "a" => ["b"] })
    result = verifier.verify(token)
    expect { result.claims["a"][0].replace("c") }.to raise_error(FrozenError)
    expect { token.signatures.clear }.to raise_error(FrozenError)
    token.unverified_claims["a"].clear
    expect(verifier.verify(token).claims).to eq("a" => ["b"])
    expect(token.warnings).to eq([])
  end

  it "calls issuer key resolution with read-only untrusted header and payload" do
    token = issuer.issue({ "iss" => "trusted" }, header: { "kid" => "key1", "typ" => "example+sd-jwt" })
    callback = lambda do |header, payload|
      expect(header["kid"]).to eq("key1")
      expect(payload["iss"]).to eq("trusted")
      expect(header).to be_frozen
      expect(payload).to be_frozen
      key
    end
    result = SDJWT::Verifier.new(algorithms: ["ES256"], issuer_key: callback, issuer: "trusted").verify(token)
    expect(result.headers.first["typ"]).to eq("example+sd-jwt")
  end
end
