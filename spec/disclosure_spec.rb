# frozen_string_literal: true

RSpec.describe SDJWT::Disclosure do
  it "hashes the original ASCII disclosure rather than decoded JSON" do
    raw = '["salt", "claim", {"value": 1}]'
    encoded = b64(raw)
    value = described_class.parse(encoded)
    expect(value.to_s).to eq(encoded)
    expect(value.salt).to eq("salt")
    expect(value.name).to eq("claim")
    expect(value.digest).to eq(b64(OpenSSL::Digest::SHA256.digest(encoded)))
    expect(value.digest).not_to eq(b64(OpenSSL::Digest::SHA256.digest(raw)))
  end

  [nil, {}, [], ["s"], ["s", "n", 1, 2], [1, "n", 1], ["s", 1, 1], ["s", "_sd", 1], ["s", "...", 1]].each do |raw|
    it "rejects malformed disclosure #{raw.inspect}" do
      expect { described_class.parse(b64(JSON.generate(raw))) }.to raise_error(SDJWT::ParseError)
    end
  end

  ["!", "a", "YQ=", "YR", "", "a\n", nil].each do |encoded|
    it "rejects invalid or noncanonical base64url #{encoded.inspect}" do
      expect { described_class.parse(encoded) }.to raise_error(SDJWT::ParseError)
    end
  end

  it "rejects duplicate members under json 2 and 3" do
    expect { described_class.parse(b64('["s", "n", {"x":1,"x":2}]')) }.to raise_error(SDJWT::ParseError)
  end

  it "requires supported hash algorithms and ASCII data" do
    expect { SDJWT::HashAlg.digest("x", "md5") }.to raise_error(SDJWT::ValidationError)
    expect { SDJWT::HashAlg.digest("雪") }.to raise_error(SDJWT::ValidationError)
  end

  it "isolates deterministic salts by thread and restores nested contexts" do
    SDJWT::Testing.with_salts(%w[a b]) do
      first = issuer.issue({ "x" => 1 }, disclose: ["/x"])
      SDJWT::Testing.with_salts(["nested"]) do
        expect(described_class.parse(issuer.issue({ "x" => 1 }, disclose: ["/x"]).disclosures[0]).salt).to eq("nested")
      end
      second = issuer.issue({ "x" => 1 }, disclose: ["/x"])
      expect([first, second].map { |token| described_class.parse(token.disclosures[0]).salt }).to eq(%w[a b])
      expect { issuer.issue({ "x" => 1 }, disclose: ["/x"]) }.to raise_error(SDJWT::ValidationError)
    end
    expect(Thread.current[:sd_jwt_test_salts]).to be_nil
    expect { SDJWT::Testing.with_salts([1]) { nil } }.to raise_error(ArgumentError)
  end
end

RSpec.describe "Deterministic test issuance" do
  it "uses compact encoding with the supplied salt" do
    SDJWT::Testing.with_salts(["test-salt"]) do
      token = issuer.issue({ "number" => 7 }, disclose: ["/number"])
      expected = b64('["test-salt","number",7]')
      expect(token.disclosures).to eq([expected])
      _, _, payload = SDJWT::Codec.jwt_parts(token.issuer_jwt)
      expect(payload["_sd"]).to eq([b64(OpenSSL::Digest::SHA256.digest(expected))])
    end
  end

  it "restores a surrounding salt sequence when invalid nested configuration raises" do
    SDJWT::Testing.with_salts(["outer"]) do
      expect { SDJWT::Testing.with_salts([nil]) { nil } }.to raise_error(ArgumentError)
      expect(SDJWT::Disclosure.parse(issuer.issue({ "a" => 1 }, disclose: ["/a"]).disclosures[0]).salt).to eq("outer")
    end
  end
end
