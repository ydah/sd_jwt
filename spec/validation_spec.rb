# frozen_string_literal: true

RSpec.describe "Input and issuance limits" do
  it "rejects invalid disclosure paths and absent members" do
    ["", "a", "/a~", "/a~2", "/missing", "/items/01", "/items/-", "/items/2", "/items/0/x", nil].each do |path|
      expect { issuer.issue({ "items" => [1] }, disclose: [path]) }.to raise_error(SDJWT::ValidationError)
    end
    expect { issuer.issue({ "x" => 1 }, disclose: ["/x", "/x"]) }.to raise_error(SDJWT::ValidationError)
  end

  it "rejects reserved names at every level" do
    %w[_sd _sd_alg ...].each do |name|
      expect { issuer.issue({ "a" => [{ name => 1 }] }) }.to raise_error(SDJWT::ValidationError)
    end
  end

  it "rejects non-JSON values and invalid encodings" do
    [Object.new, Float::NAN, Float::INFINITY, { symbol: 1 }, "\xff".b, "\xff".dup.force_encoding("UTF-8")].each do |value|
      expect { issuer.issue({ "a" => value }) }.to raise_error(SDJWT::ValidationError)
    end
    expect { SDJWT::Codec.parse_json("\xff".b) }.to raise_error(SDJWT::ParseError)
    expect { SDJWT::Codec.parse_json(nil) }.to raise_error(SDJWT::ParseError)
    expect { SDJWT::Codec.generate(Float::NAN) }.to raise_error(SDJWT::ValidationError)
  end

  it "rejects non-object claims and headers" do
    expect { issuer.issue([]) }.to raise_error(SDJWT::ValidationError)
    expect { issuer.issue({}, header: []) }.to raise_error(SDJWT::ValidationError)
    expect { issuer.issue({}, decoys: -1) }.to raise_error(ArgumentError)
    expect { issuer.issue({}, disclose: nil) }.to raise_error(SDJWT::ValidationError)
    expect { issuer.issue({}, header: { "alg" => "HS256" }) }.to raise_error(SDJWT::ValidationError)
    expect { issuer.issue({}, header: { "crit" => ["x"] }) }.to raise_error(SDJWT::ValidationError)
    expect { SDJWT::Issuer.new(signing_key: nil).issue({}) }.to raise_error(SDJWT::ValidationError)
    expect { issuer(alg: "none") }.to raise_error(SDJWT::ValidationError)
  end

  it "rejects excessive size, nesting, disclosure counts, and decoy expansion" do
    expect { issuer(max_bytes: 128).issue({ "value" => "x" * 256 }) }.to raise_error(SDJWT::ParseError)
    expect { issuer(max_depth: 2).issue({ "a" => { "b" => { "c" => 1 } } }) }.to raise_error(SDJWT::ValidationError)
    expect { issuer(max_disclosures: 1).issue({ "a" => 1, "b" => 2 }, disclose: %w[/a /b]) }.to raise_error(SDJWT::ValidationError)
    expect { issuer(max_disclosures: 1).issue({ "a" => 1 }, disclose: ["/a"], decoys: 1) }.to raise_error(SDJWT::ValidationError)
    cyclic = {}
    cyclic["self"] = cyclic
    expect { issuer.issue(cyclic) }.to raise_error(SDJWT::ValidationError)
  end

  it "rejects invalid verifier policies" do
    [[], ["none"], [nil], "ES256"].each do |algorithms|
      expect { SDJWT::Verifier.new(algorithms: algorithms, issuer_key: key) }.to raise_error(ArgumentError)
    end
    [[], ["sha-1"], nil].each do |algorithms|
      expect { verifier(hash_algorithms: algorithms) }.to raise_error(ArgumentError)
    end
    [{ max_depth: 0 }, { max_bytes: -1 }, { max_disclosures: 1.5 }, { required_claims: [1] }, { require_key_binding: nil },
     { max_kb_age: 0 }, { leeway: -1 }, { require_key_binding: true }, { key_binding_algorithms: ["HS256"] }].each do |options|
      expect { verifier(**options) }.to raise_error(ArgumentError)
    end
  end

  it "selects only paths that really have disclosures" do
    token = issuer.issue({ "a" => 1 }, disclose: ["/a"])
    expect { token.present(only: nil) }.to raise_error(ArgumentError)
    expect { token.present(only: ["/b"]) }.to raise_error(SDJWT::ValidationError) { |error| expect(error.pointer).to eq("/b") }
  end

  it "rejects duplicate header and payload members before key lookup" do
    header = b64('{"alg":"ES256","alg":"HS256"}')
    payload = b64('{"a":1,"a":2}')
    callback = ->(*) { raise "key lookup must not run" }
    instance = SDJWT::Verifier.new(algorithms: ["ES256"], issuer_key: callback)
    expect { instance.verify("#{header}.#{payload}.#{b64("signature")}~") }.to raise_error(SDJWT::VerificationError)
  end

  it "uses at least 128 bits of random salt independently per disclosure" do
    tokens = 32.times.map { issuer.issue({ "a" => 1 }, disclose: ["/a"]) }
    salts = tokens.map { |token| SDJWT::Disclosure.parse(token.disclosures.first).salt }
    expect(salts.uniq.length).to eq(32)
    expect(salts.map { |salt| SDJWT::Codec.decode(salt).bytesize }).to all(be >= 16)
  end
end

RSpec.describe "Malformed wire inputs" do
  it "rejects arbitrary invalid bytes with a domain-specific error" do
    random = Random.new(310)
    instance = verifier
    1000.times do
      source = Array.new(random.rand(120)) { random.rand(256) }.pack("C*").force_encoding("UTF-8")
      expect { instance.verify(source) }.to raise_error(SDJWT::VerificationError)
    end
  end

  it "rejects JSON numbers beyond finite floating point representation" do
    expect { SDJWT::Codec.parse_json('{"number":1e1000}') }.to raise_error(SDJWT::ParseError)
    encoded = b64('["salt","number",1e1000]')
    digest = SDJWT::HashAlg.digest(encoded)
    expect { verifier.verify(signed({ "_sd" => [digest] }, [encoded])) }.to raise_error(SDJWT::VerificationError)
  end
end
