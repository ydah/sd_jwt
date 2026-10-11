# frozen_string_literal: true

RSpec.describe "SD-JWT serializations" do
  let(:token) { issuer.issue({ "a" => 1 }, disclose: ["/a"]) }

  %i[flattened general].each do |format|
    it "round trips #{format}" do
      encoded = token.to_json(format: format)
      expect(SDJWT.parse(encoded).to_s).to eq(token.to_s)
      expect(verifier.verify(encoded).claims).to eq("a" => 1)
    end
  end

  it "verifies every General JWS signature and rejects any invalid signature" do
    first = JSON.parse(token.to_json)
    _, _, payload = SDJWT::Codec.jwt_parts(token.issuer_jwt)
    other_key = OpenSSL::PKey::EC.generate("prime256v1")
    other = JWT.encode(payload, other_key, "ES256").split(".")
    expect(other[1]).to eq(first["payload"])
    object = { "payload" => first["payload"], "signatures" => [first.except("payload"),
                                                               { "protected" => other[0], "signature" => other[2], "header" => {} }] }
    resolver = ->(header, _) { header["kid"] == "second" ? other_key : key }
    protected_header = b64(JSON.generate({ "alg" => "ES256", "kid" => "second" }))
    signing_input = "#{protected_header}.#{first["payload"]}"
    signature = JWT::JWA.create_signer(algorithm: "ES256", key: other_key).sign(data: signing_input)
    object["signatures"][1].merge!("protected" => protected_header, "signature" => b64(signature))
    instance = SDJWT::Verifier.new(algorithms: ["ES256"], issuer_key: resolver)
    expect(instance.verify(JSON.generate(object)).headers.length).to eq(2)
    parsed = SDJWT.parse(JSON.generate(object))
    expect { parsed.to_s }.to raise_error(SDJWT::ConversionError)
    expect { parsed.to_json }.to raise_error(SDJWT::ConversionError)
    expect(instance.verify(parsed.present(only: [])).claims).to eq({})
    object["signatures"][1]["signature"] = first["signature"]
    expect { instance.verify(JSON.generate(object)) }.to raise_error(SDJWT::VerificationError)
  end

  it "rejects disclosure metadata on General signatures after the first" do
    first = JSON.parse(token.to_json)
    second = Marshal.load(Marshal.dump(first))
    object = { "payload" => first.delete("payload"), "signatures" => [first, second.except("payload")] }
    expect { verifier.verify(JSON.generate(object)) }.to raise_error(SDJWT::VerificationError)
  end

  it "supports unprotected alg and kid with exact JSON signature input" do
    header = b64(JSON.generate({ "typ" => "example+sd-jwt" }))
    payload = b64('{"x":1}')
    signature = JWT::JWA.create_signer(algorithm: "ES256", key: key).sign(data: "#{header}.#{payload}")
    source = JSON.generate({ "protected" => header, "payload" => payload, "signature" => b64(signature),
                             "header" => { "alg" => "ES256", "kid" => "test", "disclosures" => [] } })
    parsed = SDJWT.parse(source)
    expect(verifier.verify(parsed).claims).to eq("x" => 1)
    expect(JSON.parse(parsed.to_json).dig("header", "kid")).to eq("test")
    expect { parsed.to_s }.to raise_error(SDJWT::ConversionError)
  end

  ["", "x", "x~", "x~~", "x~a~", "x\u2603~", "{}", "[]", nil].each do |source|
    it("rejects malformed serialization #{source.inspect}") { expect { SDJWT.parse(source) }.to raise_error(SDJWT::ParseError) }
  end

  it "rejects malformed JSON members and colliding headers" do
    original = JSON.parse(token.to_json)
    mutations = [{ "header" => [] }, { "signature" => nil }, { "payload" => 1 }, { "header" => { "disclosures" => "x" } },
                 { "header" => { "kb_jwt" => nil } }, { "header" => { "alg" => "ES256" } }, { "header" => { "crit" => [] } },
                 { "signatures" => [] }, { "signatures" => [nil] }]
    mutations.each do |change|
      expect { SDJWT.parse(JSON.generate(original.merge(change))) }.to raise_error(SDJWT::ParseError)
    end
    expect { SDJWT.parse(JSON.generate({ "payload" => original["payload"], "signatures" => [1] })) }.to raise_error(SDJWT::ParseError)
    expect { SDJWT.parse(token.to_s, strict: false) }.to raise_error(ArgumentError)
    expect { token.to_json(format: :unknown) }.to raise_error(ArgumentError)
  end

  it "caps General JWS signature count" do
    object = JSON.parse(token.to_json(format: :general))
    object["signatures"] *= 2
    expect { verifier(max_signatures: 1).verify(JSON.generate(object)) }.to raise_error(SDJWT::VerificationError)
  end
end
