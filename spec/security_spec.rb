# frozen_string_literal: true

RSpec.describe "RFC 9901 security requirements" do
  let(:claim) { disclosure("salt", "hidden", "private content") }

  def rejected(payload, values = [], **options)
    expect { verifier(**options).verify(signed(payload, values)) }.to raise_error(SDJWT::VerificationError)
  end

  it("rejects duplicate embedded digests") { rejected({ "_sd" => [claim.digest, claim.digest] }, [claim]) }
  it("rejects duplicate decoys") { rejected({ "_sd" => [claim.digest, claim.digest] }) }
  it("rejects duplicate disclosures") { rejected({ "_sd" => [claim.digest] }, [claim, claim]) }
  it("rejects unreferenced disclosures") { rejected({}, [claim]) }
  it("rejects claim collisions") { rejected({ "hidden" => false, "_sd" => [claim.digest] }, [claim]) }
  it("rejects invalid digest arrays") { rejected({ "_sd" => claim.digest }, [claim]) }
  it("rejects nonstring digests") { rejected({ "_sd" => [123] }) }
  it("rejects wrong length digests") { rejected({ "_sd" => [b64("short")] }) }
  it("rejects object disclosures used as array elements") { rejected({ "a" => [{ "..." => claim.digest }] }, [claim]) }
  it("rejects placeholders with extra members") { rejected({ "a" => [{ "..." => claim.digest, "x" => 1 }] }, [claim]) }
  it("rejects ... in ordinary objects") { rejected({ "..." => claim.digest }, [claim]) }
  it("rejects nested hash algorithm declarations") { rejected({ "a" => { "_sd_alg" => "sha-256" } }) }
  it("rejects unknown hash algorithms") { rejected({ "_sd_alg" => "sha-1" }) }
  it("rejects non-string hash algorithms") { rejected({ "_sd_alg" => [] }) }
  it("rejects disallowed hash algorithms") { rejected({ "_sd_alg" => "sha-384" }) }
  it("rejects missing required claims") { rejected({}, [], required_claims: ["exp"]) }
  it("rejects expired disclosed validity claims") do
    exp = disclosure("salt", "exp", 1)
    rejected({ "_sd" => [exp.digest] }, [exp])
  end
  it("rejects a future nbf") { rejected({ "nbf" => Time.now.to_i + 600 }) }
  it("rejects invalid validity types") { %w[exp nbf iat].each { |name| rejected({ name => "100" }) } }
  it("rejects mismatched issuer") { rejected({ "iss" => "other" }, [], issuer: "trusted") }
  it("rejects audiences without an expected audience") { rejected({ "aud" => "recipient" }) }
  it("rejects invalid or mismatched audiences") do
    [[], 1, [1], "different"].each { |aud| rejected({ "aud" => aud }, [], audience: "recipient") }
  end

  it "validates disclosed audience and dates after reconstruction" do
    aud = disclosure("salt", "aud", %w[recipient other])
    expect(verifier(audience: "recipient").verify(signed({ "_sd" => [aud.digest], "nbf" => Time.now.to_i - 5 }, [aud])).claims["aud"]).to include("recipient")
    expect(verifier(leeway: 20).verify(signed({ "exp" => Time.now.to_i - 1 })).claims).to have_key("exp")
  end

  it "rejects array disclosures used as object claims" do
    item = disclosure("salt", 1)
    rejected({ "_sd" => [item.digest] }, [item])
  end

  it "rejects duplicate digests across recursive disclosures" do
    parent = disclosure("parent", "a", { "_sd" => [claim.digest] })
    rejected({ "_sd" => [claim.digest, parent.digest] }, [claim, parent])
  end

  it "rejects reserved names without leaking their values" do
    %w[_sd ... _sd_alg].each do |name|
      encoded = b64(JSON.generate(["salt", name, "private secret"]))
      digest = SDJWT::HashAlg.digest(encoded)
      expect { verifier.verify(signed({ "_sd" => [digest] }, [encoded])) }.to raise_error(SDJWT::VerificationError) do |error|
        expect(error.message).not_to include("private secret")
        expect(error.cause).to be_nil
      end
    end
  end

  it "rejects none even when configured" do
    expect { SDJWT::Verifier.new(algorithms: ["none"], issuer_key: nil) }.to raise_error(ArgumentError)
    expect { verifier.verify("#{JWT.encode({}, nil, "none")}~") }.to raise_error(SDJWT::VerificationError)
  end

  it "rejects altered signatures and missing keys" do
    token = issuer.issue({ "a" => 1 })
    other = OpenSSL::PKey::EC.generate("prime256v1")
    expect { SDJWT::Verifier.new(algorithms: ["ES256"], issuer_key: other).verify(token) }.to raise_error(SDJWT::VerificationError)
    expect { SDJWT::Verifier.new(algorithms: ["ES256"], issuer_key: nil).verify(token) }.to raise_error(SDJWT::VerificationError)
  end

  it "rejects unsupported critical headers" do
    %w[crit b64 disclosures kb_jwt].each do |name|
      expect { verifier.verify(signed({}, [], header: { name => [] })) }.to raise_error(SDJWT::VerificationError)
    end
  end

  it "enforces verifier limits even for already parsed Token objects" do
    token = issuer.issue({ "a" => 1, "b" => 2 }, disclose: ["/a", "/b"])
    expect { verifier(max_disclosures: 1).verify(token) }.to raise_error(SDJWT::VerificationError)
    expect { verifier(max_bytes: 10).verify(token) }.to raise_error(SDJWT::VerificationError)
    deep = issuer.issue({ "a" => { "b" => { "c" => 1 } } }, disclose: ["/a", "/a/b"])
    expect { verifier(max_depth: 1).verify(deep) }.to raise_error(SDJWT::VerificationError)
  end
end

RSpec.describe "Signature and registered claim boundaries" do
  it "rejects nonstandard ECDSA raw signature lengths" do
    token = issuer.issue({})
    parts = token.issuer_jwt.split(".")
    raw = SDJWT::Codec.decode(parts[2])
    parts[2] = b64("#{raw[0, 32]}\0#{raw[32, 32]}")
    expect { verifier.verify("#{parts.join(".")}~") }.to raise_error(SDJWT::VerificationError)
  end

  it "rejects invalid registered claim types during issuance and verification" do
    %w[iss sub jti cnf].each do |name|
      expect { issuer.issue({ name => false }) }.to raise_error(SDJWT::ValidationError)
      expect { verifier.verify(signed({ name => false })) }.to raise_error(SDJWT::VerificationError)
    end
    expect { issuer.issue({ "aud" => 1 }) }.to raise_error(SDJWT::ValidationError)
  end

  it "checks confirmation key coordinate and modulus sizes before crypto operations" do
    invalid = [{ "kty" => "EC", "crv" => "P-256", "x" => b64("x" * 31), "y" => b64("y" * 32) },
               { "kty" => "RSA", "n" => b64("x" * 1025), "e" => b64("\1\0\1") },
               { "kty" => "RSA", "n" => b64("\xff" * 256), "e" => b64("x" * 9) }]
    invalid.each do |jwk|
      expect { issuer.issue({}, holder_jwk: jwk) }.to raise_error(SDJWT::ValidationError)
    end
  end

  it "supports RSA holder key binding" do
    holder = OpenSSL::PKey::RSA.generate(2048)
    public_jwk = JWT::JWK.new(holder).export.transform_keys(&:to_s)
    token = issuer.issue({}, holder_jwk: public_jwk)
    presentation = token.present(only: [], key_binding: { key: holder, alg: "RS256", aud: "a", nonce: "n" })
    expect(verifier(require_key_binding: true, audience: "a", nonce: "n").verify(presentation).key_binding_verified).to be(true)
  end
end
