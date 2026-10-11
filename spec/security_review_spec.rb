# frozen_string_literal: true

RSpec.describe "Independent security review regressions" do
  def hmac_token(secret, algorithm = "HS256")
    input = [b64(JSON.generate({ "alg" => algorithm })), b64('{"admin":true}')].join(".")
    signature = OpenSSL::HMAC.digest(algorithm.sub("HS", "SHA"), secret, input)
    "#{input}.#{b64(signature)}~"
  end

  it "rejects public RSA key encodings used as an HMAC secret" do
    rsa = OpenSSL::PKey::RSA.generate(2048)
    [rsa.public_key.to_pem, rsa.public_key.to_der].each do |public_bytes|
      instance = SDJWT::Verifier.new(algorithms: %w[RS256 HS256], issuer_key: public_bytes)
      expect { instance.verify(hmac_token(public_bytes)) }.to raise_error(SDJWT::VerificationError)
      expect { SDJWT::Issuer.new(signing_key: public_bytes, alg: "HS256").issue({}) }.to raise_error(SDJWT::ValidationError)
    end
  end

  it "rejects public EC key encodings and SSH public keys used as HMAC secrets" do
    [key.public_to_pem, key.public_to_der, "ssh-rsa #{b64("public key data")} fixture"].each do |public_bytes|
      instance = SDJWT::Verifier.new(algorithms: %w[HS256 ES256], issuer_key: ->(*) { public_bytes })
      expect { instance.verify(hmac_token(public_bytes)) }.to raise_error(SDJWT::VerificationError)
    end
  end

  %w[HS256 HS384 HS512].each do |algorithm|
    it "requires a full digest length secret for #{algorithm} independently of global JWT configuration" do
      short_secret = "s" * ((algorithm.delete_prefix("HS").to_i / 8) - 1)
      instance = SDJWT::Verifier.new(algorithms: [algorithm], issuer_key: short_secret)
      expect { instance.verify(hmac_token(short_secret, algorithm)) }.to raise_error(SDJWT::VerificationError)
      expect { SDJWT::Issuer.new(signing_key: short_secret, alg: algorithm).issue({}) }.to raise_error(SDJWT::ValidationError)
    end

    it "accepts sufficiently long random #{algorithm} secrets as strings and JWKs" do
      secret = SecureRandom.random_bytes(algorithm.delete_prefix("HS").to_i / 8)
      [secret, JWT::JWK.new(secret, alg: algorithm)].each do |signing_key|
        issued = SDJWT::Issuer.new(signing_key: signing_key, alg: algorithm).issue({ "valid" => true })
        instance = SDJWT::Verifier.new(algorithms: [algorithm], issuer_key: signing_key)
        expect(instance.verify(issued).claims).to eq("valid" => true)
      end
    end
  end

  it "rejects holder RSA keys with a trivial exponent or even modulus" do
    rsa = OpenSSL::PKey::RSA.generate(2048)
    jwk = JWT::JWK.new(rsa).export.transform_keys(&:to_s)
    invalid = [jwk.merge("e" => b64("\1")), jwk.merge("e" => b64("\2")),
               jwk.merge("n" => b64(("\xff".b * 255) + "\xfe".b))]
    invalid.each do |public_key|
      expect { issuer.issue({}, holder_jwk: public_key) }.to raise_error(SDJWT::ValidationError)
    end
  end

  it "rejects holder binding forged without a private key for an exponent-one RSA key" do
    rsa = OpenSSL::PKey::RSA.generate(2048)
    jwk = JWT::JWK.new(rsa).export.transform_keys(&:to_s).merge("e" => b64("\1"))
    credential = signed({ "cnf" => { "jwk" => jwk } })
    claims = { "iat" => Time.now.to_i, "aud" => "verifier", "nonce" => "challenge", "sd_hash" => SDJWT::HashAlg.digest(credential) }
    input = [b64('{"alg":"RS256","typ":"kb+jwt"}'), b64(JSON.generate(claims))].join(".")
    algorithm = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::ObjectId("SHA256"), OpenSSL::ASN1::Null(nil)])
    digest = OpenSSL::ASN1::OctetString(OpenSSL::Digest::SHA256.digest(input))
    digest_info = OpenSSL::ASN1::Sequence([algorithm, digest]).to_der
    forged_signature = "\0\1".b + ("\xff".b * (256 - digest_info.bytesize - 3)) + "\0".b + digest_info
    presentation = "#{credential}#{input}.#{b64(forged_signature)}"
    instance = verifier(require_key_binding: true, audience: "verifier", nonce: "challenge")
    expect { instance.verify(presentation) }.to raise_error(SDJWT::VerificationError)
  end

  %w[PS256 PS384 PS512].each do |algorithm|
    it "requires the JOSE salt length for #{algorithm}" do
      rsa = OpenSSL::PKey::RSA.generate(2048)
      input = [b64(JSON.generate({ "alg" => algorithm })), b64("{}")].join(".")
      hash = algorithm.sub("PS", "SHA")
      instance = SDJWT::Verifier.new(algorithms: [algorithm], issuer_key: rsa)
      [0, 1, :max].each do |length|
        signature = rsa.sign_pss(hash, input, salt_length: length, mgf1_hash: hash)
        expect { instance.verify("#{input}.#{b64(signature)}~") }.to raise_error(SDJWT::VerificationError)
      end
      signature = rsa.sign_pss(hash, input, salt_length: :digest, mgf1_hash: hash)
      expect(instance.verify("#{input}.#{b64(signature)}~").claims).to eq({})
    end
  end

  %w[RS256 PS256].each do |algorithm|
    it "rejects undersized RSA issuer keys for #{algorithm}" do
      rsa = OpenSSL::PKey::RSA.generate(1024)
      input = [b64(JSON.generate({ "alg" => algorithm })), b64("{}")].join(".")
      signature = if algorithm == "RS256"
                    rsa.sign("SHA256", input)
                  else
                    rsa.sign_pss("SHA256", input, salt_length: :digest, mgf1_hash: "SHA256")
                  end
      instance = SDJWT::Verifier.new(algorithms: [algorithm], issuer_key: rsa)
      expect { instance.verify("#{input}.#{b64(signature)}~") }.to raise_error(SDJWT::VerificationError)
    end
  end

  it "rejects altered disclosure names and values, including equivalent re-encodings" do
    token = issuer.issue({ "sensitive" => "original" }, disclose: ["/sensitive"])
    original = JSON.parse(SDJWT::Codec.decode(token.disclosures.first))
    [original.dup.tap { |raw| raw[1] = "admin" }, original.dup.tap { |raw| raw[2] = true }].each do |raw|
      expect { verifier.verify("#{token.issuer_jwt}~#{b64(JSON.generate(raw))}~") }.to raise_error(SDJWT::VerificationError)
    end
    reencoded = b64(JSON.pretty_generate(original))
    expect { verifier.verify("#{token.issuer_jwt}~#{reencoded}~") }.to raise_error(SDJWT::VerificationError)
  end

  it "enforces key-binding time boundaries and transaction claim types" do
    allow(Time).to receive(:now).and_return(Time.at(2_000_000_000))
    jwk = JWT::JWK.new(holder_key).export.transform_keys(&:to_s)
    credential = issuer.issue({}, holder_jwk: jwk)
    claims = { "iat" => Time.now.to_i, "aud" => "verifier", "nonce" => "challenge", "sd_hash" => SDJWT::HashAlg.digest(credential.to_s) }
    instance = verifier(require_key_binding: true, audience: "verifier", nonce: "challenge", max_kb_age: 300)
    [Time.now.to_i, Time.now.to_i - 300].each do |iat|
      kb = SDJWT::Codec.sign(claims.merge("iat" => iat), key: holder_key, algorithm: "ES256", header: { "typ" => "kb+jwt" })
      expect(instance.verify(credential.to_s + kb).key_binding_verified).to be(true)
    end
    invalid = [{ "iat" => Time.now.to_i + 0.1 }, { "iat" => Time.now.to_i - 300.1 }, { "aud" => ["verifier"] },
               { "nonce" => ["challenge"] }, { "exp" => Time.now.to_i }, { "nbf" => Time.now.to_i + 1 }]
    invalid.each do |change|
      kb = SDJWT::Codec.sign(claims.merge(change), key: holder_key, algorithm: "ES256", header: { "typ" => "kb+jwt" })
      expect { instance.verify(credential.to_s + kb) }.to raise_error(SDJWT::VerificationError)
    end
  end

  it "keeps JWK algorithm restrictions when verifying strict PSS signatures" do
    rsa = OpenSSL::PKey::RSA.generate(2048)
    key = JWT::JWK.new(rsa, alg: "RS256")
    token = SDJWT::Issuer.new(signing_key: rsa, alg: "PS256").issue({})
    instance = SDJWT::Verifier.new(algorithms: %w[RS256 PS256], issuer_key: key)
    expect { instance.verify(token) }.to raise_error(SDJWT::VerificationError)
  end

  it "normalizes native provider failures for malformed confirmation keys" do
    invalid = [{ "kty" => "EC", "crv" => "P-256", "x" => b64("\0" * 32), "y" => b64("\0" * 32) },
               { "kty" => "RSA", "n" => b64("\xff".b * 256), "e" => b64("\1\0\1") }]
    instance = verifier(require_key_binding: true, audience: "a", nonce: "n")
    invalid.each do |jwk|
      credential = signed({ "cnf" => { "jwk" => jwk } })
      kb = SDJWT::KeyBinding.create(credential, key: holder_key, alg: "ES256", aud: "a", nonce: "n")
      expect { instance.verify(credential + kb) }.to raise_error(SDJWT::VerificationError) { |error| expect(error.cause).to be_nil }
    end
  end
end
