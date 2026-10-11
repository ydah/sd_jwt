# frozen_string_literal: true

require_relative "../script/prepare_rfc_fixtures"

RFCFixtures.prepare unless File.file?(File.join(RFCFixtures::DIRECTORY, "manifest.json"))

RSpec.describe "RFC 9901 conformance vectors" do
  let(:directory) { RFCFixtures::DIRECTORY }
  let(:rfc_key) { JWT::JWK.import(JSON.parse(File.read(File.join(directory, "section-appendix.a.5-2.json")))) }

  def fixture(id)
    JSON.parse(File.read(File.join(directory, "#{id}.json")))
  end

  JSON.parse(File.read(File.join(RFCFixtures::DIRECTORY, "disclosures.json"))).each do |vector|
    it "matches disclosure digest at #{vector.fetch("id")} exactly" do
      disclosure = SDJWT::Disclosure.parse(vector.fetch("encoded"))
      expect(disclosure.digest).to eq(vector.fetch("digest"))
      expect(disclosure.to_s).to eq(vector.fetch("encoded"))
    end
  end

  JSON.parse(File.read(File.join(RFCFixtures::DIRECTORY, "manifest.json"))).each do |entry|
    next unless entry.fetch("kind") == "sd-jwt"

    it "verifies complete RFC token #{entry.fetch("id")}" do
      source = File.read(File.join(directory, "#{entry.fetch("id")}.txt"))
      instance = SDJWT::Verifier.new(algorithms: ["ES256"], issuer_key: rfc_key)
      result = instance.verify(source)
      expected = case entry.fetch("id")
                 when "section-5.1-12"
                   fixture("section-5.1-2").merge(fixture("section-5.1-6").slice("iss", "iat", "exp", "cnf"))
                 when "section-appendix.a.3-6"
                   fixture("section-appendix.a.3-4").merge(fixture("section-appendix.a.3-8").slice("iss", "iat", "exp", "cnf"))
                 when "section-appendix.a.4-6"
                   fixture("section-appendix.a.4-4").merge(fixture("section-appendix.a.4-8").slice("cnf"))
                 else
                   expected_id = { "section-5.2-2" => "section-5.2-7", "section-appendix.a.1-12" => "section-appendix.a.1-14",
                                   "section-appendix.a.2-9" => "section-appendix.a.2-11", "section-appendix.a.3-12" => "section-appendix.a.3-16",
                                   "section-appendix.a.4-12" => "section-appendix.a.4-14" }.fetch(entry.fetch("id"))
                   fixture(expected_id)
                 end
      expect(result.claims).to eq(expected)
      token = SDJWT.parse(source)
      expect(instance.verify(token.to_json(format: :general)).claims).to eq(result.claims)
      expect(token.to_s).to eq(source)
    end
  end

  it "matches the RFC 5.2 selected claims and key binding hash" do
    source = File.read(File.join(directory, "section-5.2-2.txt"))
    expected = fixture("section-5.2-7")
    instance = SDJWT::Verifier.new(algorithms: ["ES256"], issuer_key: rfc_key, require_key_binding: true,
                                   audience: "https://verifier.example.org", nonce: "1234567890")
    allow(Time).to receive(:now).and_return(Time.at(fixture("section-5.2-4").fetch("iat")))
    expect(instance.verify(source).claims).to eq(expected)
  end

  %w[section-8.2-3 section-8.2-5].each do |id|
    it "verifies RFC JSON serialization #{id}" do
      source = File.read(File.join(directory, "#{id}.json"))
      result = SDJWT::Verifier.new(algorithms: ["ES256"], issuer_key: rfc_key).verify(source)
      expect(result.claims).to include("iss")
    end
  end

  it "processes the General JSON illustration with undistributed issuer keys" do
    source = File.read(File.join(directory, "section-8.3-3.json"))
    parsed = SDJWT.parse(source)
    expect(parsed.signatures.length).to eq(2)
    expect(JSON.parse(parsed.to_json(format: :general))).to eq(JSON.parse(source))
    expect(parsed.unverified_claims).to include("given_name", "family_name")
    # The two illustrative issuer signatures do not use the Appendix A.5 key.
    expect { SDJWT::Verifier.new(algorithms: ["ES256"], issuer_key: rfc_key).verify(source) }.to raise_error(SDJWT::VerificationError)
  end

  it "reconstructs flat, structured, and recursively disclosed RFC section 6 examples" do
    vectors = JSON.parse(File.read(File.join(directory, "disclosures.json")))
    %w[section-6.1-2 section-6.2-2 section-6.3-2].each do |id|
      prefix = id.split("-")[1]
      disclosures = vectors.select { |vector| vector.fetch("id").start_with?("section-#{prefix}-") }.map { |vector| vector.fetch("encoded") }
      result = SDJWT::Processor.new(fixture(id), disclosures).claims
      expect(result.slice("sub", "address")).to eq(fixture("section-6-5"))
    end
  end
end
