# frozen_string_literal: true

require_relative "../lib/sd_jwt"

key = OpenSSL::PKey::EC.generate("prime256v1")
issuer = SDJWT::Issuer.new(signing_key: key)
verifier = SDJWT::Verifier.new(algorithms: ["ES256"], issuer_key: key)
[10, 100, 1000].each do |count|
  claims = count.times.to_h { |index| ["claim#{index}", "value#{index}"] }
  paths = claims.keys.map { |name| "/#{name}" }
  nil
  start = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  token = issuer.issue(claims, disclose: paths)
  issuance = Process.clock_gettime(Process::CLOCK_MONOTONIC) - start
  start = Process.clock_gettime(Process::CLOCK_MONOTONIC)
  raise "round trip mismatch" unless verifier.verify(token).claims == claims

  verification = Process.clock_gettime(Process::CLOCK_MONOTONIC) - start
  rss = begin
    IO.popen(["ps", "-o", "rss=", "-p", Process.pid.to_s], &:read).strip
  rescue Errno::EPERM
    "unavailable"
  end
  puts "#{count} disclosures, #{token.to_s.bytesize} bytes: issue=#{issuance.round(4)}s verify=#{verification.round(4)}s rss=#{rss} KiB"
end
begin
  verifier.verify("x" * (SDJWT::Codec::MAX_BYTES + 1))
  raise "oversized token accepted"
rescue SDJWT::VerificationError
  puts "Input above 1 MiB rejected before parsing"
end
