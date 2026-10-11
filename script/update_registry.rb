# frozen_string_literal: true

require "digest"
require "fileutils"
require "json"
require "rexml/document"
require "tempfile"
require "yaml"

root = File.expand_path("..", __dir__)
manifest_path = File.join(__dir__, "registry_sources.json")
manifest = JSON.parse(File.read(manifest_path))
directory = File.join(root, "tmp", "registry")
FileUtils.mkdir_p(directory)
refresh = ARGV.delete("--refresh")
raise "Usage: ruby script/update_registry.rb [--refresh]" unless ARGV.empty?

Tempfile.create(["iana-jwt-", ".xml"], directory) do |file|
  cached = File.join(directory, "iana-jwt.xml")
  if File.file?(cached) && !refresh
    FileUtils.cp(cached, file.path)
  else
    success = system("curl", "--fail", "--silent", "--show-error", "--location", "--proto", "=https", "--proto-redir", "=https",
                     "--connect-timeout", "10", "--max-time", "60", "--retry", "3", manifest.fetch("url"), "--output", file.path)
    raise "IANA download failed" unless success
  end

  checksum = Digest::SHA256.file(file.path).hexdigest
  raise "IANA registry changed; review with --refresh" unless refresh || checksum == manifest.fetch("sha256")

  document = REXML::Document.new(File.read(file.path))
  records = REXML::XPath.match(document, "//*[local-name()='record']").select do |record|
    record.get_elements("xref").any? { |reference| reference.attributes["data"] == "rfc9901" }
  end
  names = records.map { |record| record.elements["value"].text }
  expected = YAML.safe_load_file(File.join(root, "data", "protocol.yml")).fetch("claims").keys
  raise "RFC 9901 claim registrations changed" unless names.sort == expected.sort

  FileUtils.cp(file.path, File.join(directory, "iana-jwt.xml"))
  if refresh
    manifest["sha256"] = checksum
    File.write(manifest_path, "#{JSON.pretty_generate(manifest)}\n")
  end
  puts "IANA RFC 9901 registrations match #{expected.length} original protocol metadata entries"
end
