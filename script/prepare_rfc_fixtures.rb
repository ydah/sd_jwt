# frozen_string_literal: true

require "base64"
require "digest"
require "fileutils"
require "json"
require "rexml/document"
require "tempfile"

module RFCFixtures
  ROOT = File.expand_path("../tmp/rfc", __dir__)
  DIRECTORY = File.join(ROOT, "fixtures")
  MANIFEST = JSON.parse(File.read(File.join(__dir__, "rfc_sources.json"))).freeze

  module_function

  def prepare
    source = MANIFEST.fetch("source")
    FileUtils.mkdir_p(File.join(ROOT, "sources"))
    path = File.join(ROOT, "sources", "rfc9901.xml")
    unless File.file?(path)
      Tempfile.create(["download", ".xml"], File.dirname(path)) do |file|
        success = system("curl", "--fail", "--silent", "--show-error", "--location", "--proto", "=https", "--proto-redir", "=https",
                         "--retry", "3", "--connect-timeout", "10", "--max-time", "60", source.fetch("url"), "--output", file.path)
        raise "RFC download failed" unless success
        raise "RFC checksum mismatch" unless Digest::SHA256.file(file.path).hexdigest == source.fetch("sha256")

        File.rename(file.path, path)
      end
    end
    raise "RFC checksum mismatch" unless Digest::SHA256.file(path).hexdigest == source.fetch("sha256")

    FileUtils.mkdir_p(DIRECTORY)
    document = REXML::Document.new(File.read(path))
    entries = REXML::XPath.match(document, "//sourcecode | //artwork").map do |element|
      extract(element)
    end
    disclosures = REXML::XPath.match(document, "//ul").filter_map do |element|
      items = element.get_elements("li")
      digest = items.find { |item| item.get_elements("t").first&.text == "SHA-256 Hash:" }
      encoded = items.find { |item| item.get_elements("t").first&.text == "Disclosure:" }
      next unless digest && encoded

      { "id" => element.attributes["pn"], "digest" => REXML::XPath.first(digest, ".//tt").text,
        "encoded" => REXML::XPath.first(encoded, ".//tt").text }
    end
    File.write(File.join(DIRECTORY, "disclosures.json"), JSON.pretty_generate(disclosures))
    File.write(File.join(DIRECTORY, "manifest.json"), JSON.pretty_generate(entries))
    File.write(File.join(DIRECTORY, "LICENSE"), <<~NOTICE)
      RFC 9901 Code Components used only for conformance tests.
      Copyright (c) 2025 IETF Trust and the persons identified as authors of the code. All rights reserved.
      Redistribution and use in source and binary forms, with or without modification, is permitted pursuant to,
      and subject to the license terms contained in, the Revised BSD License set forth in Section 4.c of the
      IETF Trust's Legal Provisions Relating to IETF Documents (https://trustee.ietf.org/license-info).
      Source attribution and corrections: manifest.json and adjacent .original.txt files.
      The full source and author notices are in ../sources/rfc9901.xml.
      #{source.fetch("url")}
    NOTICE
    expected = MANIFEST.fetch("counts")
    raise "RFC extraction count changed" unless entries.length == expected.fetch("blocks") && disclosures.length == expected.fetch("disclosures")

    puts "RFC fixtures: #{entries.length} blocks, #{disclosures.length} disclosure digest vectors (ignored tmp/)"
  end

  def extract(element)
    id = element.attributes["pn"]
    original = element.text.to_s.strip
    File.write(File.join(DIRECTORY, "#{id}.original.txt"), original)
    normalized = original.gsub(/"(?:[^"\\]|\\.)*"/m) { |string| string.gsub(/\r?\n\s*/, "") }
    entry = { "id" => id, "kind" => "illustration", "normalization" => normalized == original ? "none" : "removed line wrapping inside encoded strings" }
    begin
      value = JSON.parse(normalized)
      File.write(File.join(DIRECTORY, "#{id}.json"), JSON.pretty_generate(value))
      entry["kind"] = "json"
    rescue JSON::ParserError
      compact = original.gsub(/\s+/, "")
      if compact.match?(/\A[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_.~-]+\z/)
        File.write(File.join(DIRECTORY, "#{id}.txt"), compact)
        entry["kind"] = compact.include?("~") ? "sd-jwt" : "jws"
        entry["normalization"] = "removed token display line wrapping"
      end
    end
    entry
  end
end

RFCFixtures.prepare if $PROGRAM_NAME == __FILE__
