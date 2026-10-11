# frozen_string_literal: true

require "bundler/gem_tasks"
require "rspec/core/rake_task"

task :fixtures do
  require_relative "script/prepare_rfc_fixtures"
  RFCFixtures.prepare
end
RSpec::Core::RakeTask.new(:spec)
task spec: :fixtures
task test: :spec
task default: :test
