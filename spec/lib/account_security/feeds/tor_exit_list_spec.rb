# frozen_string_literal: true

require "rails_helper"

RSpec.describe AccountSecurity::Feeds::TorExitList do
  it "ignores abnormally large lines before IP parsing and keeps a plausible feed" do
    response = instance_double(Net::HTTPResponse, code: "200")
    valid_ips = (1..20).map { |value| "8.8.8.#{value}" }
    body = (["x" * (described_class::MAX_LINE_BYTES + 1)] + valid_ips).join("\n")

    allow(described_class).to receive(:fetch).and_return([response, body])
    expect(described_class).to receive(:replace!) do |ips|
      expect(ips).to match_array(valid_ips)
    end

    result = described_class.sync_locked!

    expect(result).to eq(success: true, entry_count: 20)
  end

  it "rejects a feed that is too small without replacing the last good copy" do
    response = instance_double(Net::HTTPResponse, code: "200")
    body = (1..5).map { |value| "8.8.8.#{value}" }.join("\n")

    allow(described_class).to receive(:fetch).and_return([response, body])
    expect(described_class).not_to receive(:replace!)

    expect { described_class.sync_locked! }.to raise_error(RuntimeError, "implausible_feed")
  end
end
