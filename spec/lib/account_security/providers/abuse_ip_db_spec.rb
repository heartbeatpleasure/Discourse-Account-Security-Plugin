# frozen_string_literal: true
require "rails_helper"

RSpec.describe AccountSecurity::Providers::AbuseIpDb do
  subject(:client) { described_class.new }

  it "bounds streamed response bodies" do
    response = instance_double(Net::HTTPResponse)
    allow(response).to receive(:[]).with("Content-Length").and_return(nil)
    allow(response).to receive(:read_body).and_yield("x" * (described_class::MAX_CHECK_BYTES + 1))
    expect { client.send(:read_bounded_body, response, described_class::MAX_CHECK_BYTES) }.to raise_error(described_class::ResponseTooLarge)
  end

  it "normalizes only the required non-verbose CHECK fields" do
    payload = {
      "data" => {
        "ipAddress" => "8.8.8.8",
        "abuseConfidenceScore" => 75,
        "totalReports" => 10,
        "numDistinctUsers" => 4,
        "lastReportedAt" => 1.day.ago.iso8601,
        "usageType" => "Data Center/Web Hosting/Transit",
        "isp" => "Example ISP",
        "domain" => "example.test",
        "countryCode" => "US",
        "isTor" => false,
        "isWhitelisted" => false,
        "reports" => [{ "comment" => "must not be retained" }],
      },
    }
    normalized = client.send(:normalize_check, payload)
    expect(normalized["abuseConfidenceScore"]).to eq(75)
    expect(normalized).not_to have_key("reports")
    expect(normalized.to_json).not_to include("must not be retained")
  end
end
