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
    normalized = client.send(:normalize_check, payload, expected_ip: "8.8.8.8")
    expect(normalized["abuseConfidenceScore"]).to eq(75)
    expect(normalized).not_to have_key("reports")
    expect(normalized.to_json).not_to include("must not be retained")
  end

  it "does not open the CHECK circuit when only the blacklist quota is exhausted" do
    allow(AccountSecurity::CircuitBreaker).to receive(:open_until!)

    client.send(:handle_failure_status, 429, { "retry-after" => "60" }, "blacklist")

    expect(AccountSecurity::CircuitBreaker).not_to have_received(:open_until!)
  end
  it "rejects a successful CHECK payload for a different IP" do
    payload = {
      "data" => {
        "ipAddress" => "1.1.1.1",
        "abuseConfidenceScore" => 10,
      },
    }

    expect {
      client.send(:normalize_check, payload, expected_ip: "8.8.8.8")
    }.to raise_error(JSON::ParserError, /mismatched check IP/)
  end

  it "rejects a successful report payload for a different IP" do
    payload = {
      "data" => {
        "ipAddress" => "1.1.1.1",
        "abuseConfidenceScore" => 10,
      },
    }

    expect {
      client.send(:normalize_report, payload, expected_ip: "8.8.8.8")
    }.to raise_error(JSON::ParserError, /mismatched report IP/)
  end

  it "rejects non-public CHECK input before creating an HTTP connection" do
    expect(Net::HTTP).not_to receive(:new)

    result = client.check("127.0.0.1")

    expect(result.success).to eq(false)
    expect(result.error_code).to eq(:invalid_ip)
  end

  it "bounds provider-controlled retry and rate-reset windows" do
    now = Time.at(1_700_000_000)
    far_future = now.to_i + 30.days.to_i

    expect(
      client.send(:bounded_reset_epoch, far_future.to_s, now: now),
    ).to be_nil
    expect(
      client.send(:bounded_reset_epoch, (now.to_i + 1.day.to_i).to_s, now: now),
    ).to eq(now.to_i + 1.day.to_i)
  end

end
