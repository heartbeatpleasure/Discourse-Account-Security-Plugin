# frozen_string_literal: true

require "rails_helper"

RSpec.describe AccountSecurity::AssessmentService do
  before do
    SiteSetting.account_security_enabled = true
    SiteSetting.account_security_ip_reputation_enabled = true
    allow(AccountSecurity::EventRecorder).to receive(:record!).and_return(nil)
  end

  it "preserves previously fetched provider context when a local blacklist match refreshes the risk" do
    now = Time.zone.now
    intelligence = AccountSecurity::IpIntelligence.create!(
      ip_address: "8.8.8.8",
      risk_level: "observed",
      evidence_strength: "moderate",
      primary_score: 20,
      total_reports: 7,
      distinct_reporters: 4,
      last_reported_at: 2.days.ago,
      usage_type: "Data Center/Web Hosting/Transit",
      isp: "Example ISP",
      domain: "example.net",
      country_code: "US",
      is_tor: false,
      local_blacklist_match: false,
      provider_checked_at: 2.hours.ago,
      next_check_after: 1.hour.ago,
      first_seen_at: 10.days.ago,
      last_seen_at: 2.hours.ago,
      source_summary: {
        "provider" => "abuseipdb",
        "is_whitelisted" => false,
        "schema_version" => 1,
      },
    )
    AccountSecurity::FeedEntry.create!(
      source: "abuseipdb_blacklist",
      ip_address: "8.8.8.8",
      score: 95,
      generation: "spec-#{now.to_i}",
    )

    result = described_class.call(
      ip: "8.8.8.8",
      trigger: "manual",
      allow_remote: false,
    )

    expect(result.success).to eq(true)
    expect(result.source).to eq("local_blacklist")
    intelligence.reload
    expect(intelligence.primary_score).to eq(95)
    expect(intelligence.local_blacklist_match).to eq(true)
    expect(intelligence.usage_type).to eq("Data Center/Web Hosting/Transit")
    expect(intelligence.isp).to eq("Example ISP")
    expect(intelligence.domain).to eq("example.net")
    expect(intelligence.country_code).to eq("US")
    expect(intelligence.total_reports).to eq(7)
    expect(intelligence.distinct_reporters).to eq(4)
    expect(intelligence.source_summary).to include(
      "provider" => "abuseipdb",
      "local_blacklist" => true,
    )
  end
end
