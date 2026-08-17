# frozen_string_literal: true
require "rails_helper"

RSpec.describe AccountSecurity::RiskPolicy do
  it "maps provider scores to the documented risk bands" do
    expect(described_class.risk_level(24)).to eq("low")
    expect(described_class.risk_level(25)).to eq("observed")
    expect(described_class.risk_level(50)).to eq("elevated")
    expect(described_class.risk_level(75)).to eq("high")
    expect(described_class.risk_level(90)).to eq("critical")
  end

  it "does not turn Tor context into risk" do
    expect(described_class.risk_level(0)).to eq("low")
  end

  it "requires recent diverse reports for strong evidence unless the local high-confidence blacklist matches" do
    expect(described_class.evidence_strength(score: 90, last_reported_at: 1.day.ago, distinct_reporters: 3)).to eq("strong")
    expect(described_class.evidence_strength(score: 90, last_reported_at: 25.days.ago, distinct_reporters: 3)).to eq("weak")
    expect(described_class.evidence_strength(score: 80, last_reported_at: nil, distinct_reporters: 0, local_blacklist_match: true)).to eq("strong")
  end
end
