# frozen_string_literal: true

require "rails_helper"

RSpec.describe AccountSecurity::TemporalCorrelationEvidence do
  fab!(:user_a) { Fabricate(:user) }
  fab!(:user_b) { Fabricate(:user) }

  it "measures how close shared-IP observations occurred without persisting copied source timestamps" do
    base = 2.days.ago.change(usec: 0)
    user_a.update_columns(registration_ip_address: "8.8.8.8", created_at: base)
    user_b.update_columns(registration_ip_address: "8.8.8.8", created_at: base + 10.minutes)

    evidence = described_class.for_pair(user_a.id, user_b.id, shared_ips: ["8.8.8.8"])
    detail = evidence.fetch("temporal_ip_details").first

    expect(evidence["temporal_evidence_version"]).to eq(described_class::EVIDENCE_VERSION)
    expect(evidence["timed_shared_ip_count"]).to eq(1)
    expect(evidence["temporal_within_15m_count"]).to eq(1)
    expect(evidence["temporal_within_1h_count"]).to eq(1)
    expect(evidence["closest_shared_ip_gap_seconds"]).to eq(10.minutes.to_i)
    expect(detail["closest_gap_seconds"]).to eq(10.minutes.to_i)
    expect(detail.keys).not_to include("closest_a_at", "closest_b_at", "first_a_at", "last_a_at")
  end

  it "recognizes repeated temporal alignment across distinct public IP addresses" do
    base = 3.days.ago.change(usec: 0)
    [
      ["1.1.1.1", base, base + 15.minutes],
      ["8.8.8.8", base + 1.day, base + 1.day + 30.minutes],
    ].each do |ip, time_a, time_b|
      UserAuthTokenLog.create!(user_id: user_a.id, action: "generate", client_ip: ip, created_at: time_a)
      UserAuthTokenLog.create!(user_id: user_b.id, action: "generate", client_ip: ip, created_at: time_b)
    end

    evidence = described_class.for_pair(
      user_a.id,
      user_b.id,
      shared_ips: ["1.1.1.1", "8.8.8.8"],
    )

    expect(evidence["timed_shared_ip_count"]).to eq(2)
    expect(evidence["temporal_within_1h_count"]).to eq(2)
    expect(evidence["temporal_public_within_24h_count"]).to eq(2)
    expect(evidence["temporal_repeated_public_alignment"]).to eq(true)
  end
end
