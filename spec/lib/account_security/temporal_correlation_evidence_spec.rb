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

RSpec.describe "authentication pattern evidence" do
  fab!(:pattern_user_a) { Fabricate(:user) }
  fab!(:pattern_user_b) { Fabricate(:user) }

  it "finds repeated close logins, matching client signatures and aligned public-IP transitions without copying user agents" do
    base = 5.days.ago.change(usec: 0)
    user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/151.0.0.0 Safari/537.36"

    [
      ["8.8.8.8", base, base + 2.minutes],
      ["1.1.1.1", base + 1.day, base + 1.day + 10.minutes],
    ].each do |ip, time_a, time_b|
      UserAuthTokenLog.create!(
        user_id: pattern_user_a.id,
        action: "generate",
        client_ip: ip,
        user_agent: user_agent,
        created_at: time_a,
      )
      UserAuthTokenLog.create!(
        user_id: pattern_user_b.id,
        action: "generate",
        client_ip: ip,
        user_agent: user_agent,
        created_at: time_b,
      )
    end

    evidence = AccountSecurity::TemporalCorrelationEvidence.for_pair(
      pattern_user_a.id,
      pattern_user_b.id,
      shared_ips: ["8.8.8.8", "1.1.1.1"],
    )

    expect(evidence["auth_pattern_evidence_version"]).to eq(AccountSecurity::TemporalCorrelationEvidence::AUTH_PATTERN_EVIDENCE_VERSION)
    expect(evidence["auth_proximity_within_5m_count"]).to eq(1)
    expect(evidence["auth_proximity_within_30m_count"]).to eq(2)
    expect(evidence["auth_proximity_same_client_within_30m_count"]).to eq(2)
    expect(evidence["auth_proximity_public_ip_count"]).to eq(2)
    expect(evidence["shared_auth_client_signature_count"]).to eq(1)
    expect(evidence["repeated_shared_auth_client_signature_count"]).to eq(1)
    expect(evidence["aligned_public_ip_transition_24h_count"]).to eq(1)
    expect(evidence["aligned_public_ip_transition_7d_count"]).to eq(1)
    expect(evidence["auth_pattern_score_effect"]).to eq("none")
    expect(evidence.to_json).not_to include(user_agent)
  end

  it "contextualizes an exact client signature with its scanned-account population when the full auth history fits the safety cap" do
    third_user = Fabricate(:user)
    base = 2.days.ago.change(usec: 0)
    user_agent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/151.0.0.0 Safari/537.36"

    [pattern_user_a, pattern_user_b, third_user].each_with_index do |user, index|
      UserAuthTokenLog.create!(
        user_id: user.id,
        action: "generate",
        client_ip: index == 2 ? "9.9.9.9" : "8.8.8.8",
        user_agent: user_agent,
        created_at: base + index.minutes,
      )
    end

    index = AccountSecurity::TemporalCorrelationEvidence.build_scan_index
    evidence = index.evidence_for_pair(
      pattern_user_a.id,
      pattern_user_b.id,
      shared_ips: ["8.8.8.8"],
    )

    expect(evidence["shared_auth_client_signature_count"]).to eq(1)
    expect(evidence["max_shared_auth_client_signature_users"]).to eq(3)
    expect(evidence["auth_client_signature_population_complete"]).to eq(true)
    expect(evidence.to_json).not_to include(user_agent)
  end

  it "marks pair authentication evidence incomplete when the bounded per-user history is truncated" do
    stub_const("AccountSecurity::TemporalCorrelationEvidence::MAX_PAIR_AUTH_ROWS_PER_USER", 2)
    base = 1.day.ago.change(usec: 0)

    3.times do |offset|
      UserAuthTokenLog.create!(
        user_id: pattern_user_a.id,
        action: "generate",
        client_ip: "8.8.8.8",
        user_agent: "Browser A",
        created_at: base + offset.minutes,
      )
    end
    UserAuthTokenLog.create!(
      user_id: pattern_user_b.id,
      action: "generate",
      client_ip: "8.8.8.8",
      user_agent: "Browser B",
      created_at: base + 1.minute,
    )

    evidence = AccountSecurity::TemporalCorrelationEvidence.for_pair(
      pattern_user_a.id,
      pattern_user_b.id,
      shared_ips: ["8.8.8.8"],
    )

    expect(evidence["temporal_auth_history_complete"]).to eq(false)
    expect(evidence["auth_pattern_history_complete"]).to eq(false)
    expect(evidence["auth_pattern_score_effect"]).to eq("none")
  end

  it "separates a matching transition pattern from a transition aligned in time" do
    base = 20.days.ago.change(usec: 0)
    user_agent = "Mozilla/5.0"

    [
      [pattern_user_a, base],
      [pattern_user_b, base + 8.days],
    ].each do |user, start_at|
      UserAuthTokenLog.create!(
        user_id: user.id,
        action: "generate",
        client_ip: "8.8.8.8",
        user_agent: user_agent,
        created_at: start_at,
      )
      UserAuthTokenLog.create!(
        user_id: user.id,
        action: "generate",
        client_ip: "1.1.1.1",
        user_agent: user_agent,
        created_at: start_at + 1.hour,
      )
    end

    evidence = AccountSecurity::TemporalCorrelationEvidence.for_pair(
      pattern_user_a.id,
      pattern_user_b.id,
      shared_ips: [],
    )

    expect(evidence["public_ip_transition_pattern_count"]).to eq(1)
    expect(evidence["public_ip_transition_match_count"]).to eq(1)
    expect(evidence["aligned_public_ip_transition_24h_count"]).to eq(0)
    expect(evidence["aligned_public_ip_transition_7d_count"]).to eq(0)
    expect(evidence["public_ip_transition_unaligned_count"]).to eq(1)
    expect(evidence["public_ip_transition_details"]).to be_empty
  end

end
