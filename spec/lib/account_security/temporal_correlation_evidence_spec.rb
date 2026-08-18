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
    expect(evidence["aligned_public_ip_transition_30d_count"]).to eq(1)
    expect(evidence["aligned_public_ip_transition_90d_count"]).to eq(1)
    expect(evidence["aligned_public_ip_transition_180d_count"]).to eq(1)
    expect(evidence["public_ip_transition_beyond_180d_count"]).to eq(0)
    expect(evidence["public_ip_transition_unaligned_count"]).to eq(1)
    expect(evidence["public_ip_transition_closest_gap_seconds"]).to eq(8.days.to_i)
    expect(evidence["public_ip_transition_details"]).to contain_exactly(
      include(
        "from_ip" => "8.8.8.8",
        "to_ip" => "1.1.1.1",
        "closest_transition_gap_seconds" => 8.days.to_i,
        "transition_population_complete" => false,
      ),
    )
  end

  it "keeps broader login-proximity horizons as positive investigation evidence without changing the score" do
    base = 12.days.ago.change(usec: 0)
    observations = [
      ["8.8.8.8", 45.minutes],
      ["1.1.1.1", 4.hours],
      ["9.9.9.9", 20.hours],
      ["208.67.222.222", 60.hours],
      ["8.8.4.4", 6.days],
    ]

    observations.each_with_index do |(ip, gap), index|
      time_a = base + index.days
      UserAuthTokenLog.create!(
        user_id: pattern_user_a.id,
        action: "generate",
        client_ip: ip,
        user_agent: "Browser A",
        created_at: time_a,
      )
      UserAuthTokenLog.create!(
        user_id: pattern_user_b.id,
        action: "generate",
        client_ip: ip,
        user_agent: "Browser B",
        created_at: time_a + gap,
      )
    end

    evidence = AccountSecurity::TemporalCorrelationEvidence.for_pair(
      pattern_user_a.id,
      pattern_user_b.id,
      shared_ips: observations.map(&:first),
    )

    expect(evidence["auth_proximity_closest_gap_seconds"]).to eq(45.minutes.to_i)
    expect(evidence["auth_proximity_within_5m_count"]).to eq(0)
    expect(evidence["auth_proximity_within_30m_count"]).to eq(0)
    expect(evidence["auth_proximity_within_1h_count"]).to eq(1)
    expect(evidence["auth_proximity_within_6h_count"]).to eq(2)
    expect(evidence["auth_proximity_within_24h_count"]).to eq(3)
    expect(evidence["auth_proximity_within_72h_count"]).to eq(4)
    expect(evidence["auth_proximity_within_7d_count"]).to eq(5)
    expect(evidence["auth_proximity_public_ip_within_24h_count"]).to eq(3)
    expect(evidence["auth_proximity_public_ip_within_7d_count"]).to eq(5)
    expect(evidence["auth_pattern_score_effect"]).to eq("none")
  end

  it "measures temporal exact-IP commonness in sliding 24-hour, 7-day and 30-day windows when population history is complete" do
    third_user = Fabricate(:user)
    fourth_user = Fabricate(:user)
    base = 20.days.ago.change(usec: 0)

    [
      [pattern_user_a, base],
      [pattern_user_b, base + 2.hours],
      [third_user, base + 3.hours],
      [fourth_user, base + 10.days],
    ].each do |user, created_at|
      user.update_columns(registration_ip_address: "8.8.8.8", created_at: created_at)
    end

    index = AccountSecurity::TemporalCorrelationEvidence.build_scan_index
    evidence = index.evidence_for_pair(
      pattern_user_a.id,
      pattern_user_b.id,
      shared_ips: ["8.8.8.8"],
    )
    detail = evidence.fetch("temporal_ip_details").first

    expect(evidence["temporal_ip_population_complete"]).to eq(true)
    expect(evidence["temporal_population_window_basis"]).to eq("closest_pair_midpoint")
    expect(detail["temporal_population_users_24h"]).to eq(3)
    expect(detail["temporal_population_users_7d"]).to eq(3)
    expect(detail["temporal_population_users_30d"]).to eq(4)
    expect(evidence["max_temporal_ip_users_24h"]).to eq(3)
    expect(evidence["max_temporal_ip_users_30d"]).to eq(4)
  end

  it "measures direct transition commonness separately from transition alignment when full auth history is complete" do
    third_user = Fabricate(:user)
    fourth_user = Fabricate(:user)
    base = 25.days.ago.change(usec: 0)

    [
      [pattern_user_a, base],
      [pattern_user_b, base + 2.hours],
      [third_user, base + 4.hours],
      [fourth_user, base + 20.days],
    ].each do |user, start_at|
      UserAuthTokenLog.create!(
        user_id: user.id,
        action: "generate",
        client_ip: "8.8.8.8",
        user_agent: "Mozilla/5.0",
        created_at: start_at,
      )
      UserAuthTokenLog.create!(
        user_id: user.id,
        action: "generate",
        client_ip: "1.1.1.1",
        user_agent: "Mozilla/5.0",
        created_at: start_at + 30.minutes,
      )
    end

    index = AccountSecurity::TemporalCorrelationEvidence.build_scan_index
    evidence = index.evidence_for_pair(pattern_user_a.id, pattern_user_b.id, shared_ips: [])
    detail = evidence.fetch("public_ip_transition_details").first

    expect(evidence["public_ip_transition_population_complete"]).to eq(true)
    expect(evidence["public_ip_transition_pattern_count"]).to eq(1)
    expect(evidence["public_ip_transition_closest_gap_seconds"]).to eq(2.hours.to_i)
    expect(evidence["aligned_public_ip_transition_6h_count"]).to eq(1)
    expect(detail["transition_user_count"]).to eq(4)
    expect(detail["transition_user_count_24h"]).to eq(3)
    expect(detail["transition_user_count_7d"]).to eq(3)
    expect(evidence["max_public_ip_transition_users"]).to eq(4)
    expect(evidence["max_public_ip_transition_users_24h"]).to eq(3)
  end

  it "marks full-scan population commonness incomplete when the global authentication safety cap truncates history" do
    stub_const("AccountSecurity::TemporalCorrelationEvidence::MAX_AUTH_ROWS", 2)
    base = 2.days.ago.change(usec: 0)

    3.times do |offset|
      UserAuthTokenLog.create!(
        user_id: pattern_user_a.id,
        action: "generate",
        client_ip: "8.8.8.8",
        created_at: base + offset.minutes,
      )
    end
    UserAuthTokenLog.create!(
      user_id: pattern_user_b.id,
      action: "generate",
      client_ip: "8.8.8.8",
      created_at: base + 10.minutes,
    )

    index = AccountSecurity::TemporalCorrelationEvidence.build_scan_index
    evidence = index.evidence_for_pair(
      pattern_user_a.id,
      pattern_user_b.id,
      shared_ips: ["8.8.8.8"],
    )

    expect(index.diagnostics[:temporal_auth_log_truncated]).to eq(true)
    expect(index.diagnostics[:temporal_ip_population_complete]).to eq(false)
    expect(index.diagnostics[:public_transition_population_complete]).to eq(false)
    expect(evidence["temporal_ip_population_complete"]).to eq(false)
    expect(evidence["public_ip_transition_population_complete"]).to eq(false)
    expect(evidence["max_temporal_ip_users_24h"]).to be_nil
  end

  it "does not present pair-only transition population as complete commonness" do
    base = 3.days.ago.change(usec: 0)
    [pattern_user_a, pattern_user_b].each_with_index do |user, index|
      start_at = base + index.hours
      UserAuthTokenLog.create!(user_id: user.id, action: "generate", client_ip: "8.8.8.8", created_at: start_at)
      UserAuthTokenLog.create!(user_id: user.id, action: "generate", client_ip: "1.1.1.1", created_at: start_at + 10.minutes)
    end

    evidence = AccountSecurity::TemporalCorrelationEvidence.for_pair(
      pattern_user_a.id,
      pattern_user_b.id,
      shared_ips: [],
    )
    detail = evidence.fetch("public_ip_transition_details").first

    expect(evidence["public_ip_transition_population_complete"]).to eq(false)
    expect(detail["transition_population_complete"]).to eq(false)
    expect(detail).not_to have_key("transition_user_count")
    expect(detail).not_to have_key("transition_user_count_24h")
  end

end
