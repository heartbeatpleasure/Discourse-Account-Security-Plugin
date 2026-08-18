# frozen_string_literal: true

require "rails_helper"

RSpec.describe AccountSecurity::AccountCorrelationService do
  fab!(:user_a) { Fabricate(:user) }
  fab!(:user_b) { Fabricate(:user) }

  before do
    SiteSetting.account_security_enabled = true
    SiteSetting.account_security_account_correlation_enabled = true
    SiteSetting.account_security_browser_continuity_enabled = true
    SiteSetting.account_security_correlation_min_score = 40
  end

  it "creates a review candidate for a shared public registration address without enforcing anything" do
    user_a.update_columns(registration_ip_address: "8.8.8.8", created_at: 10.minutes.ago)
    user_b.update_columns(registration_ip_address: "8.8.8.8", created_at: Time.zone.now)

    correlation = described_class.recalculate_pair!(user_a.id, user_b.id, source: "spec")

    expect(correlation).to be_present
    expect(correlation.status).to eq("open")
    expect(correlation.evidence["shared_registration_ip"]).to eq(true)
    expect(correlation.evidence["shared_exact_ip_count"]).to be >= 1
    expect(user_a.reload.suspended?).to eq(false)
    expect(user_b.reload.suspended?).to eq(false)
  end

  it "keeps an exact trusted-network match visible but lowers its identity score" do
    user_a.update_columns(registration_ip_address: "8.8.8.8", created_at: 10.minutes.ago)
    user_b.update_columns(registration_ip_address: "8.8.8.8", created_at: Time.zone.now)
    AccountSecurity::TrustedNetwork.create!(
      network: "8.8.8.8/32",
      label: "Known shared network",
      reason: "Expected shared access",
      scope: "bypass_lookup_and_enforcement",
      created_by: Fabricate(:admin),
    )

    correlation = described_class.recalculate_pair!(user_a.id, user_b.id, source: "spec")

    expect(correlation).to be_present
    expect(correlation.evidence["trusted_shared_ip_count"]).to eq(1)
    expect(correlation.score).to be < SiteSetting.account_security_correlation_min_score
  end

  it "keeps exact private registration-IP overlap visible without treating private addresses as identity weight" do
    user_a.update_columns(registration_ip_address: "10.0.0.50", ip_address: "10.0.0.50", created_at: 1.hour.ago)
    user_b.update_columns(registration_ip_address: "10.0.0.50", ip_address: "10.0.0.50", created_at: Time.zone.now)

    correlation = described_class.recalculate_pair!(user_a.id, user_b.id, source: "spec")

    expect(correlation).to be_present
    expect(correlation.evidence["shared_registration_ip_nonpublic"]).to eq(true)
    expect(correlation.evidence["same_current_ip_nonpublic"]).to eq(true)
    expect(correlation.score).to eq(0)
    expect(correlation.confidence).to eq("weak")
  end

  it "combines repeated shared networks with a hashed client signature without double-counting the same client" do
    now = Time.zone.now
    %w[8.8.8.8/32 1.1.1.1/32].each do |network|
      [user_a, user_b].each do |user|
        AccountSecurity::UserNetwork.create!(
          user_id: user.id,
          network_key: network,
          address_family: "ipv4",
          first_seen_at: now,
          last_seen_at: now,
          successful_login_count: 1,
        )
        AccountSecurity::SessionSignature.create!(
          user_id: user.id,
          network_key: network,
          signature_hash: "a" * 64,
          first_seen_at: now,
          last_seen_at: now,
          observation_count: 1,
        )
      end
    end

    evidence = described_class.build_evidence(user_a, user_b)

    expect(evidence["shared_network_count"]).to eq(2)
    expect(evidence["shared_session_signature_count"]).to eq(2)
    expect(evidence["shared_session_client_signature_count"]).to eq(1)
    expect(evidence["client_signature_group_count"]).to eq(1)
    expect(evidence["client_signature_evidence_source_count"]).to eq(1)
    expect(evidence["max_shared_session_client_signature_users"]).to eq(2)
    expect(evidence["max_client_signature_group_users"]).to eq(2)
    expect(evidence["session_client_signature_population_complete"]).to eq(true)
    expect(evidence["client_signature_population_complete"]).to eq(true)
  end
  it "stores aggregate temporal evidence without copying source timestamps into correlation evidence" do
    base = 1.day.ago.change(usec: 0)
    user_a.update_columns(registration_ip_address: "8.8.4.4", created_at: base)
    user_b.update_columns(registration_ip_address: "8.8.4.4", created_at: base + 20.minutes)

    correlation = described_class.recalculate_pair!(user_a.id, user_b.id, source: "spec")

    expect(correlation).to be_present
    expect(correlation.evidence["temporal_evidence_version"]).to eq(
      AccountSecurity::TemporalCorrelationEvidence::EVIDENCE_VERSION,
    )
    expect(correlation.evidence["closest_shared_ip_gap_seconds"]).to eq(20.minutes.to_i)
    serialized = correlation.evidence.to_json
    expect(serialized).not_to include("closest_a_at")
    expect(serialized).not_to include("closest_b_at")
  end

  it "prioritizes realtime candidates deterministically before applying the safety limit" do
    session_signature = Struct.new(:network_key, :signature_hash).new("8.8.8.0/24", "a" * 64)

    allow(described_class).to receive(:existing_other_user_ids).with(user_a.id).and_return([90, 40])
    allow(AccountSecurity::CoreIpEvidence).to receive(:candidate_user_ids_for_ip).and_return([70, 30])
    allow(described_class).to receive(:small_group_user_ids).and_return([60, 20], [50, 10])

    ids = described_class.candidate_user_ids_for_observation(
      user_id: user_a.id,
      normalized_ip: "8.8.8.8",
      network: "8.8.8.0/24",
      session_signature: session_signature,
    )

    expect(ids).to eq([40, 90, 30, 70, 20, 60, 10, 50])
  end

  it "reports when an existing pair is retained only for investigation after falling below the current storage threshold" do
    now = Time.zone.now
    [user_a, user_b].each do |user|
      AccountSecurity::UserNetwork.create!(
        user_id: user.id,
        network_key: "8.8.8.0/24",
        address_family: "ipv4",
        first_seen_at: now,
        last_seen_at: now,
        successful_login_count: 1,
      )
    end
    AccountSecurity::AccountCorrelation.create!(
      user_a_id: [user_a.id, user_b.id].min,
      user_b_id: [user_a.id, user_b.id].max,
      score: 50,
      confidence: "strong",
      status: "open",
      evidence: {},
      first_seen_at: now,
      last_seen_at: now,
    )

    result = described_class.recalculate_pair_with_result!(user_a.id, user_b.id, source: "spec")

    expect(result.outcome).to eq("retained_below_threshold")
    expect(result.candidate_now).to eq(false)
    expect(result.correlation).to be_present
    expect(result.correlation.evidence["shared_network_count"]).to eq(1)
  end

  it "keeps the v2 shared-network fields while exposing a deduplicated network signal for scoring v3" do
    exact_details = [
      {
        "ip_address" => "8.8.8.8",
        "public" => true,
        "trusted" => false,
        "user_count" => 2,
        "sources_a" => ["registration"],
        "sources_b" => ["registration"],
      },
    ]
    supplemental = {
      "shared_networks" => ["8.8.8.8/32"],
      "shared_network_user_counts" => { "8.8.8.8/32" => 2 },
      "max_shared_network_users" => 2,
      "temporal_evidence" => AccountSecurity::TemporalCorrelationEvidence.empty_evidence,
    }

    evidence = described_class.build_evidence(
      user_a,
      user_b,
      precomputed_ip_details: exact_details,
      precomputed_supplemental: supplemental,
    )

    expect(evidence["shared_network_count"]).to eq(1)
    expect(evidence["shared_networks"]).to eq(["8.8.8.8/32"])
    expect(evidence["shared_independent_network_count"]).to eq(0)
    expect(evidence["shared_exact_ip_network_overlap_count"]).to eq(1)
    expect(evidence["shared_independent_networks"]).to eq([])
    expect(evidence["max_independent_shared_network_users"]).to eq(0)
    expect(evidence).not_to have_key("shared_network_user_counts")
  end

  it "preserves the new evidence-completion fields from a precomputed full scan" do
    temporal = AccountSecurity::TemporalCorrelationEvidence.empty_evidence.merge(
      "temporal_ip_population_complete" => true,
      "temporal_within_6h_count" => 2,
      "temporal_within_72h_count" => 3,
      "temporal_within_7d_count" => 4,
      "max_temporal_ip_users_24h" => 3,
      "auth_proximity_closest_gap_seconds" => 1.hour.to_i,
      "auth_proximity_within_6h_count" => 2,
      "auth_proximity_within_7d_count" => 5,
      "public_ip_transition_closest_gap_seconds" => 2.days.to_i,
      "aligned_public_ip_transition_30d_count" => 1,
      "public_ip_transition_population_complete" => true,
      "max_public_ip_transition_users" => 2,
    )

    evidence = described_class.build_evidence(
      user_a,
      user_b,
      precomputed_ip_details: [],
      precomputed_supplemental: {
        "shared_networks" => [],
        "shared_session_signature_count" => 2,
        "shared_session_client_signature_count" => 2,
        "repeated_shared_session_signature_count" => 1,
        "repeated_shared_session_client_signature_count" => 1,
        "max_shared_session_client_signature_users" => 2,
        "session_client_signature_population_complete" => true,
        "shared_session_signature_paired_observations" => 4,
        "temporal_evidence" => temporal.merge(
          "shared_auth_client_signature_count" => 3,
          "repeated_shared_auth_client_signature_count" => 2,
          "shared_auth_client_signature_paired_observations" => 6,
          "max_shared_auth_client_signature_users" => 3,
          "auth_client_signature_population_complete" => true,
        ),
      },
    )

    expect(evidence["client_signature_group_count"]).to eq(3)
    expect(evidence["repeated_client_signature_group_count"]).to eq(2)
    expect(evidence["client_signature_evidence_source_count"]).to eq(2)
    expect(evidence["max_client_signature_group_users"]).to eq(3)
    expect(evidence["client_signature_population_complete"]).to eq(true)
    expect(evidence["client_signature_group_paired_observations"]).to eq(6)
    expect(evidence["temporal_score_effect"]).to eq("weighted_v3")
    expect(evidence["auth_pattern_score_effect"]).to eq("weighted_v3")
    expect(evidence["temporal_ip_population_complete"]).to eq(true)
    expect(evidence["temporal_within_6h_count"]).to eq(2)
    expect(evidence["temporal_within_72h_count"]).to eq(3)
    expect(evidence["max_temporal_ip_users_24h"]).to eq(3)
    expect(evidence["auth_proximity_closest_gap_seconds"]).to eq(1.hour.to_i)
    expect(evidence["auth_proximity_within_7d_count"]).to eq(5)
    expect(evidence["aligned_public_ip_transition_30d_count"]).to eq(1)
    expect(evidence["max_public_ip_transition_users"]).to eq(2)
  end

end
