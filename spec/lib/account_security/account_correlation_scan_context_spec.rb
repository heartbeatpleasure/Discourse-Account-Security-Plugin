# frozen_string_literal: true

require "rails_helper"

RSpec.describe AccountSecurity::AccountCorrelationScanContext do
  fab!(:user_a) { Fabricate(:user) }
  fab!(:user_b) { Fabricate(:user) }

  before do
    SiteSetting.account_security_enabled = true
    SiteSetting.account_security_account_correlation_enabled = true
    SiteSetting.account_security_browser_continuity_enabled = true
  end

  it "preloads supplemental network, session and browser evidence without making browser continuity a pair generator" do
    now = Time.zone.now
    [user_a, user_b].each do |user|
      AccountSecurity::UserNetwork.create!(
        user_id: user.id,
        network_key: "8.8.8.8/32",
        address_family: "ipv4",
        first_seen_at: now,
        last_seen_at: now,
        successful_login_count: 1,
      )
      AccountSecurity::SessionSignature.create!(
        user_id: user.id,
        network_key: "8.8.8.8/32",
        signature_hash: "d" * 64,
        first_seen_at: now - 2.days,
        last_seen_at: now,
        observation_count: 3,
      )
      AccountSecurity::BrowserContinuity.create!(
        user_id: user.id,
        token_hash: "e" * 64,
        first_seen_at: now - 3.days,
        last_seen_at: now,
        observation_count: 2,
      )
    end

    context = described_class.new
    pairs = Set.new
    context.add_candidate_pairs!(pairs, max_group_users: 20, max_pairs: 20_000)
    evidence = context.evidence_for_pair(user_a.id, user_b.id)

    expect(pairs).to include([user_a.id, user_b.id].sort)
    expect(evidence["shared_networks"]).to include("8.8.8.8/32")
    expect(evidence["shared_session_signature_count"]).to eq(1)
    expect(evidence["shared_session_client_signature_count"]).to eq(1)
    expect(evidence["repeated_shared_session_signature_count"]).to eq(1)
    expect(evidence["repeated_shared_session_client_signature_count"]).to eq(1)
    expect(evidence["max_shared_session_client_signature_users"]).to eq(2)
    expect(evidence["session_client_signature_population_complete"]).to eq(true)
    expect(evidence["shared_session_signature_paired_observations"]).to eq(3)
    expect(evidence["browser_continuity_count"]).to eq(1)
    expect(evidence["repeated_browser_continuity_count"]).to eq(1)
    expect(evidence["browser_continuity_paired_observations"]).to eq(2)
  end
  it "deduplicates the same client signature across shared networks for the v3-ready summary" do
    now = Time.zone.now
    %w[8.8.8.8/32 1.1.1.1/32].each do |network|
      [user_a, user_b].each do |user|
        AccountSecurity::SessionSignature.create!(
          user_id: user.id,
          network_key: network,
          signature_hash: "f" * 64,
          first_seen_at: now - 1.day,
          last_seen_at: now,
          observation_count: 2,
        )
      end
    end

    evidence = described_class.new.evidence_for_pair(user_a.id, user_b.id)

    expect(evidence["shared_session_signature_count"]).to eq(2)
    expect(evidence["shared_session_client_signature_count"]).to eq(1)
    expect(evidence["repeated_shared_session_signature_count"]).to eq(2)
    expect(evidence["repeated_shared_session_client_signature_count"]).to eq(1)
    expect(evidence["max_shared_session_client_signature_users"]).to eq(2)
    expect(evidence["session_client_signature_population_complete"]).to eq(true)
  end

end
