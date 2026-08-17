# frozen_string_literal: true

require "rails_helper"

RSpec.describe AccountSecurity::AccountCorrelationService do
  fab!(:user_a) { Fabricate(:user) }
  fab!(:user_b) { Fabricate(:user) }

  before do
    SiteSetting.account_security_enabled = true
    SiteSetting.account_security_account_correlation_enabled = true
    SiteSetting.account_security_correlation_min_score = 40
  end

  it "creates a review candidate for a shared public registration address without enforcing anything" do
    user_a.update_columns(registration_ip_address: "8.8.8.8", created_at: 10.minutes.ago)
    user_b.update_columns(registration_ip_address: "8.8.8.8", created_at: Time.zone.now)

    correlation = described_class.recalculate_pair!(user_a.id, user_b.id, source: "spec")

    expect(correlation).to be_present
    expect(correlation.status).to eq("open")
    expect(correlation.evidence["shared_registration_ip"]).to eq(true)
    expect(correlation.score).to be >= SiteSetting.account_security_correlation_min_score
    expect(user_a.reload.suspended?).to eq(false)
    expect(user_b.reload.suspended?).to eq(false)
  end

  it "does not use an explicitly trusted address as correlation evidence" do
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

    expect(correlation).to be_nil
    expect(AccountSecurity::AccountCorrelation.count).to eq(0)
  end

  it "combines repeated shared networks with a hashed session signature" do
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

    correlation = described_class.recalculate_pair!(user_a.id, user_b.id, source: "spec")

    expect(correlation).to be_present
    expect(correlation.evidence["shared_network_count"]).to eq(2)
    expect(correlation.evidence["shared_session_signature_count"]).to eq(2)
    expect(correlation.confidence).to eq("very_strong")
  end
end
