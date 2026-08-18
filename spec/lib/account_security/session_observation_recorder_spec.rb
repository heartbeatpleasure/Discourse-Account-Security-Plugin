# frozen_string_literal: true

require "rails_helper"

RSpec.describe AccountSecurity::SessionObservationRecorder do
  fab!(:user_a) { Fabricate(:user) }
  fab!(:user_b) { Fabricate(:user) }

  before do
    SiteSetting.account_security_enabled = true
    SiteSetting.account_security_account_correlation_enabled = true
    SiteSetting.account_security_session_observation_enabled = true
    SiteSetting.account_security_browser_continuity_enabled = true

    allow(AccountSecurity::AccountCorrelationService).to receive(:existing_other_user_ids).and_return([])
    allow(AccountSecurity::CoreIpEvidence).to receive(:candidate_user_ids_for_ip).and_return([])
  end

  it "records at low frequency but keeps an immediate same-browser account switch" do
    token_hash = "a" * 64
    started = Time.zone.now.change(usec: 0)

    first = described_class.record!(
      user_id: user_a.id,
      ip: "8.8.8.8",
      browser_token_hash: token_hash,
      observed_at: started,
    )
    duplicate = described_class.record!(
      user_id: user_a.id,
      ip: "8.8.8.8",
      browser_token_hash: token_hash,
      observed_at: started + 1.hour,
    )
    switched = described_class.record!(
      user_id: user_b.id,
      ip: "8.8.8.8",
      browser_token_hash: token_hash,
      observed_at: started + 2.hours,
    )

    expect(first).to be_present
    expect(duplicate).to be_nil
    expect(switched).to be_present
    expect(AccountSecurity::SessionObservation.where(browser_token_hash: token_hash).count).to eq(2)

    summary = AccountSecurity::BrowserContinuityRecorder.shared_summary(user_a.id, user_b.id)
    expect(summary[:account_switch_count]).to eq(1)
    expect(summary[:account_switch_closest_gap_seconds]).to eq(2.hours.to_i)
    expect(summary[:account_switch_within_6h_count]).to eq(1)
  end

  it "never infers negative browser evidence when accounts use different browser tokens" do
    started = Time.zone.now.change(usec: 0)
    described_class.record!(
      user_id: user_a.id,
      ip: "8.8.8.8",
      browser_token_hash: "b" * 64,
      observed_at: started,
    )
    described_class.record!(
      user_id: user_b.id,
      ip: "8.8.8.8",
      browser_token_hash: "c" * 64,
      observed_at: started + 2.hours,
    )

    summary = AccountSecurity::BrowserContinuityRecorder.shared_summary(user_a.id, user_b.id)
    expect(summary[:count]).to eq(0)
    expect(summary[:account_switch_count]).to eq(0)

    with_different_browsers = {
      "shared_exact_ip_count" => 1,
      "shared_public_ip_count" => 1,
      "untrusted_public_ip_count" => 1,
      "exact_ip_population_complete" => true,
      "shared_ip_details" => [
        {
          "ip_address" => "8.8.8.8",
          "public" => true,
          "trusted" => false,
          "user_count" => 2,
          "sources_a" => ["session_observation"],
          "sources_b" => ["session_observation"],
        },
      ],
      "browser_continuity_count" => 0,
    }
    expect(AccountSecurity::AccountCorrelationPolicy.score(with_different_browsers)).to eq(
      AccountSecurity::AccountCorrelationPolicy.score(with_different_browsers.except("browser_continuity_count")),
    )
  end
end
