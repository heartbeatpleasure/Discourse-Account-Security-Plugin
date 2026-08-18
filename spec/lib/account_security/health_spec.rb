# frozen_string_literal: true

require "rails_helper"

RSpec.describe AccountSecurity::Health do
  FeedState = Struct.new(:fetched_at, :status)

  before do
    SiteSetting.account_security_enabled = true
    SiteSetting.account_security_ip_reputation_enabled = true
    SiteSetting.account_security_abuseipdb_api_key = "test-key"
    SiteSetting.account_security_tor_feed_enabled = true
    SiteSetting.account_security_blacklist_sync_enabled = true
    SiteSetting.account_security_staff_notifications_enabled = false
    SiteSetting.account_security_account_correlation_enabled = false
  end

  it "explains a degraded state when the blacklist has never synchronized" do
    tor = FeedState.new(Time.zone.now, "healthy")

    status, reason = described_class.overall_state(nil, tor, nil, { state: "closed" })

    expect(status).to eq("degraded")
    expect(reason).to eq("abuseipdb_blacklist_never_synced")
  end

  it "reports missing notification groups when staff notifications are enabled" do
    SiteSetting.account_security_staff_notifications_enabled = true
    SiteSetting.account_security_notification_groups = ""
    tor = FeedState.new(Time.zone.now, "healthy")
    blacklist = FeedState.new(Time.zone.now, "healthy")

    status, reason = described_class.overall_state(nil, tor, blacklist, { state: "closed" })

    expect(status).to eq("degraded")
    expect(reason).to eq("notification_groups_missing")
  end
end

RSpec.describe AccountSecurity::Health, "account-correlation operations" do
  before do
    SiteSetting.account_security_enabled = true
    SiteSetting.account_security_ip_reputation_enabled = false
    SiteSetting.account_security_account_correlation_enabled = true
  end

  it "surfaces a failed correlation scan even while external IP reputation is disabled" do
    allow(AccountSecurity::AccountCorrelationScanner).to receive(:status).and_return(
      state: "failed",
      error_code: "scan_failed",
      completed_at: Time.zone.now.iso8601,
    )
    allow(AccountSecurity::AccountCorrelationScheduler).to receive(:health_status).and_return(
      enabled: true,
      state: "healthy",
      reason: nil,
    )

    payload = described_class.payload

    expect(payload[:overall]).to eq("degraded")
    expect(payload[:overall_reason]).to eq("correlation_scan_failed")
    expect(payload.dig(:correlation, :scan, :state)).to eq("failed")
  end
end
