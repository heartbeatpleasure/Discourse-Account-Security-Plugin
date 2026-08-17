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
