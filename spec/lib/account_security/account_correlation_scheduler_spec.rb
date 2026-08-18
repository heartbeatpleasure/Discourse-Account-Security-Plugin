# frozen_string_literal: true

require "rails_helper"

RSpec.describe AccountSecurity::AccountCorrelationScheduler do
  fab!(:admin)

  before do
    SiteSetting.account_security_enabled = true
    SiteSetting.account_security_account_correlation_enabled = true
    SiteSetting.account_security_correlation_auto_scan_frequency = "monthly"
    SiteSetting.account_security_correlation_auto_scan_time = "03:00"
    SiteSetting.account_security_correlation_auto_scan_timezone = "America/New_York"
    SiteSetting.account_security_correlation_auto_scan_day_of_month = 1
    SiteSetting.account_security_correlation_auto_scan_weekday = "sunday"
    SiteSetting.site_contact_username = admin.username
    admin.user_option.update!(timezone: "Europe/Amsterdam")
    PluginStore.remove(AccountSecurity::STORE_NAMESPACE, described_class.last_slot_key)
  end

  after do
    PluginStore.remove(AccountSecurity::STORE_NAMESPACE, described_class.last_slot_key)
  end

  it "uses the site-contact Discourse timezone as the canonical wall clock for settings" do
    now = Time.utc(2026, 8, 17, 21, 0)

    expect(described_class.timezone).to eq("Europe/Amsterdam")
    expect(described_class.latest_slot(now)).to eq(Time.utc(2026, 8, 1, 1, 0))
    expect(described_class.next_slot(now)).to eq(Time.utc(2026, 9, 1, 1, 0))
  end

  it "uses the hidden legacy timezone only when no site-contact timezone is available" do
    SiteSetting.site_contact_username = ""

    expect(described_class.timezone).to eq("America/New_York")
  end

  it "uses timezone-aware calendar arithmetic across weekly quarterly and yearly cadences" do
    now = Time.utc(2026, 8, 17, 21, 0)

    SiteSetting.account_security_correlation_auto_scan_frequency = "weekly"
    expect(described_class.latest_slot(now)).to eq(Time.utc(2026, 8, 16, 1, 0))
    expect(described_class.next_slot(now)).to eq(Time.utc(2026, 8, 23, 1, 0))

    SiteSetting.account_security_correlation_auto_scan_frequency = "quarterly"
    expect(described_class.latest_slot(now)).to eq(Time.utc(2026, 7, 1, 1, 0))
    expect(described_class.next_slot(now)).to eq(Time.utc(2026, 10, 1, 1, 0))

    SiteSetting.account_security_correlation_auto_scan_frequency = "yearly"
    expect(described_class.latest_slot(now)).to eq(Time.utc(2026, 1, 1, 2, 0))
    expect(described_class.next_slot(now)).to eq(Time.utc(2027, 1, 1, 2, 0))
  end

  it "initializes a new schedule without launching an unexpected full scan immediately" do
    expect(AccountSecurity::AccountCorrelationScanner).not_to receive(:enqueue!)

    result = described_class.run_if_due!(now: Time.utc(2026, 8, 17, 21, 0))

    expect(result[:initialized]).to eq(true)
    expect(result[:enqueued]).to eq(false)
  end

  it "separates last-run slots when cadence time or the site schedule timezone changes" do
    first_key = described_class.last_slot_key
    described_class.store_last_slot(Time.utc(2026, 8, 1, 1, 0))

    SiteSetting.account_security_correlation_auto_scan_time = "04:00"
    time_key = described_class.last_slot_key
    expect(time_key).not_to eq(first_key)
    expect(described_class.last_slot).to be_nil

    admin.user_option.update!(timezone: "America/New_York")
    timezone_key = described_class.last_slot_key
    expect(timezone_key).not_to eq(time_key)
    expect(described_class.last_slot).to be_nil
  ensure
    [first_key, time_key, timezone_key].compact.each do |key|
      PluginStore.remove(AccountSecurity::STORE_NAMESPACE, key)
    end
  end
end

RSpec.describe AccountSecurity::AccountCorrelationScheduler, "health reporting" do
  fab!(:admin)

  before do
    SiteSetting.account_security_enabled = true
    SiteSetting.account_security_account_correlation_enabled = true
    SiteSetting.account_security_correlation_auto_scan_frequency = "monthly"
    SiteSetting.account_security_correlation_auto_scan_time = "03:00"
    SiteSetting.account_security_correlation_auto_scan_day_of_month = 1
    SiteSetting.site_contact_username = admin.username
    admin.user_option.update!(timezone: "UTC")
    PluginStore.remove(AccountSecurity::STORE_NAMESPACE, described_class.last_slot_key)
  end

  after do
    PluginStore.remove(AccountSecurity::STORE_NAMESPACE, described_class.last_slot_key)
  end

  it "reports an overdue automatic scan after the scheduler grace period" do
    now = Time.utc(2026, 8, 18, 12, 0)
    previous_slot = Time.utc(2026, 7, 1, 3, 0)
    described_class.store_last_slot(previous_slot)

    health = described_class.health_status(now: now)

    expect(health[:state]).to eq("degraded")
    expect(health[:reason]).to eq("correlation_schedule_overdue")
    expect(health[:overdue]).to eq(true)
  end
end
