# frozen_string_literal: true

require "rails_helper"

RSpec.describe AccountSecurity::AccountCorrelationScheduler do
  before do
    SiteSetting.account_security_enabled = true
    SiteSetting.account_security_account_correlation_enabled = true
    SiteSetting.account_security_correlation_auto_scan_frequency = "monthly"
    SiteSetting.account_security_correlation_auto_scan_time = "03:00"
    SiteSetting.account_security_correlation_auto_scan_day_of_month = 1
    SiteSetting.account_security_correlation_auto_scan_weekday = "sunday"
    PluginStore.remove(AccountSecurity::STORE_NAMESPACE, described_class.last_slot_key)
  end

  after do
    PluginStore.remove(AccountSecurity::STORE_NAMESPACE, described_class.last_slot_key)
  end

  it "uses monthly automatic scans by default and exposes the next UTC slot" do
    now = Time.utc(2026, 8, 17, 21, 0)

    expect(described_class.frequency).to eq("monthly")
    expect(described_class.latest_slot(now)).to eq(Time.utc(2026, 8, 1, 3, 0))
    expect(described_class.next_slot(now)).to eq(Time.utc(2026, 9, 1, 3, 0))
  end

  it "supports weekly, quarterly and yearly schedules without invalid month arithmetic" do
    now = Time.utc(2026, 8, 17, 21, 0)

    SiteSetting.account_security_correlation_auto_scan_frequency = "weekly"
    expect(described_class.next_slot(now)).to be > now

    SiteSetting.account_security_correlation_auto_scan_frequency = "quarterly"
    expect(described_class.latest_slot(now).month).to eq(7)
    expect(described_class.next_slot(now).month).to eq(10)

    SiteSetting.account_security_correlation_auto_scan_frequency = "yearly"
    expect(described_class.latest_slot(now)).to eq(Time.utc(2026, 1, 1, 3, 0))
    expect(described_class.next_slot(now)).to eq(Time.utc(2027, 1, 1, 3, 0))
  end

  it "initializes the schedule without launching an unexpected full scan immediately" do
    expect(AccountSecurity::AccountCorrelationScanner).not_to receive(:enqueue!)

    result = described_class.run_if_due!(now: Time.utc(2026, 8, 17, 21, 0))

    expect(result[:initialized]).to eq(true)
    expect(result[:enqueued]).to eq(false)
  end
  it "keeps last-run slots separate when the cadence changes" do
    SiteSetting.account_security_correlation_auto_scan_frequency = "monthly"
    monthly_key = described_class.last_slot_key
    described_class.store_last_slot(Time.utc(2026, 8, 1, 3, 0))

    SiteSetting.account_security_correlation_auto_scan_frequency = "weekly"
    weekly_key = described_class.last_slot_key

    expect(weekly_key).not_to eq(monthly_key)
    expect(described_class.last_slot).to be_nil
  ensure
    PluginStore.remove(AccountSecurity::STORE_NAMESPACE, monthly_key) if defined?(monthly_key) && monthly_key
    PluginStore.remove(AccountSecurity::STORE_NAMESPACE, weekly_key) if defined?(weekly_key) && weekly_key
  end

end
