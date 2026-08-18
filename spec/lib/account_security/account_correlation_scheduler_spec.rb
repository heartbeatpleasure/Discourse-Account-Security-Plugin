# frozen_string_literal: true

require "rails_helper"

RSpec.describe AccountSecurity::AccountCorrelationScheduler do
  fab!(:admin)

  before do
    SiteSetting.account_security_enabled = true
    SiteSetting.account_security_account_correlation_enabled = true
    SiteSetting.account_security_correlation_auto_scan_frequency = "monthly"
    SiteSetting.account_security_correlation_auto_scan_time = "03:00"
    SiteSetting.account_security_correlation_auto_scan_timezone = "Europe/Amsterdam"
    SiteSetting.account_security_correlation_auto_scan_day_of_month = 1
    SiteSetting.account_security_correlation_auto_scan_weekday = "sunday"
    PluginStore.remove(AccountSecurity::STORE_NAMESPACE, described_class.last_slot_key)
  end

  after do
    PluginStore.remove(AccountSecurity::STORE_NAMESPACE, described_class.last_slot_key)
  end

  it "interprets the configured clock time in the saved schedule timezone" do
    now = Time.utc(2026, 8, 17, 21, 0)

    expect(described_class.frequency).to eq("monthly")
    expect(described_class.latest_slot(now)).to eq(Time.utc(2026, 8, 1, 1, 0))
    expect(described_class.next_slot(now)).to eq(Time.utc(2026, 9, 1, 1, 0))
    expect(described_class.schedule_status(now: now)[:timezone]).to eq("Europe/Amsterdam")
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

  it "separates last-run slots when cadence time or timezone changes" do
    first_key = described_class.last_slot_key
    described_class.store_last_slot(Time.utc(2026, 8, 1, 1, 0))

    SiteSetting.account_security_correlation_auto_scan_time = "04:00"
    time_key = described_class.last_slot_key
    expect(time_key).not_to eq(first_key)
    expect(described_class.last_slot).to be_nil

    SiteSetting.account_security_correlation_auto_scan_timezone = "America/New_York"
    timezone_key = described_class.last_slot_key
    expect(timezone_key).not_to eq(time_key)
    expect(described_class.last_slot).to be_nil
  ensure
    [first_key, time_key, timezone_key].compact.each do |key|
      PluginStore.remove(AccountSecurity::STORE_NAMESPACE, key)
    end
  end

  it "persists a schedule together with the timezone of the administrator who saved it" do
    status = described_class.update!(
      frequency: "weekly",
      send_time: "11:30",
      weekday: "monday",
      day_of_month: 7,
      timezone: "Europe/Amsterdam",
      actor: admin,
    )

    expect(SiteSetting.account_security_correlation_auto_scan_frequency).to eq("weekly")
    expect(SiteSetting.account_security_correlation_auto_scan_time).to eq("11:30")
    expect(SiteSetting.account_security_correlation_auto_scan_weekday).to eq("monday")
    expect(SiteSetting.account_security_correlation_auto_scan_timezone).to eq("Europe/Amsterdam")
    expect(status[:timezone]).to eq("Europe/Amsterdam")
  end
end
