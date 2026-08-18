# frozen_string_literal: true

require "rails_helper"

RSpec.describe AccountSecurity::Statistics do
  it "atomically accumulates only known nonnegative counters for the current day" do
    described_class.increment!(provider_calls: 2, events_created: 1, cache_hits: -50, unknown: 999)
    described_class.increment!(provider_calls: 3, events_created: 4)

    row = AccountSecurity::DailyStat.find_by!(stat_date: Date.current)
    expect(row.provider_calls).to eq(5)
    expect(row.events_created).to eq(5)
    expect(row.cache_hits).to eq(0)
  end

  it "bounds requested reporting periods" do
    expect(described_class.period_payload(1)[:period_days]).to eq(7)
    expect(described_class.period_payload(10_000)[:period_days]).to eq(365)
  end
end
