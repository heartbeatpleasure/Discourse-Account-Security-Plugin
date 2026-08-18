# frozen_string_literal: true

require "rails_helper"

RSpec.describe AccountSecurity::Feeds::AbuseIpDbBlacklist do
  before do
    SiteSetting.account_security_abuseipdb_api_key = "test-key"
  end

  it "preserves the last good local blacklist when the provider request fails" do
    AccountSecurity::FeedEntry.create!(
      source: "abuseipdb_blacklist",
      ip_address: "8.8.8.8",
      score: 90,
      generation: "previous",
    )
    provider = instance_double(AccountSecurity::Providers::AbuseIpDb)
    allow(AccountSecurity::Providers::AbuseIpDb).to receive(:new).and_return(provider)
    allow(provider).to receive(:blacklist).and_return(
      AccountSecurity::Providers::AbuseIpDb::Result.new(
        success: false,
        status: 503,
        data: {},
        error_code: :server_error,
        headers: {},
      ),
    )

    result = described_class.sync_locked!

    expect(result).to include(success: false, error: "server_error")
    expect(AccountSecurity::FeedEntry.where(source: "abuseipdb_blacklist").pluck(:ip_address).map(&:to_s)).to contain_exactly("8.8.8.8")
    expect(AccountSecurity::FeedSnapshot.find_by(source: "abuseipdb_blacklist").status).to eq("error")
  end

  it "atomically replaces the previous generation after a valid provider result" do
    AccountSecurity::FeedEntry.create!(
      source: "abuseipdb_blacklist",
      ip_address: "8.8.8.8",
      score: 90,
      generation: "previous",
    )
    provider = instance_double(AccountSecurity::Providers::AbuseIpDb)
    allow(AccountSecurity::Providers::AbuseIpDb).to receive(:new).and_return(provider)
    allow(provider).to receive(:blacklist).and_return(
      AccountSecurity::Providers::AbuseIpDb::Result.new(
        success: true,
        status: 200,
        data: [
          { ip: "1.1.1.1", score: 95 },
          { ip: "9.9.9.9", score: 80 },
        ],
        headers: {},
      ),
    )

    result = described_class.sync_locked!

    expect(result).to include(success: true, entry_count: 2)
    expect(AccountSecurity::FeedEntry.where(source: "abuseipdb_blacklist").pluck(:ip_address).map(&:to_s)).to contain_exactly("1.1.1.1", "9.9.9.9")
    snapshot = AccountSecurity::FeedSnapshot.find_by!(source: "abuseipdb_blacklist")
    expect(snapshot.status).to eq("healthy")
    expect(snapshot.entry_count).to eq(2)
  end
end
