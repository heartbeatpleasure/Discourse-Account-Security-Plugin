# frozen_string_literal: true

require "rails_helper"

RSpec.describe AccountSecurity::AccountCorrelationScanner do
  before do
    SiteSetting.account_security_enabled = true
    SiteSetting.account_security_account_correlation_enabled = true
    Discourse.redis.del(described_class::STATUS_KEY)
  end

  after do
    Discourse.redis.del(described_class::STATUS_KEY)
  end

  it "builds each local candidate pair only once" do
    users = Array.new(3) { Fabricate(:user) }
    users.each do |user|
      user.update_columns(registration_ip_address: "8.8.8.8", ip_address: "8.8.8.8")
    end

    pairs, truncated = described_class.candidate_pairs

    expect(truncated).to eq(false)
    expect(pairs.sort).to eq(users.map(&:id).sort.combination(2).to_a.sort)
  end

  it "does not expand network groups beyond the shared-network safety cap" do
    users = Array.new(described_class::MAX_GROUP_USERS + 1) { Fabricate(:user) }
    now = Time.zone.now
    users.each do |user|
      AccountSecurity::UserNetwork.create!(
        user_id: user.id,
        network_key: "8.8.4.0/24",
        address_family: "ipv4",
        first_seen_at: now,
        last_seen_at: now,
        successful_login_count: 1,
      )
    end

    pairs, = described_class.candidate_pairs

    expect(pairs).to be_empty
  end
end
