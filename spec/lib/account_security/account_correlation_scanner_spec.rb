# frozen_string_literal: true

require "rails_helper"

RSpec.describe AccountSecurity::AccountCorrelationScanner do
  before do
    SiteSetting.account_security_enabled = true
    SiteSetting.account_security_account_correlation_enabled = true
    SiteSetting.account_security_browser_continuity_enabled = true
    Discourse.redis.del(described_class::STATUS_KEY)
  end

  after do
    Discourse.redis.del(described_class::STATUS_KEY)
  end

  it "builds each exact registration-IP pair only once" do
    users = Array.new(3) { Fabricate(:user) }
    users.each do |user|
      user.update_columns(registration_ip_address: "8.8.8.8", ip_address: "8.8.8.8")
    end

    pairs, truncated, _index, _context, diagnostics = described_class.candidate_pairs

    expect(truncated).to eq(false)
    expect(pairs.sort).to eq(users.map(&:id).sort.combination(2).to_a.sort)
    expect(diagnostics[:exact_ip_pairs_generated]).to eq(3)
  end

  it "does not discard exact non-public registration-IP overlap" do
    users = Array.new(5) { Fabricate(:user) }
    users.each { |user| user.update_columns(registration_ip_address: "10.0.0.25") }

    pairs, _truncated, _index, _context, diagnostics = described_class.candidate_pairs

    expect(pairs.sort).to eq(users.map(&:id).sort.combination(2).to_a.sort)
    expect(diagnostics[:nonpublic_ip_groups]).to be >= 1
  end

  it "uses Discourse core user IP history when generating existing-account candidates" do
    user_a = Fabricate(:user)
    user_b = Fabricate(:user)
    UserIpAddressHistory.create!(user_id: user_a.id, ip_address: "1.1.1.1")
    UserIpAddressHistory.create!(user_id: user_b.id, ip_address: "1.1.1.1")

    pairs, _truncated, _index, _context, diagnostics = described_class.candidate_pairs

    expect(pairs).to include([user_a.id, user_b.id].sort)
    expect(diagnostics[:history_rows]).to be >= 2
  end

  it "does not expand exact-IP groups beyond the safety cap" do
    users = Array.new(described_class::MAX_GROUP_USERS + 1) { Fabricate(:user) }
    users.each { |user| user.update_columns(registration_ip_address: "8.8.4.4") }

    pairs, _truncated, _index, _context, diagnostics = described_class.candidate_pairs

    expect(pairs).to be_empty
    expect(diagnostics[:large_ip_groups_skipped]).to be >= 1
  end
  it "does not generate a candidate pair from browser continuity alone" do
    user_a = Fabricate(:user)
    user_b = Fabricate(:user)
    user_a.update_columns(registration_ip_address: "1.1.1.1", ip_address: "1.1.1.1")
    user_b.update_columns(registration_ip_address: "8.8.8.8", ip_address: "8.8.8.8")
    token_hash = AccountSecurity::BrowserContinuityRecorder.token_hash("C" * 43)
    now = Time.zone.now
    AccountSecurity::BrowserContinuity.create!(user_id: user_a.id, token_hash: token_hash, first_seen_at: now, last_seen_at: now, observation_count: 1)
    AccountSecurity::BrowserContinuity.create!(user_id: user_b.id, token_hash: token_hash, first_seen_at: now, last_seen_at: now, observation_count: 1)

    pairs, _truncated, _index, _context, _diagnostics = described_class.candidate_pairs

    expect(pairs).not_to include([user_a.id, user_b.id].sort)
  end

end
