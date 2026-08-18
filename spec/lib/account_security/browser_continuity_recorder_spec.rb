# frozen_string_literal: true

require "rails_helper"

RSpec.describe AccountSecurity::BrowserContinuityRecorder do
  fab!(:user_a) { Fabricate(:user) }
  fab!(:user_b) { Fabricate(:user) }

  before do
    SiteSetting.account_security_enabled = true
    SiteSetting.account_security_account_correlation_enabled = true
    SiteSetting.account_security_browser_continuity_enabled = true
  end

  it "sets a signed host-only Secure HttpOnly continuity cookie and queues only its HMAC" do
    signed_cookies = {}
    cookies = Struct.new(:signed).new(signed_cookies)
    expect(Jobs).to receive(:enqueue) do |job, args|
      expect(job).to eq(:account_security_record_browser_continuity)
      expect(args[:user_id]).to eq(user_a.id)
      expect(args[:token_hash]).to match(/\A[0-9a-f]{64}\z/)
    end

    digest = described_class.capture_login!(cookies: cookies, user: user_a)
    cookie = signed_cookies[described_class::COOKIE_NAME]

    expect(digest).to match(/\A[0-9a-f]{64}\z/)
    expect(cookie[:value]).to match(described_class::TOKEN_PATTERN)
    expect(cookie[:value]).not_to eq(digest)
    expect(cookie[:path]).to eq("/")
    expect(cookie[:secure]).to eq(true)
    expect(cookie[:httponly]).to eq(true)
    expect(cookie[:same_site]).to eq(:lax)
  end

  it "persists only an HMAC-shaped token hash and detects a shared browser token" do
    raw = "A" * 43
    digest = described_class.token_hash(raw)

    expect(digest).not_to include(raw)
    expect(digest).to match(/\A[0-9a-f]{64}\z/)

    described_class.record!(user_id: user_a.id, token_hash: digest)
    described_class.record!(user_id: user_b.id, token_hash: digest)

    summary = described_class.shared_summary(user_a.id, user_b.id)
    expect(summary[:count]).to eq(1)
    expect(summary[:max_users]).to eq(2)
    expect(AccountSecurity::BrowserContinuity.where(token_hash: digest).count).to eq(2)

    described_class.record!(user_id: user_a.id, token_hash: digest, observed_at: 2.days.from_now)
    described_class.record!(user_id: user_b.id, token_hash: digest, observed_at: 2.days.from_now)
    repeated = described_class.shared_summary(user_a.id, user_b.id)
    expect(repeated[:repeated_count]).to eq(1)
    expect(repeated[:paired_observations]).to eq(2)
    expect(repeated[:max_span_days]).to be >= 1
  end

  it "keeps browser continuity supplemental and does not create a candidate by itself" do
    digest = described_class.token_hash("B" * 43)
    described_class.record!(user_id: user_a.id, token_hash: digest)
    described_class.record!(user_id: user_b.id, token_hash: digest)

    correlation = AccountSecurity::AccountCorrelation.find_by(
      user_a_id: [user_a.id, user_b.id].min,
      user_b_id: [user_a.id, user_b.id].max,
    )

    expect(correlation).to be_nil

    user_a.update_columns(registration_ip_address: "8.8.8.8")
    user_b.update_columns(registration_ip_address: "8.8.8.8")
    correlation = AccountSecurity::AccountCorrelationService.recalculate_pair!(user_a.id, user_b.id)

    expect(correlation).to be_present
    expect(correlation.evidence["browser_continuity_count"]).to eq(1)
    expect(correlation.evidence["browser_continuity_positive_only"]).to eq(true)
  end
end
