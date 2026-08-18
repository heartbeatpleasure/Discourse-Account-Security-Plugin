# frozen_string_literal: true

require "rails_helper"

RSpec.describe AccountSecurity::SessionObservationsController do
  fab!(:user)

  before do
    SiteSetting.account_security_enabled = true
    SiteSetting.account_security_account_correlation_enabled = true
    SiteSetting.account_security_session_observation_enabled = true
    SiteSetting.account_security_browser_continuity_enabled = true
  end

  it "requires an authenticated user" do
    post "/account-security/session-observation.json"
    expect(response.status).not_to eq(204)
  end

  it "queues only normalized/HMAC-derived evidence and never the raw user agent" do
    sign_in(user)
    browser_hash = "a" * 64
    client_hash = "b" * 64
    allow(AccountSecurity::BrowserContinuityRecorder).to receive(:ensure_token_hash!).and_return(browser_hash)
    allow(AccountSecurity::SessionSignatureRecorder).to receive(:signature_for).and_return(client_hash)

    expect(Jobs).to receive(:enqueue) do |job, args|
      expect(job).to eq(:account_security_record_session_observation)
      expect(args[:user_id]).to eq(user.id)
      expect(args[:browser_token_hash]).to eq(browser_hash)
      expect(args[:client_signature_hash]).to eq(client_hash)
      expect(args.keys).not_to include(:user_agent)
      expect(args[:ip]).to be_present
    end

    post "/account-security/session-observation.json"

    expect(response.status).to eq(204)
  end
end
