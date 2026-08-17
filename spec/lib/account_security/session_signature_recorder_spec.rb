# frozen_string_literal: true

require "rails_helper"

RSpec.describe AccountSecurity::SessionSignatureRecorder do
  fab!(:user)

  before do
    SiteSetting.account_security_enabled = true
    SiteSetting.account_security_account_correlation_enabled = true
  end

  it "stores only a site-local HMAC of the user agent" do
    user_agent = "Mozilla/5.0 AccountSecurityTest/1.0"
    token = UserAuthToken.generate!(
      user_id: user.id,
      user_agent: user_agent,
      client_ip: "8.8.8.8",
    )

    record = described_class.record_from_token!(
      user: user,
      token_id: token.id,
      ip: "8.8.8.8",
    )

    expect(record).to be_present
    expect(record.signature_hash).to match(/\A[0-9a-f]{64}\z/)
    expect(record.signature_hash).not_to include("AccountSecurityTest")
    expect(AccountSecurity::SessionSignature.column_names).not_to include("user_agent")
  end

  it "refuses to associate a token with a different observed IP" do
    token = UserAuthToken.generate!(
      user_id: user.id,
      user_agent: "Mozilla/5.0",
      client_ip: "8.8.8.8",
    )

    expect(
      described_class.record_from_token!(user: user, token_id: token.id, ip: "1.1.1.1"),
    ).to be_nil
    expect(AccountSecurity::SessionSignature.count).to eq(0)
  end
end
