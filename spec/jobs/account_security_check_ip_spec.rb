# frozen_string_literal: true

require "rails_helper"

RSpec.describe Jobs::AccountSecurityCheckIp do
  fab!(:user)

  before do
    SiteSetting.account_security_enabled = true
    SiteSetting.account_security_account_correlation_enabled = true
    SiteSetting.account_security_ip_reputation_enabled = false
  end

  it "can update local account correlation without calling an external reputation provider" do
    familiarity = { new_network: true, network: "8.8.8.8/32" }
    allow(AccountSecurity::NetworkFamiliarity).to receive(:observe!).and_return(familiarity)
    allow(AccountSecurity::SessionSignatureRecorder).to receive(:record_from_token!).and_return(nil)
    expect(AccountSecurity::AccountCorrelationService).to receive(:observe!).with(
      user: user,
      ip: "8.8.8.8",
      trigger: "login",
      network: "8.8.8.8/32",
      session_signature: nil,
    )
    expect(AccountSecurity::AssessmentService).not_to receive(:call)

    described_class.new.execute(ip: "8.8.8.8", user_id: user.id, trigger: "login")
  end
end
