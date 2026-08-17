# frozen_string_literal: true

require "rails_helper"

RSpec.describe AccountSecurity::QuotaManager do
  before do
    SiteSetting.account_security_registration_reserve = 250
    SiteSetting.account_security_staff_reserve = 100
    SiteSetting.account_security_auth_failure_reserve = 100
    SiteSetting.account_security_manual_reserve = 50
  end

  it "protects dedicated authentication-abuse capacity from normal login enrichment" do
    counts = described_class::BUCKETS.index_with { 0 }

    expect(described_class.protected_capacity("login", counts)).to eq(500)
    expect(described_class.protected_capacity("auth_failure", counts)).to eq(400)
    expect(described_class.protected_capacity("registration", counts)).to eq(150)
    expect(described_class.protected_capacity("staff_login", counts)).to eq(50)
    expect(described_class.protected_capacity("manual", counts)).to eq(0)
  end
end
