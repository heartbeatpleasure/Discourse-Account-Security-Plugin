# frozen_string_literal: true

require "rails_helper"

RSpec.describe AccountSecurity::NetworkFamiliarity do
  fab!(:user)

  before do
    SiteSetting.account_security_user_network_retention_days = 90
    SiteSetting.account_security_ipv6_familiarity_prefix = 64
  end

  it "treats the first successful observation as new and later observations as familiar" do
    first = described_class.observe!(user: user, ip: "8.8.8.8")
    second = described_class.observe!(user: user, ip: "8.8.8.8")

    expect(first).to eq(new_network: true, network: "8.8.8.8/32")
    expect(second).to eq(new_network: false, network: "8.8.8.8/32")
    expect(AccountSecurity::UserNetwork.find_by(user_id: user.id).successful_login_count).to eq(2)
  end

  it "uses the configured IPv6 prefix so privacy-address changes inside one network stay familiar" do
    first = described_class.observe!(user: user, ip: "2001:4860:4860:1234::1")
    second = described_class.observe!(user: user, ip: "2001:4860:4860:1234::abcd")

    expect(first[:network]).to eq("2001:4860:4860:1234::/64")
    expect(second[:network]).to eq(first[:network])
    expect(second[:new_network]).to eq(false)
  end

  it "records registration origin without counting it as a successful login" do
    described_class.observe!(user: user, ip: "1.1.1.1", registration: true)
    record = AccountSecurity::UserNetwork.find_by(user_id: user.id, network_key: "1.1.1.1/32")

    expect(record.registration_origin).to eq(true)
    expect(record.successful_login_count).to eq(0)
  end
end
