# frozen_string_literal: true

require "rails_helper"

RSpec.describe AccountSecurity::SharedIpGroupBuilder do
  fab!(:user_a) { Fabricate(:user) }
  fab!(:user_b) { Fabricate(:user) }

  it "surfaces an exact shared IP from the independent local evidence index even without a stored pair" do
    user_a.update_columns(registration_ip_address: "8.8.8.8")
    user_b.update_columns(registration_ip_address: "8.8.8.8")

    payload = described_class.build(
      page: 1,
      per_page: 20,
      correlation_scope: AccountSecurity::AccountCorrelation.all,
    )

    group = payload[:groups].find { |item| item[:ip_address] == "8.8.8.8" }
    expect(group).to be_present
    expect(group[:account_count]).to eq(2)
    expect(group[:public]).to eq(true)
    expect(group[:pair_count]).to eq(0)
  end

  it "keeps incomplete source diagnostics explicit instead of implying rarity" do
    index = instance_double(AccountSecurity::CoreIpEvidence::ScanIndex)
    allow(index).to receive(:shared_ip_groups).and_return([])
    allow(index).to receive(:source_complete?).and_return(false)
    allow(index).to receive(:diagnostics).and_return(
      auth_log_truncated: true,
      session_observation_truncated: false,
    )
    allow(AccountSecurity::CoreIpEvidence).to receive(:build_scan_index).and_return(index)

    payload = described_class.build(
      page: 1,
      per_page: 20,
      correlation_scope: AccountSecurity::AccountCorrelation.none,
    )

    expect(payload[:source_complete]).to eq(false)
    expect(payload.dig(:diagnostics, :auth_log_truncated)).to eq(true)
  end
end
