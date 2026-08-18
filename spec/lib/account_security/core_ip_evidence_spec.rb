# frozen_string_literal: true

require "rails_helper"

RSpec.describe AccountSecurity::CoreIpEvidence do
  fab!(:user_a) { Fabricate(:user) }
  fab!(:user_b) { Fabricate(:user) }

  it "combines registration, current and Discourse core history for an exact IP" do
    user_a.update_columns(registration_ip_address: "8.8.8.8", ip_address: "8.8.8.8")
    user_b.update_columns(registration_ip_address: "8.8.8.8")
    UserIpAddressHistory.create!(user_id: user_b.id, ip_address: "8.8.8.8")

    details = described_class.shared_details_for_pair(user_a.id, user_b.id)
    detail = details.find { |row| row["ip_address"] == "8.8.8.8" }

    expect(detail).to be_present
    expect(detail["sources_a"]).to include("registration", "current")
    expect(detail["sources_b"]).to include("registration", "history")
    expect(detail["public"]).to eq(true)
    expect(detail["user_count"]).to be >= 2
  end

  it "keeps exact non-public IP relations instead of dropping them" do
    user_a.update_columns(registration_ip_address: "10.0.0.50")
    user_b.update_columns(registration_ip_address: "10.0.0.50")

    details = described_class.shared_details_for_pair(user_a.id, user_b.id)

    expect(details.one?).to eq(true)
    expect(details.first["ip_address"]).to eq("10.0.0.50")
    expect(details.first["public"]).to eq(false)
  end

  it "preserves Set-based source collections when building scan details" do
    detail = described_class.detail_for(
      "8.8.4.4",
      Set.new(%w[registration history]),
      Set.new(%w[current history]),
      2,
    )

    expect(detail["sources_a"]).to eq(%w[history registration])
    expect(detail["sources_b"]).to eq(%w[current history])
  end

  it "keeps high-sharing IP groups visible in scan diagnostics without generating pairs" do
    index = described_class::ScanIndex.new
    allow(described_class).to receive(:context_for).with("8.8.8.8").and_return(
      public: true,
      trusted: false,
      tor: false,
      local_blacklist: false,
      usage_type: "Data Center/Web Hosting/Transit",
      isp: "Example Infrastructure",
      hosting: true,
      mobile: false,
    )

    21.times { |offset| index.add(offset + 1, "8.8.8.8", "history") }

    pairs = index.pair_set(max_group_users: 20, max_pairs: 20_000)
    summary = index.diagnostics[:large_ip_group_summaries].first

    expect(pairs).to be_empty
    expect(index.diagnostics[:large_ip_groups_skipped]).to eq(1)
    expect(summary).to include(
      "ip_address" => "8.8.8.8",
      "user_count" => 21,
      "hosting" => true,
      "isp" => "Example Infrastructure",
    )
  end
end
