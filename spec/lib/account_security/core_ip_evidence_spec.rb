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
end
