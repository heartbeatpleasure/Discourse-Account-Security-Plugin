# frozen_string_literal: true

require "rails_helper"

RSpec.describe AccountSecurity::EventRecorder do
  fab!(:user)

  before do
    SiteSetting.account_security_user_notes_enabled = false
  end

  def intelligence
    AccountSecurity::IpIntelligence.create!(
      ip_address: "8.8.8.8",
      risk_level: "high",
      evidence_strength: "strong",
      primary_score: 80,
      first_seen_at: Time.zone.now,
      last_seen_at: Time.zone.now,
      next_check_after: 1.hour.from_now,
    )
  end

  it "clusters repeated matching events without losing their occurrence count" do
    record = intelligence

    first = described_class.record!(
      user: user,
      ip: "8.8.8.8",
      intelligence: record,
      trigger: "login",
      new_network: true,
      familiarity_network: "8.8.8.8/32",
    )
    second = described_class.record!(
      user: user,
      ip: "8.8.8.8",
      intelligence: record,
      trigger: "login",
      new_network: true,
      familiarity_network: "8.8.8.8/32",
    )

    expect(second.id).to eq(first.id)
    expect(first.reload.occurrence_count).to eq(2)
    expect(AccountSecurity::RiskEvent.count).to eq(1)
  end
end
