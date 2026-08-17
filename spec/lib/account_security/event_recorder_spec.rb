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

RSpec.describe AccountSecurity::EventRecorder, "local authentication-abuse evidence" do
  before do
    SiteSetting.account_security_user_notes_enabled = false
    SiteSetting.account_security_staff_notifications_enabled = false
  end

  it "creates a strong local cluster event even when provider intelligence is unavailable" do
    event = described_class.record_local_cluster!(
      ip: "1.1.1.1",
      intelligence: nil,
      trigger: "auth_failure",
      local_context: {
        "abuse_family" => "failed_login",
        "failure_count" => 10,
        "threshold" => 10,
        "window_minutes" => 10,
        "threshold_exceeded" => true,
        "local_abuse_confirmed" => false,
      },
    )

    expect(event.event_type).to eq("auth_failure_cluster")
    expect(event.severity).to eq("elevated")
    expect(event.evidence_strength).to eq("strong")
  end

  it "upgrades an existing high-risk cluster to confirmed local evidence without inflating occurrence count" do
    intelligence = AccountSecurity::IpIntelligence.create!(
      ip_address: "1.0.0.1",
      risk_level: "high",
      evidence_strength: "strong",
      primary_score: 85,
      first_seen_at: Time.zone.now,
      last_seen_at: Time.zone.now,
      next_check_after: 1.hour.from_now,
    )

    first = described_class.record_local_cluster!(
      ip: "1.0.0.1",
      intelligence: intelligence,
      trigger: "auth_failure",
      local_context: {
        "abuse_family" => "failed_login",
        "failure_count" => 10,
        "threshold" => 10,
        "window_minutes" => 10,
        "threshold_exceeded" => true,
        "local_abuse_confirmed" => false,
      },
    )
    second = described_class.record_local_cluster!(
      ip: "1.0.0.1",
      intelligence: intelligence,
      trigger: "auth_failure",
      local_context: {
        "abuse_family" => "failed_login",
        "failure_count" => 20,
        "threshold" => 10,
        "window_minutes" => 10,
        "threshold_exceeded" => true,
        "local_abuse_confirmed" => true,
      },
    )

    expect(second.id).to eq(first.id)
    expect(second.reload.evidence_strength).to eq("corroborated")
    expect(second.occurrence_count).to eq(1)
    expect(second.context["local_abuse_confirmed"]).to eq(true)
  end
end
