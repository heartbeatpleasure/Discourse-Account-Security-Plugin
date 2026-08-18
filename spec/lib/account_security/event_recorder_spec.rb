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

RSpec.describe AccountSecurity::EventRecorder, "incident identity and snapshots" do
  fab!(:user)

  before do
    SiteSetting.account_security_user_notes_enabled = false
    SiteSetting.account_security_staff_notifications_enabled = false
    allow(AccountSecurity::Statistics).to receive(:increment!)
  end

  it "escalates the same incident when its risk changes instead of splitting it" do
    intelligence = AccountSecurity::IpIntelligence.create!(
      ip_address: "8.8.4.4",
      risk_level: "high",
      evidence_strength: "strong",
      primary_score: 70,
      first_seen_at: Time.zone.now,
      last_seen_at: Time.zone.now,
      next_check_after: 1.hour.from_now,
    )

    first = described_class.record!(
      user: user,
      ip: "8.8.4.4",
      intelligence: intelligence,
      trigger: "login",
      new_network: true,
      familiarity_network: "8.8.4.4/32",
    )

    intelligence.update!(risk_level: "critical", evidence_strength: "corroborated", primary_score: 95)
    second = described_class.record!(
      user: user,
      ip: "8.8.4.4",
      intelligence: intelligence,
      trigger: "login",
      new_network: true,
      familiarity_network: "8.8.4.4/32",
    )

    expect(second.id).to eq(first.id)
    expect(second.reload.risk_level).to eq("critical")
    expect(second.evidence_strength).to eq("corroborated")
    expect(second.occurrence_count).to eq(2)
    expect(AccountSecurity::RiskEvent.count).to eq(1)
    expect(
      AccountSecurity::RiskEventAudit.where(
        risk_event_id: second.id,
        action: "incident_escalated",
      ).count,
    ).to eq(1)
  end

  it "keeps an immutable event-time intelligence snapshot when current provider data changes" do
    intelligence = AccountSecurity::IpIntelligence.create!(
      ip_address: "9.9.9.9",
      risk_level: "high",
      evidence_strength: "strong",
      primary_score: 72,
      total_reports: 10,
      distinct_reporters: 4,
      usage_type: "Data Center/Web Hosting/Transit",
      isp: "Example ISP",
      first_seen_at: Time.zone.now,
      last_seen_at: Time.zone.now,
      provider_checked_at: Time.zone.now,
      next_check_after: 1.hour.from_now,
    )

    event = described_class.record!(
      user: user,
      ip: "9.9.9.9",
      intelligence: intelligence,
      trigger: "login",
      new_network: true,
      familiarity_network: "9.9.9.9/32",
    )

    snapshot = event.reload.intelligence_snapshot
    expect(snapshot["provider_data_available"]).to eq(true)
    expect(snapshot["primary_score"]).to eq(72)
    expect(snapshot["total_reports"]).to eq(10)

    intelligence.update!(primary_score: 12, total_reports: 1, isp: "Changed ISP")
    expect(event.reload.intelligence_snapshot).to eq(snapshot)
  end

  it "captures a local event-time snapshot even without external provider intelligence" do
    event = described_class.record_local_cluster!(
      ip: "1.1.1.1",
      intelligence: nil,
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

    snapshot = event.reload.intelligence_snapshot
    expect(snapshot["provider_data_available"]).to eq(false)
    expect(snapshot["risk_level"]).to eq("high")
    expect(snapshot["evidence_strength"]).to eq("strong")
    expect(snapshot["captured_at"]).to be_present
  end
end
