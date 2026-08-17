# frozen_string_literal: true

require "rails_helper"

RSpec.describe AccountSecurity::NotificationSuppressionManager do
  fab!(:admin)
  fab!(:user)

  before do
    SiteSetting.account_security_staff_notifications_enabled = true
    allow(AccountSecurity::StaffAudit).to receive(:log!)
  end

  def event
    AccountSecurity::RiskEvent.create!(
      user: user,
      ip_address: "8.8.8.8",
      event_type: "login_new_network",
      severity: "high",
      risk_level: "high",
      evidence_strength: "strong",
      status: "open",
      context: { "familiarity_network" => "8.8.8.8/32" },
      last_seen_at: Time.zone.now,
    )
  end

  it "suppresses notifications only for the exact user/network pair and can release the suppression" do
    risk_event = event
    record = described_class.create!(event: risk_event, actor: admin, duration_hours: 24)

    expect(record).to be_persisted
    expect(described_class.active_for(risk_event)&.id).to eq(record.id)

    described_class.release!(event: risk_event, actor: admin)
    expect(described_class.active_for(risk_event)).to be_nil
  end

  it "rejects unsupported suppression durations" do
    expect {
      described_class.create!(event: event, actor: admin, duration_hours: 25)
    }.to raise_error(Discourse::InvalidParameters)
  end
end
