# frozen_string_literal: true
require "rails_helper"

RSpec.describe AccountSecurity::AbuseReporter do
  fab!(:admin)

  before do
    SiteSetting.account_security_enabled = true
    SiteSetting.account_security_ip_reputation_enabled = true
    SiteSetting.account_security_abuse_reporting_enabled = true
    SiteSetting.account_security_abuseipdb_api_key = "test-key"
  end

  def create_event(overrides = {})
    AccountSecurity::RiskEvent.create!(
      {
        ip_address: "8.8.8.8",
        event_type: "auth_failure_cluster",
        severity: "high",
        risk_level: "high",
        evidence_strength: "corroborated",
        status: "open",
        context: {
          "local_abuse_confirmed" => true,
          "threshold_exceeded" => true,
        },
      }.merge(overrides),
    )
  end

  it "rejects an event without objectively confirmed local abuse" do
    event = create_event(context: { "local_abuse_confirmed" => false, "threshold_exceeded" => true })

    expect {
      described_class.report_event!(event_id: event.id, actor: admin)
    }.to raise_error(Discourse::InvalidParameters)

    expect(AccountSecurity::ProviderReport.count).to eq(0)
  end

  it "rejects ordinary reputation events even if their context is marked confirmed" do
    event = create_event(event_type: "registration")

    expect {
      described_class.report_event!(event_id: event.id, actor: admin)
    }.to raise_error(Discourse::InvalidParameters)

    expect(AccountSecurity::ProviderReport.count).to eq(0)
  end

  it "rejects reporting when the opt-in setting is disabled" do
    SiteSetting.account_security_abuse_reporting_enabled = false
    event = create_event

    expect {
      described_class.report_event!(event_id: event.id, actor: admin)
    }.to raise_error(Discourse::InvalidAccess)

    expect(AccountSecurity::ProviderReport.count).to eq(0)
  end
end
