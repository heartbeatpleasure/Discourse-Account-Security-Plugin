# frozen_string_literal: true

require "rails_helper"

RSpec.describe Jobs::AccountSecurityCleanup do
  fab!(:admin)

  before do
    SiteSetting.account_security_event_retention_days = 30
    SiteSetting.account_security_user_network_retention_days = 90
    SiteSetting.account_security_low_risk_cache_retention_days = 30
    SiteSetting.account_security_stats_retention_days = 365
    SiteSetting.account_security_correlation_retention_days = 180
  end

  def old_event(ip:)
    AccountSecurity::RiskEvent.create!(
      ip_address: ip,
      event_type: "auth_failure_cluster",
      severity: "high",
      risk_level: "high",
      evidence_strength: "strong",
      context: {},
      status: "open",
      occurrence_count: 1,
      last_seen_at: 60.days.ago,
      created_at: 60.days.ago,
      updated_at: 60.days.ago,
    )
  end

  def provider_report(event)
    AccountSecurity::ProviderReport.create!(
      risk_event_id: event.id,
      ip_address: event.ip_address,
      provider: "abuseipdb",
      category: "brute_force",
      reported_by_id: admin.id,
      status: "reported",
      provider_status: 200,
      reported_at: 55.days.ago,
      created_at: 55.days.ago,
      updated_at: 55.days.ago,
    )
  end

  it "retains provider reports for exactly as long as their retained Risk Event" do
    event = old_event(ip: "8.8.8.8")
    report = provider_report(event)
    audit = AccountSecurity::RiskEventAudit.create!(
      risk_event_id: event.id,
      actor_user_id: admin.id,
      action: "abuse_reported",
      details: { "provider_report_id" => report.id },
      created_at: 55.days.ago,
    )

    described_class.new.execute({})

    expect(AccountSecurity::RiskEvent.exists?(event.id)).to eq(false)
    expect(AccountSecurity::ProviderReport.exists?(report.id)).to eq(false)
    expect(AccountSecurity::RiskEventAudit.exists?(audit.id)).to eq(false)
  end

  it "does not remove event/report/audit history while an unreleased plugin-owned block still references the event" do
    event = old_event(ip: "8.8.4.4")
    report = provider_report(event)
    audit = AccountSecurity::RiskEventAudit.create!(
      risk_event_id: event.id,
      actor_user_id: admin.id,
      action: "abuse_reported",
      details: { "provider_report_id" => report.id },
      created_at: 55.days.ago,
    )
    AccountSecurity::TemporaryIpBlock.create!(
      risk_event_id: event.id,
      screened_ip_address_id: 9_999_999,
      ip_address: event.ip_address,
      created_by_id: admin.id,
      expires_at: 1.day.from_now,
      created_at: 55.days.ago,
      updated_at: 55.days.ago,
    )

    described_class.new.execute({})

    expect(AccountSecurity::RiskEvent.exists?(event.id)).to eq(true)
    expect(AccountSecurity::ProviderReport.exists?(report.id)).to eq(true)
    expect(AccountSecurity::RiskEventAudit.exists?(audit.id)).to eq(true)
  end
  it "does not expire provider-report history before its retained Risk Event" do
    SiteSetting.account_security_event_retention_days = 365
    event = old_event(ip: "1.1.1.1")
    event.update_columns(created_at: 220.days.ago, updated_at: 220.days.ago, last_seen_at: 220.days.ago)
    report = provider_report(event)
    report.update_columns(created_at: 200.days.ago, updated_at: 200.days.ago, reported_at: 200.days.ago)
    audit = AccountSecurity::RiskEventAudit.create!(
      risk_event_id: event.id,
      actor_user_id: admin.id,
      action: "abuse_reported",
      details: { "provider_report_id" => report.id },
      created_at: 200.days.ago,
    )

    described_class.new.execute({})

    expect(AccountSecurity::RiskEvent.exists?(event.id)).to eq(true)
    expect(AccountSecurity::ProviderReport.exists?(report.id)).to eq(true)
    expect(AccountSecurity::RiskEventAudit.exists?(audit.id)).to eq(true)
  end

end
