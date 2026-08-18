# frozen_string_literal: true

require "rails_helper"

RSpec.describe AccountSecurity::RiskEventAuditTrail do
  fab!(:admin)

  def event
    @event ||= AccountSecurity::RiskEvent.create!(
      ip_address: "8.8.8.8",
      event_type: "auth_failure_cluster",
      severity: "high",
      risk_level: "high",
      evidence_strength: "strong",
      context: {},
      status: "open",
      occurrence_count: 1,
      last_seen_at: Time.zone.now,
    )
  end

  it "persists only whitelisted, bounded audit details" do
    expect(
      described_class.record!(
        event: event,
        action: "review_changed",
        actor: admin,
        from_status: "open",
        to_status: "monitor",
        details: {
          resolution_reason: "Reviewed by staff",
          secret_payload: "must not be persisted",
        },
      ),
    ).to eq(true)

    audit = AccountSecurity::RiskEventAudit.last
    expect(audit.actor_user_id).to eq(admin.id)
    expect(audit.from_status).to eq("open")
    expect(audit.to_status).to eq("monitor")
    expect(audit.details["resolution_reason"]).to eq("Reviewed by staff")
    expect(audit.details).not_to have_key("secret_payload")
  end

  it "keeps persisted audit rows append-only" do
    described_class.record!(event: event, action: "event_created")
    audit = AccountSecurity::RiskEventAudit.last

    expect { audit.update!(action: "review_changed") }.to raise_error(ActiveRecord::ReadOnlyRecord)
  end
end
