# frozen_string_literal: true

require "rails_helper"

RSpec.describe AccountSecurity::IncidentNotifier do
  fab!(:user)
  fab!(:group)

  before do
    SiteSetting.account_security_staff_notifications_enabled = true
    SiteSetting.account_security_notification_groups = group.id.to_s
    SiteSetting.account_security_notification_include_ip = false
    allow(PostCreator).to receive(:create!).and_return(true)
  end

  def critical_registration
    AccountSecurity::RiskEvent.create!(
      user: user,
      ip_address: "8.8.8.8",
      event_type: "registration",
      severity: "critical",
      risk_level: "critical",
      evidence_strength: "strong",
      status: "open",
      context: {
        "familiarity_network" => "8.8.8.8/32",
        "usage_type" => "Data Center/Web Hosting/Transit",
      },
      last_seen_at: Time.zone.now,
    )
  end

  it "sends one incident PM to the configured group without putting the IP in the message by default" do
    risk_event = critical_registration
    captured = nil
    allow(PostCreator).to receive(:create!) do |_actor, options|
      captured = options
      true
    end

    expect(described_class.notify_if_needed!(risk_event)).to eq(true)
    expect(risk_event.reload.notified_at).to be_present
    expect(risk_event.notification_kind).to eq("critical_registration")
    expect(captured[:target_group_names]).to eq(group.name)
    expect(captured[:archetype]).to eq(Archetype.private_message)
    expect(captured[:raw]).not_to include("8.8.8.8")
    expect(captured[:raw]).to include("/admin/plugins/account-security-events/#{risk_event.id}")

    described_class.notify_if_needed!(risk_event)
    expect(PostCreator).to have_received(:create!).once
  end

  it "honors an active user/network notification suppression" do
    risk_event = critical_registration
    AccountSecurity::NotificationSuppression.create!(
      user: user,
      network_key: "8.8.8.8/32",
      expires_at: 1.day.from_now,
    )

    expect(described_class.notify_if_needed!(risk_event)).to eq(false)
    expect(PostCreator).not_to have_received(:create!)
    expect(risk_event.reload.notified_at).to be_nil
  end
end
