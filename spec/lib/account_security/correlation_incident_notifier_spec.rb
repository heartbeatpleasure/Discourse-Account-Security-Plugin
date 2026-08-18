# frozen_string_literal: true

require "rails_helper"

RSpec.describe AccountSecurity::CorrelationIncidentNotifier do
  fab!(:user_a) { Fabricate(:user) }
  fab!(:user_b) { Fabricate(:user) }
  fab!(:group)

  before do
    SiteSetting.account_security_staff_notifications_enabled = true
    SiteSetting.account_security_correlation_notifications_enabled = true
    SiteSetting.account_security_notification_groups = group.id.to_s
    allow(PostCreator).to receive(:create!).and_return(true)
    allow(AccountSecurity::Statistics).to receive(:increment!)
  end

  def correlation(score: 60, confidence: "strong", status: "open")
    first_id, second_id = [user_a.id, user_b.id].sort
    AccountSecurity::AccountCorrelation.create!(
      user_a_id: first_id,
      user_b_id: second_id,
      score: score,
      confidence: confidence,
      status: status,
      evidence: {
        "shared_exact_ip_count" => 2,
        "untrusted_public_ip_count" => 1,
        "shared_auth_ip_count" => 2,
      },
      first_seen_at: Time.zone.now,
      last_seen_at: Time.zone.now,
    )
  end

  it "sends one deduplicated notification for a new strong realtime finding" do
    item = correlation
    captured = nil
    allow(PostCreator).to receive(:create!) do |_actor, options|
      captured = options
      true
    end

    expect(described_class.notify_if_needed!(item, source: "login")).to eq(true)
    expect(item.reload.notified_at).to be_present
    expect(item.notified_score).to eq(60)
    expect(captured[:target_group_names]).to eq(group.name)
    expect(captured[:raw]).to include(user_a.username)
    expect(captured[:raw]).to include(user_b.username)

    expect(described_class.notify_if_needed!(item, source: "login")).to eq(false)
    expect(PostCreator).to have_received(:create!).once
  end

  it "never emits per-pair notifications from historical full scans" do
    item = correlation

    expect(described_class.notify_if_needed!(item, source: "backfill_scan")).to eq(false)
    expect(described_class.notify_if_needed!(item, source: "scheduled_scan")).to eq(false)
    expect(PostCreator).not_to have_received(:create!)
  end

  it "notifies again only after a material realtime escalation" do
    item = correlation
    expect(described_class.notify_if_needed!(item, source: "login")).to eq(true)

    item.update!(score: 74)
    expect(described_class.notify_if_needed!(item, source: "login")).to eq(false)

    item.update!(score: 75, confidence: "very_strong")
    expect(described_class.notify_if_needed!(item, source: "browser_continuity")).to eq(true)
    expect(PostCreator).to have_received(:create!).twice
  end

  it "does not notify resolved or expected correlations" do
    item = correlation(status: "expected_shared_network")

    expect(described_class.notify_if_needed!(item, source: "login")).to eq(false)
    expect(PostCreator).not_to have_received(:create!)
  end
end
