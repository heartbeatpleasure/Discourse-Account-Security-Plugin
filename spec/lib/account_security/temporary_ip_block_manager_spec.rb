# frozen_string_literal: true

require "rails_helper"

RSpec.describe AccountSecurity::TemporaryIpBlockManager do
  fab!(:admin)

  before do
    SiteSetting.account_security_temporary_ip_blocks_enabled = true
  end

  def event(ip = "8.8.8.8")
    AccountSecurity::RiskEvent.create!(
      ip_address: ip,
      event_type: "registration",
      severity: "high",
      risk_level: "high",
      evidence_strength: "strong",
      status: "open",
      context: {},
      last_seen_at: Time.zone.now,
    )
  end

  it "creates and tracks only an explicit temporary core IP block" do
    risk_event = event

    block = described_class.create!(event: risk_event, actor: admin, duration_minutes: 60)

    expect(block).to be_persisted
    expect(ScreenedIpAddress.should_block?("8.8.8.8")).to eq(true)
    expect(block.screened_ip_address_id).to be_present
    expect(block.expires_at).to be > Time.zone.now
  end

  it "does not take ownership of a pre-existing Discourse screening rule" do
    ScreenedIpAddress.create!(ip_address: "8.8.4.4", action_type: ScreenedIpAddress.actions[:block])
    risk_event = event("8.8.4.4")

    expect {
      described_class.create!(event: risk_event, actor: admin, duration_minutes: 60)
    }.to raise_error(AccountSecurity::TemporaryIpBlockManager::ExistingScreening)

    expect(AccountSecurity::TemporaryIpBlock.count).to eq(0)
    expect(ScreenedIpAddress.should_block?("8.8.4.4")).to eq(true)
  end

  it "removes only the exact plugin-owned screening record when released" do
    risk_event = event
    block = described_class.create!(event: risk_event, actor: admin, duration_minutes: 60)

    described_class.release_for_event!(event: risk_event, actor: admin)

    expect(block.reload.released_at).to be_present
    expect(ScreenedIpAddress.find_by(id: block.screened_ip_address_id)).to be_nil
  end

  it "does not delete a screened IP record that no longer matches plugin ownership" do
    risk_event = event
    block = described_class.create!(event: risk_event, actor: admin, duration_minutes: 60)
    screened = ScreenedIpAddress.find(block.screened_ip_address_id)
    screened.update!(ip_address: "8.8.4.4")

    described_class.release_for_event!(event: risk_event, actor: admin)

    expect(block.reload.release_reason).to eq("ownership_mismatch")
    expect(ScreenedIpAddress.find_by(id: screened.id)).to be_present
  end

  it "expires plugin-owned blocks even when no administrator triggers the release" do
    risk_event = event
    block = described_class.create!(event: risk_event, actor: admin, duration_minutes: 60)
    block.update!(expires_at: 1.minute.ago)

    described_class.expire_due!

    expect(block.reload.release_reason).to eq("expired")
    expect(block.released_at).to be_present
    expect(ScreenedIpAddress.find_by(id: block.screened_ip_address_id)).to be_nil
  end
end
