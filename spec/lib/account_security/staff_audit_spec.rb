# frozen_string_literal: true

require "rails_helper"

RSpec.describe AccountSecurity::StaffAudit do
  fab!(:admin)
  fab!(:user)

  it "accepts only administrators and allowlisted actions" do
    expect(described_class.log!(actor: user, action: "event_review_changed", details: { event_id: 1 })).to eq(false)
    expect(described_class.log!(actor: admin, action: "not_allowed", details: { event_id: 1 })).to eq(false)
  end

  it "does not copy arbitrary detail values into the staff log" do
    logger = instance_double(StaffActionLogger)
    allow(StaffActionLogger).to receive(:new).with(admin).and_return(logger)
    expect(logger).to receive(:log_custom).with(
      "account_security_event_review_changed",
      hash_including(subject: "Account Security", event_id: 1, status: "acknowledged"),
    )

    described_class.log!(
      actor: admin,
      action: "event_review_changed",
      details: { event_id: 1, status: "acknowledged", raw_ip: "8.8.8.8" },
    )
  end
  it "audits calibration draft changes without logging the draft weights themselves" do
    logger = instance_double(StaffActionLogger)
    allow(StaffActionLogger).to receive(:new).with(admin).and_return(logger)
    expect(logger).to receive(:log_custom).with(
      "account_security_scoring_calibration_draft_saved",
      hash_including(subject: "Account Security", scoring_version: 3, scoring_revision: 2),
    )

    described_class.log!(
      actor: admin,
      action: "scoring_calibration_draft_saved",
      details: { scoring_version: 3, scoring_revision: 2, browser_base_points: 35 },
    )
  end

end
