# frozen_string_literal: true

require "rails_helper"

RSpec.describe Jobs::AccountSecurityProcessAuthAbuseCluster do
  before do
    SiteSetting.account_security_enabled = true
    SiteSetting.account_security_ip_reputation_enabled = true
    SiteSetting.account_security_auth_abuse_detection_enabled = true
    allow(AccountSecurity::Statistics).to receive(:increment!)
  end

  it "does not make a second remote lookup for the escalation phase" do
    result = AccountSecurity::AssessmentService::Result.new(
      success: true,
      reason: "local_preview",
      intelligence: nil,
      event: nil,
      new_network: true,
      source: "local_only",
    )
    received = nil
    allow(AccountSecurity::AssessmentService).to receive(:call) do |**kwargs|
      received = kwargs
      result
    end
    expect(AccountSecurity::EventRecorder).to receive(:record_local_cluster!)

    described_class.new.execute(
      ip: "8.8.8.8",
      family: "failed_login",
      failure_count: 20,
      threshold: 10,
      window_minutes: 10,
      escalation: true,
    )

    expect(received[:trigger]).to eq("auth_failure")
    expect(received[:allow_remote]).to eq(false)
  end

  it "retains a local cluster event when a Trusted Network bypasses provider enrichment" do
    result = AccountSecurity::AssessmentService::Result.new(
      success: true,
      reason: "trusted_network",
      intelligence: nil,
      event: nil,
      new_network: true,
      source: "trusted_network",
    )
    allow(AccountSecurity::AssessmentService).to receive(:call).and_return(result)
    expect(AccountSecurity::EventRecorder).to receive(:record_local_cluster!).with(
      hash_including(trigger: "auth_failure"),
    )

    described_class.new.execute(
      ip: "8.8.4.4",
      family: "failed_login",
      failure_count: 10,
      threshold: 10,
      window_minutes: 10,
      escalation: false,
    )
  end
end

RSpec.describe Jobs::AccountSecurityProcessAuthAbuseCluster, "local-only mode" do
  before do
    SiteSetting.account_security_enabled = true
    SiteSetting.account_security_ip_reputation_enabled = false
    SiteSetting.account_security_auth_abuse_detection_enabled = true
    allow(AccountSecurity::Statistics).to receive(:increment!)
  end

  it "keeps local authentication-abuse detection active without external IP reputation" do
    expect(AccountSecurity::AssessmentService).not_to receive(:call)
    expect(AccountSecurity::EventRecorder).to receive(:record_local_cluster!).with(
      hash_including(
        ip: "8.8.8.8",
        intelligence: nil,
        trigger: "auth_failure",
        local_context: hash_including("failure_count" => 10),
      ),
    )

    described_class.new.execute(
      ip: "8.8.8.8",
      family: "failed_login",
      failure_count: 10,
      threshold: 10,
      window_minutes: 10,
      escalation: false,
    )
  end
end
