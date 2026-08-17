# frozen_string_literal: true

require "rails_helper"

RSpec.describe AccountSecurity::AccountCorrelationPolicy do
  before do
    SiteSetting.account_security_correlation_min_score = 40
  end

  it "treats one shared current address as context rather than enough evidence" do
    evidence = {
      "shared_registration_ip" => false,
      "same_current_ip" => true,
      "shared_network_count" => 1,
      "shared_session_signature_count" => 0,
      "registration_delta_minutes" => 30.days.to_i / 60,
      "max_shared_network_users" => 2,
    }

    score = described_class.score(evidence)
    expect(score).to be < SiteSetting.account_security_correlation_min_score
    expect(described_class.candidate?(score)).to eq(false)
  end

  it "raises confidence when multiple independent local signals agree" do
    evidence = {
      "shared_registration_ip" => true,
      "same_current_ip" => true,
      "shared_network_count" => 2,
      "shared_session_signature_count" => 1,
      "registration_delta_minutes" => 30,
      "max_shared_network_users" => 2,
    }

    score = described_class.score(evidence)
    expect(score).to eq(100)
    expect(described_class.confidence(score)).to eq("very_strong")
    expect(described_class.candidate?(score)).to eq(true)
  end

  it "reduces confidence for a heavily shared network" do
    base = {
      "shared_registration_ip" => true,
      "same_current_ip" => false,
      "shared_network_count" => 0,
      "shared_session_signature_count" => 0,
      "registration_delta_minutes" => 15_000,
    }

    small_network = described_class.score(base.merge("max_shared_network_users" => 2))
    shared_network = described_class.score(base.merge("max_shared_network_users" => 20))

    expect(shared_network).to be < small_network
    expect(described_class.candidate?(shared_network)).to eq(false)
  end
end
