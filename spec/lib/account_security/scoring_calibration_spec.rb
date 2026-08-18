# frozen_string_literal: true

require "rails_helper"

RSpec.describe AccountSecurity::ScoringCalibration do
  it "keeps the live profile in code while allowing a separate validated preview draft" do
    draft = described_class::DEFAULT_PROFILE.merge(
      "strong_threshold" => 43,
      "browser_base_points" => 31,
      "browser_switch_24h_bonus" => 5,
    )

    saved = described_class.save_draft!(draft)

    expect(saved["strong_threshold"]).to eq(43)
    expect(described_class.draft["browser_base_points"]).to eq(31)
    expect(described_class::DEFAULT_PROFILE["strong_threshold"]).to eq(45)
    expect(AccountSecurity::AccountCorrelationPolicy.confidence(44)).to eq("moderate")
  ensure
    described_class.reset_draft!
  end

  it "rejects inconsistent confidence and time-decay profiles" do
    expect do
      described_class.validated_profile(
        described_class::DEFAULT_PROFILE.merge("strong_threshold" => 20),
      )
    end.to raise_error(Discourse::InvalidParameters)

    expect do
      described_class.validated_profile(
        described_class::DEFAULT_PROFILE.merge(
          "browser_switch_1h_bonus" => 2,
          "browser_switch_6h_bonus" => 5,
        ),
      )
    end.to raise_error(Discourse::InvalidParameters)
  end
end
