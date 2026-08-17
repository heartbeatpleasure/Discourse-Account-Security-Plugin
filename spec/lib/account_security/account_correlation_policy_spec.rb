# frozen_string_literal: true

require "rails_helper"

RSpec.describe AccountSecurity::AccountCorrelationPolicy do
  before do
    SiteSetting.account_security_correlation_min_score = 40
  end

  it "keeps one exact public registration IP as a review candidate" do
    evidence = {
      "shared_exact_ip_count" => 1,
      "untrusted_public_ip_count" => 1,
      "shared_registration_ip_public" => true,
      "max_shared_exact_ip_users" => 2,
    }

    result = described_class.score_with_breakdown(evidence)

    expect(result[:score]).to eq(48)
    expect(described_class.store_candidate?(result[:score], evidence)).to eq(true)
    expect(described_class.confidence(result[:score])).to eq("moderate")
  end

  it "keeps exact non-public overlap visible even when the score is low" do
    evidence = {
      "shared_exact_ip_count" => 1,
      "shared_nonpublic_ip_count" => 1,
      "shared_registration_ip_nonpublic" => true,
      "max_shared_exact_ip_users" => 5,
    }

    score = described_class.score(evidence)

    expect(score).to be < SiteSetting.account_security_correlation_min_score
    expect(described_class.store_candidate?(score, evidence)).to eq(true)
  end

  it "raises confidence when several independent exact IPs agree" do
    evidence = {
      "shared_exact_ip_count" => 3,
      "untrusted_public_ip_count" => 3,
      "shared_registration_ip_public" => true,
      "shared_history_ip_count" => 2,
      "shared_session_signature_count" => 1,
      "registration_delta_minutes" => 30,
      "max_shared_exact_ip_users" => 2,
    }

    score = described_class.score(evidence)

    expect(score).to eq(100)
    expect(described_class.confidence(score)).to eq("very_strong")
  end

  it "reduces identity confidence for shared Tor and popular IP context without hiding the pair" do
    base = {
      "shared_exact_ip_count" => 1,
      "untrusted_public_ip_count" => 1,
      "shared_registration_ip_public" => true,
      "max_shared_exact_ip_users" => 5,
    }

    ordinary = described_class.score(base)
    contextual = described_class.score(base.merge("tor_shared_ip_count" => 1))

    expect(contextual).to be < ordinary
    expect(described_class.store_candidate?(contextual, base)).to eq(true)
  end

  it "uses browser continuity only as positive evidence and never penalizes its absence" do
    base = {
      "shared_exact_ip_count" => 1,
      "untrusted_public_ip_count" => 1,
      "max_shared_exact_ip_users" => 2,
    }

    without_continuity = described_class.score(base)
    with_continuity = described_class.score(
      base.merge("browser_continuity_count" => 1, "max_browser_continuity_users" => 2),
    )

    expect(with_continuity).to be > without_continuity
    expect(described_class.score(base.merge("browser_continuity_count" => 0))).to eq(without_continuity)
  end
  it "never creates a candidate from browser continuity alone" do
    browser_only = {
      "browser_continuity_count" => 2,
      "max_browser_continuity_users" => 2,
      "registration_delta_minutes" => 10,
    }

    score = described_class.score(browser_only)

    expect(score).to be > 0
    expect(described_class.store_candidate?(score, browser_only)).to eq(false)
  end

  it "keeps a public registration IP shared by five accounts visible with reduced confidence" do
    evidence = {
      "shared_exact_ip_count" => 1,
      "untrusted_public_ip_count" => 1,
      "shared_registration_ip_public" => true,
      "max_shared_exact_ip_users" => 5,
    }

    score = described_class.score(evidence)

    expect(score).to eq(41)
    expect(described_class.store_candidate?(score, evidence)).to eq(true)
    expect(described_class.confidence(score)).to eq("moderate")
  end

end
