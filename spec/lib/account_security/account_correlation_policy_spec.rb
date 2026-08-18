# frozen_string_literal: true

require "rails_helper"

RSpec.describe AccountSecurity::AccountCorrelationPolicy do
  before do
    SiteSetting.account_security_correlation_min_score = 40
  end

  it "treats one clean public IP with authentication evidence as moderate rather than weak" do
    evidence = {
      "shared_exact_ip_count" => 1,
      "shared_ip_details" => [
        {
          "public" => true,
          "user_count" => 2,
          "sources_a" => ["auth_session"],
          "sources_b" => ["auth_session"],
        },
      ],
    }

    result = described_class.score_with_breakdown(evidence)

    expect(result[:score]).to eq(38)
    expect(described_class.confidence(result[:score])).to eq("moderate")
    expect(described_class.store_candidate?(result[:score], evidence)).to eq(true)
  end

  it "keeps a single non-public exact IP visible but low confidence" do
    evidence = {
      "shared_exact_ip_count" => 1,
      "shared_ip_details" => [
        {
          "public" => false,
          "user_count" => 5,
          "sources_a" => ["current"],
          "sources_b" => ["current"],
        },
      ],
    }

    score = described_class.score(evidence)

    expect(score).to eq(6)
    expect(described_class.confidence(score)).to eq("weak")
    expect(described_class.store_candidate?(score, evidence)).to eq(true)
  end

  it "rates a public shared IP plus registration authentication and nearby registration time as strong" do
    evidence = {
      "shared_exact_ip_count" => 2,
      "registration_delta_minutes" => 2.days.to_i / 60,
      "shared_ip_details" => [
        {
          "ip_address" => "84.106.2.103",
          "public" => true,
          "user_count" => 2,
          "sources_a" => ["auth_session"],
          "sources_b" => ["auth_session", "registration"],
        },
        {
          "ip_address" => "10.0.3.1",
          "public" => false,
          "user_count" => 5,
          "sources_a" => %w[current auth_session active_session],
          "sources_b" => %w[current auth_session active_session],
        },
      ],
    }

    result = described_class.score_with_breakdown(evidence)

    expect(result[:score]).to eq(60)
    expect(described_class.confidence(result[:score])).to eq("strong")
  end

  it "makes multiple independent public IP matches very strong when sources corroborate them" do
    evidence = {
      "shared_exact_ip_count" => 2,
      "registration_delta_minutes" => 30,
      "shared_ip_details" => [
        {
          "public" => true,
          "user_count" => 2,
          "sources_a" => %w[registration auth_session],
          "sources_b" => %w[registration auth_session],
        },
        {
          "public" => true,
          "user_count" => 2,
          "sources_a" => %w[history auth_session],
          "sources_b" => %w[history auth_session],
        },
      ],
    }

    score = described_class.score(evidence)

    expect(score).to be >= 75
    expect(described_class.confidence(score)).to eq("very_strong")
  end

  it "applies shared-address popularity only to the public IP that is actually popular" do
    evidence = {
      "shared_exact_ip_count" => 2,
      "shared_ip_details" => [
        {
          "public" => true,
          "user_count" => 2,
          "sources_a" => ["auth_session"],
          "sources_b" => ["auth_session"],
        },
        {
          "public" => false,
          "user_count" => 20,
          "sources_a" => ["current"],
          "sources_b" => ["current"],
        },
      ],
    }

    result = described_class.score_with_breakdown(evidence)
    popularity = result[:breakdown].find { |entry| entry["key"] == "shared_ip_popularity" }

    expect(result[:score]).to eq(44)
    expect(popularity).to be_nil
  end

  it "reduces Tor public-IP weight without hiding the exact-IP pair" do
    ordinary = {
      "shared_exact_ip_count" => 1,
      "shared_ip_details" => [
        {
          "public" => true,
          "user_count" => 2,
          "sources_a" => ["auth_session"],
          "sources_b" => ["auth_session"],
        },
      ],
    }
    tor = Marshal.load(Marshal.dump(ordinary))
    tor["shared_ip_details"][0]["tor"] = true

    expect(described_class.score(tor)).to be < described_class.score(ordinary)
    expect(described_class.store_candidate?(described_class.score(tor), tor)).to eq(true)
  end

  it "uses browser continuity only as positive evidence and never penalizes its absence" do
    base = {
      "shared_exact_ip_count" => 1,
      "shared_ip_details" => [
        {
          "public" => true,
          "user_count" => 2,
          "sources_a" => ["auth_session"],
          "sources_b" => ["auth_session"],
        },
      ],
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

  it "keeps a public registration IP shared by five accounts moderate unless other evidence corroborates it" do
    evidence = {
      "shared_exact_ip_count" => 1,
      "shared_ip_details" => [
        {
          "public" => true,
          "user_count" => 5,
          "sources_a" => ["registration"],
          "sources_b" => ["registration"],
        },
      ],
    }

    score = described_class.score(evidence)

    expect(score).to eq(36)
    expect(described_class.confidence(score)).to eq("moderate")
  end

  it "uses evidence-oriented confidence bands instead of treating scores in the thirties as weak" do
    expect(described_class.confidence(24)).to eq("weak")
    expect(described_class.confidence(25)).to eq("moderate")
    expect(described_class.confidence(49)).to eq("moderate")
    expect(described_class.confidence(50)).to eq("strong")
    expect(described_class.confidence(74)).to eq("strong")
    expect(described_class.confidence(75)).to eq("very_strong")
  end
end
