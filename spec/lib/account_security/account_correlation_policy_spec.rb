# frozen_string_literal: true

require "rails_helper"

RSpec.describe AccountSecurity::AccountCorrelationPolicy do
  before do
    SiteSetting.account_security_correlation_min_score = 40
  end

  def public_ip(ip:, users: 2, sources_a: ["auth_session"], sources_b: ["auth_session"], **context)
    {
      "ip_address" => ip,
      "public" => true,
      "trusted" => false,
      "user_count" => users,
      "sources_a" => sources_a,
      "sources_b" => sources_b,
    }.merge(context.transform_keys(&:to_s))
  end

  def exact_ip_evidence(*details)
    {
      "shared_exact_ip_count" => details.length,
      "shared_public_ip_count" => details.length,
      "untrusted_public_ip_count" => details.count { |detail| detail["trusted"] != true },
      "exact_ip_population_complete" => true,
      "shared_ip_details" => details,
    }
  end

  it "uses scoring version 3" do
    expect(described_class::SCORING_VERSION).to eq(3)
  end

  it "rates one rare clean public IP with authentication support as moderate" do
    evidence = exact_ip_evidence(public_ip(ip: "8.8.8.8"))

    result = described_class.score_with_breakdown(evidence)

    expect(result[:score]).to eq(26)
    expect(result[:breakdown].map { |entry| entry["key"] }).to eq(["v3_exact_public_ip"])
    expect(described_class.confidence(result[:score])).to eq("moderate")
    expect(described_class.store_candidate?(result[:score], evidence)).to eq(true)
  end

  it "keeps exact non-public overlap visible without treating it as identity weight" do
    evidence = {
      "shared_exact_ip_count" => 1,
      "registration_delta_minutes" => 10,
      "shared_ip_details" => [
        {
          "ip_address" => "10.0.0.50",
          "public" => false,
          "user_count" => 2,
          "sources_a" => ["registration"],
          "sources_b" => ["registration"],
        },
      ],
    }

    expect(described_class.score(evidence)).to eq(0)
    expect(described_class.confidence(0)).to eq("weak")
    expect(described_class.store_candidate?(0, evidence)).to eq(true)
  end

  it "treats two distinct rare public IP overlaps as strong network evidence without making them very strong by themselves" do
    evidence = exact_ip_evidence(
      public_ip(ip: "8.8.8.8"),
      public_ip(ip: "1.1.1.1"),
    )

    score = described_class.score(evidence)

    expect(score).to eq(45)
    expect(described_class.confidence(score)).to eq("strong")
  end

  it "uses temporal IP commonness so a historically reused address can still be distinctive near the overlap" do
    base = exact_ip_evidence(public_ip(ip: "8.8.8.8", users: 20))
    locally_distinctive = base.merge(
      "temporal_ip_details" => [
        {
          "ip_address" => "8.8.8.8",
          "closest_gap_seconds" => 1.hour.to_i,
          "temporal_population_complete" => true,
          "temporal_population_users_24h" => 2,
          "temporal_population_users_7d" => 2,
          "temporal_population_users_30d" => 3,
        },
      ],
      "auth_proximity_details" => [
        {
          "ip_address" => "8.8.8.8",
          "public" => true,
          "closest_gap_seconds" => 1.hour.to_i,
        },
      ],
      "auth_proximity_public_ip_within_24h_count" => 1,
    )

    expect(described_class.score(locally_distinctive)).to be > described_class.score(base)
    expect(described_class.score(locally_distinctive)).to be >= 30
  end

  it "reduces exact-IP weight smoothly as an address is shared by more accounts" do
    rare = exact_ip_evidence(public_ip(ip: "8.8.8.8", users: 2))
    shared = exact_ip_evidence(public_ip(ip: "8.8.8.8", users: 5))
    common = exact_ip_evidence(public_ip(ip: "8.8.8.8", users: 20))

    expect(described_class.score(rare)).to be > described_class.score(shared)
    expect(described_class.score(shared)).to be > described_class.score(common)
    expect(described_class.confidence(described_class.score(shared))).to eq("weak")
  end

  it "weights Tor hosting and mobile context inside the exact-IP group instead of applying unrelated global penalties" do
    ordinary = exact_ip_evidence(public_ip(ip: "8.8.8.8"))
    tor = exact_ip_evidence(public_ip(ip: "8.8.8.8", tor: true))
    hosting = exact_ip_evidence(public_ip(ip: "8.8.8.8", hosting: true))
    mobile = exact_ip_evidence(public_ip(ip: "8.8.8.8", mobile: true))

    expect(described_class.score(tor)).to be < described_class.score(hosting)
    expect(described_class.score(hosting)).to be < described_class.score(mobile)
    expect(described_class.score(mobile)).to be < described_class.score(ordinary)
    expect(described_class.store_candidate?(described_class.score(tor), tor)).to eq(true)
  end

  it "uses only the strongest login-proximity bucket plus a small bounded repeat bonus" do
    base = exact_ip_evidence(public_ip(ip: "8.8.8.8"))
    score_for_gap = lambda do |seconds, repeat_count = 1|
      evidence = base.merge(
        "auth_proximity_details" => [
          { "ip_address" => "8.8.8.8", "public" => true, "closest_gap_seconds" => seconds },
        ],
        "auth_proximity_public_ip_within_24h_count" => repeat_count,
      )
      result = described_class.score_with_breakdown(evidence)
      result[:breakdown].find { |entry| entry["key"] == "v3_temporal_proximity" }&.fetch("points", 0).to_i
    end

    expect(score_for_gap.call(5.minutes.to_i)).to eq(10)
    expect(score_for_gap.call(30.minutes.to_i)).to eq(9)
    expect(score_for_gap.call(1.hour.to_i)).to eq(8)
    expect(score_for_gap.call(6.hours.to_i)).to eq(7)
    expect(score_for_gap.call(24.hours.to_i)).to eq(5)
    expect(score_for_gap.call(72.hours.to_i)).to eq(3)
    expect(score_for_gap.call(7.days.to_i)).to eq(2)
    expect(score_for_gap.call(8.days.to_i)).to eq(0)
    expect(score_for_gap.call(1.hour.to_i, 20)).to be <= described_class::GROUP_CAPS[:temporal_proximity]
  end

  it "keeps a direct A to B transition score-relevant beyond seven days with deliberate time decay" do
    base = exact_ip_evidence(
      public_ip(ip: "8.8.8.8"),
      public_ip(ip: "1.1.1.1"),
    ).merge("public_ip_transition_population_complete" => true)

    transition_points = lambda do |gap|
      evidence = base.merge(
        "public_ip_transition_details" => [
          {
            "from_ip" => "8.8.8.8",
            "to_ip" => "1.1.1.1",
            "closest_transition_gap_seconds" => gap,
            "transition_population_complete" => true,
            "transition_user_count" => 2,
            "transition_user_count_24h" => gap <= 1.day.to_i ? 2 : nil,
            "transition_user_count_7d" => gap <= 7.days.to_i ? 2 : nil,
          }.compact,
        ],
      )
      described_class.score_with_breakdown(evidence)[:breakdown]
        .find { |entry| entry["key"] == "v3_public_ip_transitions" }&.fetch("points", 0).to_i
    end

    expect(transition_points.call(12.hours.to_i)).to be > transition_points.call(20.days.to_i)
    expect(transition_points.call(20.days.to_i)).to be > transition_points.call(120.days.to_i)
    expect(transition_points.call(120.days.to_i)).to be > 0
    expect(transition_points.call(181.days.to_i)).to eq(0)
  end

  it "does not downweight a rare direct A to B sequence a second time merely because both endpoints were historically common" do
    transition = {
      "public_ip_transition_population_complete" => true,
      "public_ip_transition_details" => [
        {
          "from_ip" => "8.8.8.8",
          "to_ip" => "1.1.1.1",
          "closest_transition_gap_seconds" => 12.hours.to_i,
          "transition_population_complete" => true,
          "transition_user_count" => 2,
          "transition_user_count_24h" => 2,
          "transition_user_count_7d" => 2,
        },
      ],
    }
    rare_endpoints = exact_ip_evidence(
      public_ip(ip: "8.8.8.8", users: 2),
      public_ip(ip: "1.1.1.1", users: 2),
    ).merge(transition)
    common_endpoints = exact_ip_evidence(
      public_ip(ip: "8.8.8.8", users: 20),
      public_ip(ip: "1.1.1.1", users: 20),
    ).merge(transition)

    transition_points = lambda do |evidence|
      described_class.score_with_breakdown(evidence)[:breakdown]
        .find { |entry| entry["key"] == "v3_public_ip_transitions" }&.fetch("points", 0).to_i
    end

    expect(transition_points.call(common_endpoints)).to eq(transition_points.call(rare_endpoints))
    expect(described_class.confidence(described_class.score(common_endpoints))).to eq("moderate")
  end

  it "reduces transition weight when the same A to B pattern is common in the local population" do
    base = exact_ip_evidence(
      public_ip(ip: "8.8.8.8"),
      public_ip(ip: "1.1.1.1"),
    ).merge("public_ip_transition_population_complete" => true)

    build = lambda do |users|
      base.merge(
        "public_ip_transition_details" => [
          {
            "from_ip" => "8.8.8.8",
            "to_ip" => "1.1.1.1",
            "closest_transition_gap_seconds" => 12.hours.to_i,
            "transition_population_complete" => true,
            "transition_user_count" => users,
            "transition_user_count_24h" => users,
            "transition_user_count_7d" => users,
          },
        ],
      )
    end

    expect(described_class.score(build.call(2))).to be > described_class.score(build.call(10))
  end

  it "treats two rare public IPs plus a closely aligned transition as strong and independent browser continuity as very strong" do
    evidence = exact_ip_evidence(
      public_ip(ip: "8.8.8.8"),
      public_ip(ip: "1.1.1.1"),
    ).merge(
      "public_ip_transition_population_complete" => true,
      "public_ip_transition_details" => [
        {
          "from_ip" => "8.8.8.8",
          "to_ip" => "1.1.1.1",
          "closest_transition_gap_seconds" => 12.hours.to_i,
          "transition_population_complete" => true,
          "transition_user_count" => 2,
          "transition_user_count_24h" => 2,
          "transition_user_count_7d" => 2,
        },
      ],
    )

    expect(described_class.score(evidence)).to eq(63)
    expect(described_class.confidence(described_class.score(evidence))).to eq("strong")

    with_browser = evidence.merge(
      "browser_continuity_count" => 1,
      "max_browser_continuity_users" => 2,
    )
    expect(described_class.score(with_browser)).to eq(88)
    expect(described_class.confidence(described_class.score(with_browser))).to eq("very_strong")
  end

  it "uses browser continuity only as positive supplemental evidence and never creates a candidate from it alone" do
    browser_only = {
      "browser_continuity_count" => 1,
      "max_browser_continuity_users" => 2,
      "registration_delta_minutes" => 5,
    }

    score = described_class.score(browser_only)

    expect(score).to eq(25)
    expect(described_class.confidence(score)).to eq("moderate")
    expect(described_class.store_candidate?(score, browser_only)).to eq(false)
    expect(described_class.score(browser_only.except("browser_continuity_count", "max_browser_continuity_users"))).to eq(0)
  end

  it "commonness-corrects the unified client-signature group and treats incomplete population data conservatively" do
    rare_complete = {
      "client_signature_group_count" => 1,
      "max_client_signature_group_users" => 2,
      "client_signature_population_complete" => true,
    }
    common_complete = rare_complete.merge("max_client_signature_group_users" => 10)
    incomplete = rare_complete.merge("client_signature_population_complete" => false)

    expect(described_class.score(rare_complete)).to eq(6)
    expect(described_class.score(common_complete)).to be < described_class.score(rare_complete)
    expect(described_class.score(incomplete)).to be < described_class.score(rare_complete)
  end

  it "does not double-count IPv4 /32 shared-network evidence but can use an independent IPv6 prefix weakly" do
    ipv4 = {
      "shared_independent_network_count" => 1,
      "shared_independent_networks" => ["8.8.8.8/32"],
      "max_independent_shared_network_users" => 2,
    }
    ipv6 = ipv4.merge("shared_independent_networks" => ["2001:db8::/64"])

    expect(described_class.score(ipv4)).to eq(0)
    expect(described_class.score(ipv6)).to eq(4)
  end

  it "uses registration timing only as a small corroborating signal" do
    timing_only = { "registration_delta_minutes" => 10 }
    with_primary = timing_only.merge(
      "client_signature_group_count" => 1,
      "max_client_signature_group_users" => 2,
      "client_signature_population_complete" => true,
    )

    expect(described_class.score(timing_only)).to eq(0)
    breakdown = described_class.score_with_breakdown(with_primary)[:breakdown]
    expect(breakdown.find { |entry| entry["key"] == "v3_registration_timing" }["points"]).to eq(5)
  end

  it "prevents a pile-up of partly overlapping network signals from reaching very strong without independent or exceptional evidence" do
    evidence = exact_ip_evidence(
      public_ip(ip: "8.8.8.8"),
      public_ip(ip: "1.1.1.1"),
      public_ip(ip: "9.9.9.9"),
    ).merge(
      "auth_proximity_details" => [
        { "ip_address" => "8.8.8.8", "public" => true, "closest_gap_seconds" => 5.minutes.to_i },
      ],
      "auth_proximity_public_ip_within_24h_count" => 8,
      "public_ip_transition_population_complete" => true,
      "public_ip_transition_details" => [
        {
          "from_ip" => "8.8.8.8",
          "to_ip" => "1.1.1.1",
          "closest_transition_gap_seconds" => 20.days.to_i,
          "transition_population_complete" => true,
          "transition_user_count" => 2,
        },
      ],
      "client_signature_group_count" => 1,
      "max_client_signature_group_users" => 2,
      "client_signature_population_complete" => true,
      "registration_delta_minutes" => 30,
    )

    result = described_class.score_with_breakdown(evidence)

    expect(result[:score]).to eq(69)
    expect(described_class.confidence(result[:score])).to eq("strong")
    guardrail = result[:breakdown].find { |entry| entry["key"] == "v3_very_strong_guardrail" }
    expect(guardrail).to be_present
    expect(guardrail["points"]).to be < 0
  end

  it "uses the v3 confidence bands" do
    expect(described_class.confidence(24)).to eq("weak")
    expect(described_class.confidence(25)).to eq("moderate")
    expect(described_class.confidence(44)).to eq("moderate")
    expect(described_class.confidence(45)).to eq("strong")
    expect(described_class.confidence(69)).to eq("strong")
    expect(described_class.confidence(70)).to eq("very_strong")
  end

  it "does not score the legacy overlapping network and signature counters in addition to their v3-ready groups" do
    base = exact_ip_evidence(public_ip(ip: "8.8.8.8"))
    legacy_noise = base.merge(
      "shared_network_count" => 8,
      "shared_session_signature_count" => 8,
      "repeated_shared_session_signature_count" => 8,
    )

    expect(described_class.score(legacy_noise)).to eq(described_class.score(base))
  end
end
