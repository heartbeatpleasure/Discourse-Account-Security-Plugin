# frozen_string_literal: true

require "rails_helper"

RSpec.describe AccountSecurity::AccountGroupBuilder do
  fab!(:user_a) { Fabricate(:user) }
  fab!(:user_b) { Fabricate(:user) }
  fab!(:user_c) { Fabricate(:user) }

  def create_correlation(first, second, evidence:, score: 40, confidence: "moderate", status: "open")
    user_a_id, user_b_id = [first.id, second.id].sort
    AccountSecurity::AccountCorrelation.create!(
      user_a_id: user_a_id,
      user_b_id: user_b_id,
      score: score,
      confidence: confidence,
      status: status,
      evidence: evidence,
      first_seen_at: 1.hour.ago,
      last_seen_at: Time.zone.now,
    )
  end

  def public_ip_evidence(ip)
    {
      "shared_exact_ip_count" => 1,
      "shared_public_ip_count" => 1,
      "shared_ip_details" => [
        {
          "ip_address" => ip,
          "public" => true,
          "sources_a" => ["auth_session"],
          "sources_b" => ["auth_session"],
        },
      ],
    }
  end

  it "derives a multi-account group from connected direct pair evidence without inventing a group score" do
    pair_ab = create_correlation(user_a, user_b, evidence: public_ip_evidence("8.8.8.8"), score: 55, confidence: "strong")
    pair_bc = create_correlation(
      user_b,
      user_c,
      evidence: public_ip_evidence("1.1.1.1").merge("shared_registration_ip" => true),
      score: 45,
      confidence: "moderate",
    )

    index = described_class.build_index
    group = index[:groups].find { |candidate| candidate[:user_ids].sort == [user_a.id, user_b.id, user_c.id].sort }

    expect(group).to be_present
    expect(group[:account_count]).to eq(3)
    expect(group[:relation_count]).to eq(2)
    expect(group[:possible_relation_count]).to eq(3)
    expect(group[:coverage_percent]).to eq(67)
    expect(group[:min_score]).to eq(45)
    expect(group[:max_score]).to eq(55)
    expect(group[:strongest_confidence]).to eq("strong")
    expect(index[:pair_to_group][pair_ab.id]).to eq(group[:key])
    expect(index[:pair_to_group][pair_bc.id]).to eq(group[:key])
  end

  it "keeps non-group-forming pair records visible inside an already connected group without counting them as direct links" do
    pair_ab = create_correlation(user_a, user_b, evidence: public_ip_evidence("8.8.8.8"))
    pair_bc = create_correlation(user_b, user_c, evidence: public_ip_evidence("1.1.1.1"))
    pair_ac = create_correlation(
      user_a,
      user_c,
      evidence: public_ip_evidence("9.9.9.9"),
      status: "expected_shared_network",
      score: 10,
      confidence: "weak",
    )

    index = described_class.build_index
    group = index[:groups].find { |candidate| candidate[:user_ids].sort == [user_a.id, user_b.id, user_c.id].sort }

    expect(group[:relation_count]).to eq(2)
    expect(group[:pair_record_count]).to eq(3)
    expect(group[:pair_ids]).to contain_exactly(pair_ab.id, pair_bc.id, pair_ac.id)
    expect(group.dig(:status_counts, "expected_shared_network")).to eq(1)
  end

  it "does not create a three-account group when the only bridge was dismissed by staff" do
    create_correlation(user_a, user_b, evidence: public_ip_evidence("8.8.8.8"))
    create_correlation(
      user_b,
      user_c,
      evidence: public_ip_evidence("1.1.1.1"),
      status: "dismissed",
      score: 5,
      confidence: "weak",
    )

    index = described_class.build_index

    expect(index[:groups]).to be_empty
  end

  it "does not use browser continuity as a standalone group-forming edge" do
    browser_only = {
      "shared_exact_ip_count" => 0,
      "shared_public_ip_count" => 0,
      "browser_continuity_count" => 1,
    }
    create_correlation(user_a, user_b, evidence: browser_only, score: 20, confidence: "weak")
    create_correlation(user_b, user_c, evidence: browser_only, score: 20, confidence: "weak")

    expect(described_class.build_index[:groups]).to be_empty
  end

  it "summarizes recurring local correlation signals without making them new group-forming rules" do
    evidence = public_ip_evidence("8.8.8.8").merge(
      "repeated_shared_session_signature_count" => 1,
      "repeated_browser_continuity_count" => 1,
      "auth_proximity_within_30m_count" => 2,
      "auth_proximity_same_client_within_30m_count" => 1,
      "aligned_public_ip_transition_7d_count" => 1,
    )
    create_correlation(user_a, user_b, evidence: evidence)
    create_correlation(user_b, user_c, evidence: public_ip_evidence("1.1.1.1"))

    group = described_class.build_index[:groups].first

    expect(group.dig(:evidence_counts, :repeated_session_signature_pairs)).to eq(1)
    expect(group.dig(:evidence_counts, :browser_continuity_repeated_pairs)).to eq(1)
    expect(group.dig(:evidence_counts, :auth_proximity_pairs)).to eq(1)
    expect(group.dig(:evidence_counts, :auth_same_client_proximity_pairs)).to eq(1)
    expect(group.dig(:evidence_counts, :public_transition_pairs)).to eq(1)
    expect(group[:relation_count]).to eq(2)
  end

  it "groups three or more accounts around one exact shared registration IP" do
    evidence = public_ip_evidence("8.8.4.4").merge("shared_registration_ip" => true)
    create_correlation(user_a, user_b, evidence: evidence)
    create_correlation(user_a, user_c, evidence: evidence)
    create_correlation(user_b, user_c, evidence: evidence)

    group = described_class.build_index[:groups].first

    expect(group[:account_count]).to eq(3)
    expect(group[:relation_count]).to eq(3)
    expect(group[:coverage_percent]).to eq(100)
    expect(group[:anchors].first[:ip_address]).to eq("8.8.4.4")
    expect(group[:anchors].first[:account_count]).to eq(3)
  end
end
