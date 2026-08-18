# frozen_string_literal: true

require "rails_helper"

RSpec.describe AccountSecurity::AccountCorrelationScanner do
  before do
    SiteSetting.account_security_enabled = true
    SiteSetting.account_security_account_correlation_enabled = true
    SiteSetting.account_security_browser_continuity_enabled = true
    Discourse.redis.del(described_class::STATUS_KEY)
    Discourse.redis.del(described_class::LAST_SUCCESS_KEY)
    Discourse.redis.del(described_class::LAST_FAILURE_KEY)
  end

  after do
    Discourse.redis.del(described_class::STATUS_KEY)
    Discourse.redis.del(described_class::LAST_SUCCESS_KEY)
    Discourse.redis.del(described_class::LAST_FAILURE_KEY)
  end

  it "builds each exact registration-IP pair only once" do
    users = Array.new(3) { Fabricate(:user) }
    users.each do |user|
      user.update_columns(registration_ip_address: "8.8.8.8", ip_address: "8.8.8.8")
    end

    pairs, truncated, _index, _context, _temporal_index, diagnostics = described_class.candidate_pairs

    expect(truncated).to eq(false)
    expect(pairs.sort).to eq(users.map(&:id).sort.combination(2).to_a.sort)
    expect(diagnostics[:exact_ip_pairs_generated]).to eq(3)
  end

  it "does not discard exact non-public registration-IP overlap" do
    users = Array.new(5) { Fabricate(:user) }
    users.each { |user| user.update_columns(registration_ip_address: "10.0.0.25") }

    pairs, _truncated, _index, _context, _temporal_index, diagnostics = described_class.candidate_pairs

    expect(pairs.sort).to eq(users.map(&:id).sort.combination(2).to_a.sort)
    expect(diagnostics[:nonpublic_ip_groups]).to be >= 1
  end

  it "uses Discourse core user IP history when generating existing-account candidates" do
    user_a = Fabricate(:user)
    user_b = Fabricate(:user)
    UserIpAddressHistory.create!(user_id: user_a.id, ip_address: "1.1.1.1")
    UserIpAddressHistory.create!(user_id: user_b.id, ip_address: "1.1.1.1")

    pairs, _truncated, _index, _context, _temporal_index, diagnostics = described_class.candidate_pairs

    expect(pairs).to include([user_a.id, user_b.id].sort)
    expect(diagnostics[:history_rows]).to be >= 2
  end

  it "does not expand exact-IP groups beyond the safety cap" do
    users = Array.new(described_class::MAX_GROUP_USERS + 1) { Fabricate(:user) }
    users.each { |user| user.update_columns(registration_ip_address: "8.8.4.4") }

    pairs, _truncated, _index, _context, _temporal_index, diagnostics = described_class.candidate_pairs

    expect(pairs).to be_empty
    expect(diagnostics[:large_ip_groups_skipped]).to be >= 1
  end
  it "does not generate a candidate pair from browser continuity alone" do
    user_a = Fabricate(:user)
    user_b = Fabricate(:user)
    user_a.update_columns(registration_ip_address: "1.1.1.1", ip_address: "1.1.1.1")
    user_b.update_columns(registration_ip_address: "8.8.8.8", ip_address: "8.8.8.8")
    token_hash = AccountSecurity::BrowserContinuityRecorder.token_hash("C" * 43)
    now = Time.zone.now
    AccountSecurity::BrowserContinuity.create!(user_id: user_a.id, token_hash: token_hash, first_seen_at: now, last_seen_at: now, observation_count: 1)
    AccountSecurity::BrowserContinuity.create!(user_id: user_b.id, token_hash: token_hash, first_seen_at: now, last_seen_at: now, observation_count: 1)

    pairs, _truncated, _index, _context, _temporal_index, _diagnostics = described_class.candidate_pairs

    expect(pairs).not_to include([user_a.id, user_b.id].sort)
  end

  it "includes existing correlation rows in full scans so scoring upgrades are persisted" do
    user_a = Fabricate(:user)
    user_b = Fabricate(:user)
    correlation = AccountSecurity::AccountCorrelation.create!(
      user_a_id: [user_a.id, user_b.id].min,
      user_b_id: [user_a.id, user_b.id].max,
      score: 1,
      confidence: "weak",
      status: "open",
      evidence: {},
      first_seen_at: Time.zone.now,
      last_seen_at: Time.zone.now,
    )

    pairs, _truncated, _index, _context, _temporal_index, diagnostics = described_class.candidate_pairs

    expect(pairs).to include([correlation.user_a_id, correlation.user_b_id])
    expect(diagnostics[:existing_pairs_added]).to be >= 1
  end


  it "rescans every persisted correlation even when new-pair discovery is truncated" do
    existing_a = Fabricate(:user)
    existing_b = Fabricate(:user)
    discovery_a = Fabricate(:user)
    discovery_b = Fabricate(:user)
    now = Time.zone.now
    AccountSecurity::AccountCorrelation.create!(
      user_a_id: [existing_a.id, existing_b.id].min,
      user_b_id: [existing_a.id, existing_b.id].max,
      score: 50,
      confidence: "strong",
      status: "open",
      evidence: {},
      first_seen_at: now,
      last_seen_at: now,
    )

    exact_index = instance_double(AccountSecurity::CoreIpEvidence::ScanIndex, diagnostics: { auth_log_truncated: false })
    allow(exact_index).to receive(:shared_details).and_return([])
    scan_context = instance_double(AccountSecurity::AccountCorrelationScanContext)
    allow(scan_context).to receive(:evidence_for_pair).and_return({})
    temporal_index = instance_double(AccountSecurity::TemporalCorrelationEvidence::ScanIndex)
    allow(temporal_index).to receive(:evidence_for_pair).and_return(AccountSecurity::TemporalCorrelationEvidence.empty_evidence)
    allow(described_class).to receive(:build_discovery_context).and_return(
      [
        [[discovery_a.id, discovery_b.id].sort],
        true,
        exact_index,
        scan_context,
        temporal_index,
        { discovery_pairs_selected: 1, discovery_truncated: true },
      ],
    )
    allow(AccountSecurity::SessionSignatureRecorder).to receive(:backfill_active_tokens!).and_return(0)
    allow(AccountSecurity::Statistics).to receive(:increment!)

    seen_pairs = []
    allow(AccountSecurity::AccountCorrelationService).to receive(:recalculate_pair_with_result!) do |a, b, **_kwargs|
      pair = [a, b].sort
      seen_pairs << pair
      outcome = pair == [existing_a.id, existing_b.id].sort ? "updated" : "created"
      AccountSecurity::AccountCorrelationService::RecalculationResult.new(outcome: outcome, candidate_now: true)
    end

    scan = described_class.run!(source: "manual")

    expect(seen_pairs).to include([existing_a.id, existing_b.id].sort)
    expect(seen_pairs).to include([discovery_a.id, discovery_b.id].sort)
    expect(scan[:truncated]).to eq(true)
    expect(scan[:existing_pairs_processed]).to eq(1)
    expect(scan[:discovery_pairs_processed]).to eq(1)
    expect(scan[:new_candidates]).to eq(1)
    expect(scan[:existing_candidates_updated]).to eq(1)
    expect(scan.dig(:diagnostics, :existing_pairs_total)).to eq(1)
    expect(described_class.health_history[:last_success_at]).to be_present
  end

  it "recovers a stale running status instead of blocking scans for the status TTL" do
    old_time = (described_class::STALE_STATUS_AFTER + 1.minute).seconds.ago.iso8601
    Discourse.redis.set(
      described_class::STATUS_KEY,
      {
        state: "running",
        started_at: old_time,
        heartbeat_at: old_time,
        source: "manual",
      }.to_json,
      ex: described_class::STATUS_TTL,
    )

    scan = described_class.status

    expect(scan[:state]).to eq("failed")
    expect(scan[:error_code]).to eq("scan_stale")
    expect(scan[:stale_recovered]).to eq(true)
    expect(scan[:completed_at]).to be_present
    expect(described_class.health_history[:last_failure_at]).to be_present
  end

end
