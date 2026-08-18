# frozen_string_literal: true

require "digest"
require "set"

module ::AccountSecurity
  module AccountGroupBuilder
    module_function

    MIN_GROUP_USERS = 3
    MAX_GROUP_USERS = AccountCorrelationScanner::MAX_GROUP_USERS
    MAX_SOURCE_PAIRS = AccountCorrelationScanner::MAX_PAIR_CANDIDATES
    MAX_ANCHORS = 6
    EXCLUDED_EDGE_STATUSES = %w[expected_shared_network dismissed].freeze
    CONFIDENCE_RANK = {
      "weak" => 0,
      "moderate" => 1,
      "strong" => 2,
      "very_strong" => 3,
    }.freeze

    def build_index(scope: nil)
      rows, source_pair_limit_reached = load_rows(scope: scope)
      return empty_index.merge(source_pair_limit_reached: source_pair_limit_reached) if rows.blank?

      parent = {}
      rank = Hash.new(0)
      eligible_pair_ids = Set.new

      rows.each do |row|
        next unless eligible_edge?(row)

        a = row[:user_a_id]
        b = row[:user_b_id]
        next if a <= 0 || b <= 0 || a == b

        parent[a] ||= a
        parent[b] ||= b
        union!(parent, rank, a, b)
        eligible_pair_ids << row[:id]
      end

      components = Hash.new { |hash, key| hash[key] = Set.new }
      parent.keys.each { |user_id| components[find_root!(parent, user_id)] << user_id }

      groups = components.values.filter_map do |members|
        next if members.length < MIN_GROUP_USERS || members.length > MAX_GROUP_USERS

        build_group(members, rows, eligible_pair_ids)
      end

      groups.sort_by! { |group| [-group[:account_count], -group[:relation_count], -group[:max_score], group[:key]] }
      pair_to_group = {}
      groups.each { |group| group[:pair_ids].each { |pair_id| pair_to_group[pair_id] ||= group[:key] } }

      {
        groups: groups,
        groups_by_key: groups.index_by { |group| group[:key] },
        pair_to_group: pair_to_group,
        source_pair_limit_reached: source_pair_limit_reached,
      }
    rescue StandardError => e
      Rails.logger.warn("[account_security] account group derivation failed class=#{e.class}")
      empty_index
    end

    def load_rows(scope: nil)
      relation = scope || AccountCorrelation.all
      raw_rows =
        relation
          .reorder(last_seen_at: :desc, id: :desc)
          .limit(MAX_SOURCE_PAIRS + 1)
          .pluck(:id, :user_a_id, :user_b_id, :score, :confidence, :status, :evidence)
      source_pair_limit_reached = raw_rows.length > MAX_SOURCE_PAIRS
      rows = raw_rows.first(MAX_SOURCE_PAIRS).filter_map do |id, user_a_id, user_b_id, score, confidence, status, evidence|
        next unless evidence.is_a?(Hash)

        {
          id: id.to_i,
          user_a_id: user_a_id.to_i,
          user_b_id: user_b_id.to_i,
          score: score.to_i,
          confidence: confidence.to_s,
          status: status.to_s,
          evidence: evidence,
        }
      end

      [rows, source_pair_limit_reached]
    end

    def eligible_edge?(row)
      return false if EXCLUDED_EDGE_STATUSES.include?(row[:status])

      evidence = row[:evidence]
      exact_count = evidence["shared_exact_ip_count"].to_i
      network_count = evidence["shared_network_count"].to_i

      evidence["shared_public_ip_count"].to_i.positive? ||
        evidence["shared_registration_ip"] == true ||
        exact_count >= 2 ||
        (exact_count.positive? && evidence["shared_auth_ip_count"].to_i.positive?) ||
        (exact_count.positive? && evidence["browser_continuity_count"].to_i.positive?) ||
        (network_count.positive? && evidence["shared_session_signature_count"].to_i.positive?)
    end

    def build_group(members, rows, eligible_pair_ids)
      member_ids = members.to_a.sort
      member_set = member_ids.to_set
      relations = rows.select do |row|
        member_set.include?(row[:user_a_id]) && member_set.include?(row[:user_b_id])
      end
      return nil if relations.blank?

      eligible_relations = relations.select { |row| eligible_pair_ids.include?(row[:id]) }
      return nil if eligible_relations.length < member_ids.length - 1

      possible = member_ids.length * (member_ids.length - 1) / 2
      status_counts = Hash.new(0)
      relations.each { |row| status_counts[row[:status]] += 1 }

      account_degrees = Hash.new(0)
      anchors = {}
      evidence_counts = {
        public_ip_pairs: 0,
        registration_ip_pairs: 0,
        authentication_ip_pairs: 0,
        browser_continuity_pairs: 0,
        session_signature_pairs: 0,
        repeated_session_signature_pairs: 0,
        browser_continuity_repeated_pairs: 0,
        temporal_24h_pairs: 0,
        auth_proximity_pairs: 0,
        auth_same_client_proximity_pairs: 0,
        public_transition_pairs: 0,
      }

      eligible_relations.each do |row|
        account_degrees[row[:user_a_id]] += 1
        account_degrees[row[:user_b_id]] += 1
        evidence = row[:evidence]

        evidence_counts[:public_ip_pairs] += 1 if evidence["shared_public_ip_count"].to_i.positive?
        evidence_counts[:registration_ip_pairs] += 1 if evidence["shared_registration_ip"] == true
        evidence_counts[:authentication_ip_pairs] += 1 if evidence["shared_auth_ip_count"].to_i.positive?
        evidence_counts[:browser_continuity_pairs] += 1 if evidence["browser_continuity_count"].to_i.positive?
        evidence_counts[:session_signature_pairs] += 1 if evidence["shared_session_signature_count"].to_i.positive?
        evidence_counts[:repeated_session_signature_pairs] += 1 if evidence["repeated_shared_session_signature_count"].to_i.positive?
        evidence_counts[:browser_continuity_repeated_pairs] += 1 if evidence["repeated_browser_continuity_count"].to_i.positive?
        evidence_counts[:temporal_24h_pairs] += 1 if evidence["temporal_within_24h_count"].to_i.positive?
        evidence_counts[:auth_proximity_pairs] += 1 if evidence["auth_proximity_within_7d_count"].to_i.positive?
        evidence_counts[:auth_same_client_proximity_pairs] += 1 if evidence["auth_proximity_same_client_within_30m_count"].to_i.positive?
        evidence_counts[:public_transition_pairs] += 1 if evidence["public_ip_transition_pattern_count"].to_i.positive?

        collect_anchors!(anchors, row)
      end

      scores = eligible_relations.map { |row| row[:score] }
      strongest_confidence =
        eligible_relations
          .map { |row| row[:confidence] }
          .max_by { |value| CONFIDENCE_RANK.fetch(value, -1) }
      common_anchors = anchors.values.select { |anchor| anchor[:account_ids].length >= 3 }
      top_anchors =
        (common_anchors.presence || anchors.values)
          .sort_by do |anchor|
            [-anchor[:account_ids].length, anchor[:public] ? 0 : 1, -anchor[:pair_count], anchor[:ip_address]]
          end
          .first(MAX_ANCHORS)
          .map { |anchor| serialize_anchor(anchor) }

      {
        key: group_key(member_ids),
        user_ids: member_ids,
        account_count: member_ids.length,
        pair_ids: relations.map { |row| row[:id] },
        pair_record_count: relations.length,
        relation_count: eligible_relations.length,
        active_relation_count: eligible_relations.length,
        possible_relation_count: possible,
        coverage_percent: possible.positive? ? ((eligible_relations.length.to_f / possible) * 100).round : 0,
        min_score: scores.min.to_i,
        max_score: scores.max.to_i,
        strongest_confidence: strongest_confidence.presence || "weak",
        status_counts: AccountCorrelation::STATUSES.index_with { |status| status_counts[status].to_i },
        account_degrees: member_ids.index_with { |user_id| account_degrees[user_id].to_i },
        evidence_counts: evidence_counts,
        anchors: top_anchors,
        shared_anchor_count: common_anchors.length,
        derived: true,
      }
    end

    def collect_anchors!(anchors, row)
      Array(row[:evidence]["shared_ip_details"]).each do |detail|
        next unless detail.is_a?(Hash)

        ip = IpNormalizer.normalize(detail["ip_address"])
        next if ip.blank?

        anchor = anchors[ip] ||= {
          ip_address: ip,
          account_ids: Set.new,
          pair_count: 0,
          public: detail["public"] == true,
          trusted: detail["trusted"] == true,
          tor: detail["tor"] == true,
          hosting: detail["hosting"] == true,
          mobile: detail["mobile"] == true,
        }
        anchor[:account_ids] << row[:user_a_id]
        anchor[:account_ids] << row[:user_b_id]
        anchor[:pair_count] += 1
        anchor[:public] ||= detail["public"] == true
        anchor[:trusted] ||= detail["trusted"] == true
        anchor[:tor] ||= detail["tor"] == true
        anchor[:hosting] ||= detail["hosting"] == true
        anchor[:mobile] ||= detail["mobile"] == true
      end
    end

    def serialize_anchor(anchor)
      {
        ip_address: anchor[:ip_address],
        account_ids: anchor[:account_ids].to_a.sort,
        account_count: anchor[:account_ids].length,
        pair_count: anchor[:pair_count].to_i,
        public: anchor[:public] == true,
        trusted: anchor[:trusted] == true,
        tor: anchor[:tor] == true,
        hosting: anchor[:hosting] == true,
        mobile: anchor[:mobile] == true,
      }
    end

    def group_key(user_ids)
      "ag-#{Digest::SHA256.hexdigest(user_ids.join(","))[0, 16]}"
    end

    def find_root!(parent, value)
      parent[value] ||= value
      parent[value] = find_root!(parent, parent[value]) if parent[value] != value
      parent[value]
    end

    def union!(parent, rank, first, second)
      root_a = find_root!(parent, first)
      root_b = find_root!(parent, second)
      return if root_a == root_b

      if rank[root_a] < rank[root_b]
        parent[root_a] = root_b
      elsif rank[root_a] > rank[root_b]
        parent[root_b] = root_a
      else
        parent[root_b] = root_a
        rank[root_a] += 1
      end
    end

    def empty_index
      { groups: [], groups_by_key: {}, pair_to_group: {}, source_pair_limit_reached: false }
    end
  end
end
