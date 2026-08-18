# frozen_string_literal: true

require "set"

module ::AccountSecurity
  module SharedIpGroupBuilder
    module_function

    MIN_USERS = 2
    MAX_ACCOUNT_PREVIEW = 100
    MAX_PAIR_PREVIEW = 20
    MAX_FILTER_PAIR_ROWS = AccountCorrelationScanner::MAX_PAIR_CANDIDATES

    def build(page:, per_page:, correlation_scope:, search_user_ids: nil, pair_filters_applied: false)
      index = CoreIpEvidence.build_scan_index
      groups = index.shared_ip_groups(min_users: MIN_USERS)

      if search_user_ids
        ids = search_user_ids.to_set
        groups.select! { |group| group[:accounts].any? { |account| ids.include?(account[:user_id]) } }
      end

      filter_truncated = false
      if pair_filters_applied
        qualifying_ips, filter_truncated = qualifying_ips_for(correlation_scope)
        groups.select! { |group| qualifying_ips.include?(group[:ip_address]) }
      end

      total = groups.length
      max_page = [(total.to_f / per_page).ceil, 1].max
      page = page.to_i.clamp(1, max_page)
      selected = groups.slice((page - 1) * per_page, per_page) || []
      selected_ips = selected.map { |group| group[:ip_address] }.to_set
      pair_rows, pair_preview_truncated = pair_rows_for(correlation_scope, selected_ips)

      {
        page: page,
        per_page: per_page,
        total: total,
        groups: selected.map { |group| enrich_group(group, pair_rows) },
        source_complete: index.source_complete?,
        diagnostics: index.diagnostics.slice(:auth_log_truncated, :session_observation_truncated),
        filter_truncated: filter_truncated,
        pair_preview_truncated: pair_preview_truncated,
      }
    end

    def qualifying_ips_for(scope)
      rows = scope.reorder(last_seen_at: :desc, id: :desc).limit(MAX_FILTER_PAIR_ROWS + 1).pluck(:evidence)
      truncated = rows.length > MAX_FILTER_PAIR_ROWS
      rows = rows.first(MAX_FILTER_PAIR_ROWS)
      ips = Set.new
      rows.each do |evidence|
        next unless evidence.is_a?(Hash)
        Array(evidence["shared_ip_details"]).each do |detail|
          next unless detail.is_a?(Hash)
          ip = IpNormalizer.normalize(detail["ip_address"])
          ips << ip if ip.present?
        end
      end
      [ips, truncated]
    end

    def pair_rows_for(scope, selected_ips)
      return [[], false] if selected_ips.empty?

      rows =
        scope
          .reorder(score: :desc, last_seen_at: :desc, id: :desc)
          .limit(MAX_FILTER_PAIR_ROWS + 1)
          .pluck(:id, :user_a_id, :user_b_id, :score, :confidence, :status, :evidence)
      truncated = rows.length > MAX_FILTER_PAIR_ROWS
      rows = rows.first(MAX_FILTER_PAIR_ROWS)
      relevant = rows.filter_map do |id, user_a_id, user_b_id, score, confidence, status, evidence|
        next unless evidence.is_a?(Hash)
        matching = Array(evidence["shared_ip_details"]).filter_map do |detail|
          next unless detail.is_a?(Hash)
          ip = IpNormalizer.normalize(detail["ip_address"])
          ip if ip.present? && selected_ips.include?(ip)
        end.uniq
        next if matching.empty?

        {
          id: id.to_i,
          user_a_id: user_a_id.to_i,
          user_b_id: user_b_id.to_i,
          score: score.to_i,
          confidence: confidence.to_s,
          status: status.to_s,
          evidence: evidence,
          ips: matching,
        }
      end
      [relevant, truncated]
    end

    def enrich_group(group, pair_rows)
      ip = group[:ip_address]
      pairs = pair_rows.select { |row| row[:ips].include?(ip) }
      context = CoreIpEvidence.context_for(ip)
      account_rows = group[:accounts]
      account_ids = account_rows.map { |row| row[:user_id] }
      users = User.where(id: account_ids.first(MAX_ACCOUNT_PREVIEW)).index_by(&:id)
      sources_by_id = account_rows.index_by { |row| row[:user_id] }

      registration_count = account_rows.count { |row| row[:sources].include?("registration") }
      auth_count = account_rows.count do |row|
        (row[:sources] & %w[auth_session active_session session_observation]).any?
      end
      temporal_count = pairs.count do |row|
        Array(row[:evidence]["temporal_ip_details"]).any? do |detail|
          detail.is_a?(Hash) &&
            IpNormalizer.normalize(detail["ip_address"]) == ip &&
            detail["closest_gap_seconds"].to_i <= 86_400
        end
      end

      {
        ip_address: ip,
        account_count: group[:account_count].to_i,
        accounts_truncated: account_ids.length > MAX_ACCOUNT_PREVIEW,
        accounts: account_ids.first(MAX_ACCOUNT_PREVIEW).filter_map do |user_id|
          user = users[user_id]
          next unless user
          { user: user, sources: Array(sources_by_id.dig(user_id, :sources)) }
        end,
        pair_count: pairs.length,
        pairs_truncated: pairs.length > MAX_PAIR_PREVIEW,
        pairs: pairs.first(MAX_PAIR_PREVIEW),
        max_score: pairs.map { |row| row[:score] }.max.to_i,
        registration_account_count: registration_count,
        auth_account_count: auth_count,
        temporal_aligned_pair_count: temporal_count,
        public: context[:public] == true,
        trusted: context[:trusted] == true,
        tor: context[:tor] == true,
        local_blacklist: context[:local_blacklist] == true,
        hosting: context[:hosting] == true,
        mobile: context[:mobile] == true,
        usage_type: context[:usage_type],
        isp: context[:isp],
      }
    end
  end
end
