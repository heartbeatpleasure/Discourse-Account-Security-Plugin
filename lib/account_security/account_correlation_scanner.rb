# frozen_string_literal: true

require "json"
require "set"

module ::AccountSecurity
  module AccountCorrelationScanner
    module_function

    STATUS_KEY = "account_security:correlation_scan:status"
    MAX_GROUP_USERS = 20
    MAX_PAIR_CANDIDATES = 20_000

    def enqueue!(requested_by_id: nil)
      return { success: false, error_code: "correlation_disabled", scan: status } unless enabled?

      DistributedMutex.synchronize("account-security-correlation-enqueue", validity: 10) do
        current = status
        if current[:state] == "running" || current[:state] == "queued"
          next { success: false, error_code: "scan_already_running", scan: current }
        end

        write_status(state: "queued", requested_by_id: requested_by_id, queued_at: Time.zone.now.iso8601)
        Jobs.enqueue(:account_security_rebuild_correlations, requested_by_id: requested_by_id)
        { success: true, scan: status }
      end
    end

    def run!(requested_by_id: nil)
      unless enabled?
        write_status(
          state: "disabled",
          requested_by_id: requested_by_id,
          completed_at: Time.zone.now.iso8601,
          error_code: "correlation_disabled",
        )
        return status
      end

      DistributedMutex.synchronize("account-security-correlation-scan", validity: 30.minutes.to_i) do
        started_at = Time.zone.now
        write_status(
          state: "running",
          requested_by_id: requested_by_id,
          started_at: started_at.iso8601,
          pairs_processed: 0,
          candidates_found: 0,
          token_signatures_backfilled: 0,
          truncated: false,
        )

        signature_count = SessionSignatureRecorder.backfill_active_tokens!
        pairs, truncated = candidate_pairs
        found = 0
        processed = 0

        pairs.each_slice(250) do |batch|
          batch.each do |user_a_id, user_b_id|
            processed += 1
            found += 1 if AccountCorrelationService.recalculate_pair!(
              user_a_id,
              user_b_id,
              observed_at: started_at,
              source: "backfill_scan",
            )
          end
          write_status(
            state: "running",
            requested_by_id: requested_by_id,
            started_at: started_at.iso8601,
            pairs_processed: processed,
            candidates_found: found,
            token_signatures_backfilled: signature_count,
            truncated: truncated,
          )
        end

        Statistics.increment!(correlation_scans: 1)
        write_status(
          state: "completed",
          requested_by_id: requested_by_id,
          started_at: started_at.iso8601,
          completed_at: Time.zone.now.iso8601,
          pairs_processed: processed,
          candidates_found: found,
          token_signatures_backfilled: signature_count,
          truncated: truncated,
        )
      end
      status
    rescue StandardError => e
      Rails.logger.warn("[account_security] account correlation scan failed class=#{e.class}")
      write_status(state: "failed", error_code: "scan_failed", completed_at: Time.zone.now.iso8601)
      status
    end

    def status
      raw = Discourse.redis.get(STATUS_KEY)
      return { state: "never" } if raw.blank?
      JSON.parse(raw, symbolize_names: true).slice(
        :state,
        :requested_by_id,
        :queued_at,
        :started_at,
        :completed_at,
        :pairs_processed,
        :candidates_found,
        :token_signatures_backfilled,
        :truncated,
        :error_code,
      )
    rescue JSON::ParserError, TypeError
      { state: "unknown" }
    end

    def candidate_pairs
      pairs = Set.new
      truncated = false
      cutoff = SessionSignatureRecorder.retention_cutoff

      collect_user_ip_groups!(pairs, :registration_ip_address)
      collect_user_ip_groups!(pairs, :ip_address)
      collect_network_groups!(pairs, UserNetwork.where("last_seen_at >= ?", cutoff), :network_key)
      collect_network_groups!(pairs, SessionSignature.where("last_seen_at >= ?", cutoff), :network_key)
      collect_signature_groups!(pairs, cutoff)

      if pairs.length > MAX_PAIR_CANDIDATES
        pairs = Set.new(pairs.to_a.first(MAX_PAIR_CANDIDATES))
        truncated = true
      end
      [pairs.to_a, truncated]
    end

    def collect_user_ip_groups!(pairs, column)
      scope = User.human_users.where(staged: false).where.not(column => nil)
      values = scope.group(column).having("COUNT(*) BETWEEN 2 AND ?", MAX_GROUP_USERS).pluck(column)
      values.each do |value|
        ip = IpNormalizer.normalize_public(value)
        next if ip.blank?
        ids = scope.where(column => ip).limit(MAX_GROUP_USERS).pluck(:id)
        add_pairs!(pairs, ids)
        break if pairs.length > MAX_PAIR_CANDIDATES
      end
    end

    def collect_network_groups!(pairs, scope, column)
      values = scope.group(column).having("COUNT(DISTINCT user_id) BETWEEN 2 AND ?", MAX_GROUP_USERS).pluck(column)
      values.each do |value|
        ids = scope.where(column => value).distinct.limit(MAX_GROUP_USERS).pluck(:user_id)
        add_pairs!(pairs, ids)
        break if pairs.length > MAX_PAIR_CANDIDATES
      end
    end

    def collect_signature_groups!(pairs, cutoff)
      scope = SessionSignature.where("last_seen_at >= ?", cutoff)
      values =
        scope
          .group(:network_key, :signature_hash)
          .having("COUNT(DISTINCT user_id) BETWEEN 2 AND ?", MAX_GROUP_USERS)
          .pluck(:network_key, :signature_hash)
      values.each do |network, signature|
        ids = scope.where(network_key: network, signature_hash: signature).distinct.limit(MAX_GROUP_USERS).pluck(:user_id)
        add_pairs!(pairs, ids)
        break if pairs.length > MAX_PAIR_CANDIDATES
      end
    end

    def add_pairs!(pairs, ids)
      ids.map(&:to_i).select(&:positive?).uniq.sort.combination(2) do |pair|
        pairs << pair
        break if pairs.length > MAX_PAIR_CANDIDATES
      end
    end

    def write_status(**values)
      current = status
      payload = current.merge(values).compact
      Discourse.redis.set(STATUS_KEY, payload.to_json, ex: 30.days.to_i)
    end

    def enabled?
      SiteSetting.account_security_enabled && SiteSetting.account_security_account_correlation_enabled
    end
  end
end
