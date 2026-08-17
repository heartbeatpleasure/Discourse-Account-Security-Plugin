# frozen_string_literal: true

require "json"
require "set"

module ::AccountSecurity
  module AccountCorrelationScanner
    module_function

    STATUS_KEY = "account_security:correlation_scan:status"
    MAX_GROUP_USERS = 20
    MAX_PAIR_CANDIDATES = 20_000

    def enqueue!(requested_by_id: nil, source: "manual")
      return { success: false, error_code: "correlation_disabled", scan: status } unless enabled?

      DistributedMutex.synchronize("account-security-correlation-enqueue", validity: 10) do
        current = status
        if current[:state] == "running" || current[:state] == "queued"
          next { success: false, error_code: "scan_already_running", scan: current }
        end

        write_status(
          state: "queued",
          requested_by_id: requested_by_id,
          source: safe_source(source),
          queued_at: Time.zone.now.iso8601,
        )
        Jobs.enqueue(
          :account_security_rebuild_correlations,
          requested_by_id: requested_by_id,
          source: safe_source(source),
        )
        { success: true, scan: status }
      end
    end

    def run!(requested_by_id: nil, source: "manual")
      unless enabled?
        write_status(
          state: "disabled",
          requested_by_id: requested_by_id,
          source: safe_source(source),
          completed_at: Time.zone.now.iso8601,
          error_code: "correlation_disabled",
        )
        return status
      end

      DistributedMutex.synchronize("account-security-correlation-scan", validity: 2.hours.to_i) do
        started_at = Time.zone.now
        scan_source = safe_source(source)
        write_status(
          state: "running",
          requested_by_id: requested_by_id,
          source: scan_source,
          started_at: started_at.iso8601,
          pairs_processed: 0,
          candidates_found: 0,
          token_signatures_backfilled: 0,
          truncated: false,
          diagnostics: {},
        )

        signature_count = SessionSignatureRecorder.backfill_active_tokens!
        pairs, truncated, exact_index, scan_context, diagnostics = candidate_pairs
        found = 0
        processed = 0

        pairs.each_slice(250) do |batch|
          batch.each do |user_a_id, user_b_id|
            processed += 1
            exact_details = exact_index.shared_details(user_a_id, user_b_id)
            found += 1 if AccountCorrelationService.recalculate_pair!(
              user_a_id,
              user_b_id,
              observed_at: started_at,
              source: scan_source == "scheduled" ? "scheduled_scan" : "backfill_scan",
              precomputed_ip_details: exact_details,
              precomputed_supplemental: scan_context.evidence_for_pair(user_a_id, user_b_id),
            )
          end
          write_status(
            state: "running",
            requested_by_id: requested_by_id,
            source: scan_source,
            started_at: started_at.iso8601,
            pairs_processed: processed,
            candidates_found: found,
            token_signatures_backfilled: signature_count,
            truncated: truncated,
            diagnostics: diagnostics,
          )
        end

        Statistics.increment!(correlation_scans: 1)
        write_status(
          state: "completed",
          requested_by_id: requested_by_id,
          source: scan_source,
          started_at: started_at.iso8601,
          completed_at: Time.zone.now.iso8601,
          pairs_processed: processed,
          candidates_found: found,
          token_signatures_backfilled: signature_count,
          truncated: truncated,
          diagnostics: diagnostics,
        )
      end
      status
    rescue StandardError => e
      Rails.logger.warn("[account_security] account correlation scan failed class=#{e.class}")
      write_status(
        state: "failed",
        requested_by_id: requested_by_id,
        source: safe_source(source),
        error_code: "scan_failed",
        completed_at: Time.zone.now.iso8601,
      )
      status
    end

    def status
      raw = Discourse.redis.get(STATUS_KEY)
      return { state: "never" } if raw.blank?
      JSON.parse(raw, symbolize_names: true).slice(
        :state,
        :requested_by_id,
        :source,
        :queued_at,
        :started_at,
        :completed_at,
        :pairs_processed,
        :candidates_found,
        :token_signatures_backfilled,
        :truncated,
        :diagnostics,
        :error_code,
      )
    rescue JSON::ParserError, TypeError
      { state: "unknown" }
    end

    def candidate_pairs
      exact_index = CoreIpEvidence.build_scan_index
      pairs = exact_index.pair_set(max_group_users: MAX_GROUP_USERS, max_pairs: MAX_PAIR_CANDIDATES)
      truncated = pairs.length > MAX_PAIR_CANDIDATES
      pairs = Set.new(pairs.to_a.first(MAX_PAIR_CANDIDATES)) if truncated

      diagnostics = exact_index.diagnostics.dup
      scan_context = AccountCorrelationScanContext.new

      unless truncated
        diagnostics.merge!(
          scan_context.add_candidate_pairs!(
            pairs,
            max_group_users: MAX_GROUP_USERS,
            max_pairs: MAX_PAIR_CANDIDATES,
          ),
        )
      else
        diagnostics.merge!(scan_context.diagnostics)
      end

      if pairs.length > MAX_PAIR_CANDIDATES
        pairs = Set.new(pairs.to_a.first(MAX_PAIR_CANDIDATES))
        truncated = true
      end
      diagnostics[:total_candidate_pairs] = pairs.length

      [pairs.to_a, truncated, exact_index, scan_context, diagnostics]
    end

    def write_status(**values)
      current = status
      payload = current.merge(values).compact
      Discourse.redis.set(STATUS_KEY, payload.to_json, ex: 30.days.to_i)
    end

    def safe_source(value)
      token = value.to_s
      %w[manual scheduled].include?(token) ? token : "manual"
    end

    def enabled?
      SiteSetting.account_security_enabled && SiteSetting.account_security_account_correlation_enabled
    end
  end
end
