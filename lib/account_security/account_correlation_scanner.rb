# frozen_string_literal: true

require "json"
require "set"

module ::AccountSecurity
  module AccountCorrelationScanner
    module_function

    STATUS_KEY = "account_security:correlation_scan:status"
    STATUS_TTL = 30.days.to_i
    MAX_GROUP_USERS = 20
    MAX_PAIR_CANDIDATES = 20_000
    SCAN_MUTEX_VALIDITY = 6.hours.to_i
    STALE_STATUS_AFTER = SCAN_MUTEX_VALIDITY + 15.minutes.to_i
    STATUS_BATCH_SIZE = 250

    COUNTER_KEYS = %i[
      pairs_processed
      existing_pairs_processed
      discovery_pairs_processed
      new_candidates
      existing_candidates_updated
      existing_candidates_below_threshold
      new_candidates_below_threshold
      pairs_skipped
      pairs_failed
    ].freeze

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
          stale_recovered: false,
          error_code: nil,
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

      DistributedMutex.synchronize("account-security-correlation-scan", validity: SCAN_MUTEX_VALIDITY) do
        started_at = Time.zone.now
        scan_source = safe_source(source)
        counters = empty_counters
        write_status(
          state: "running",
          requested_by_id: requested_by_id,
          source: scan_source,
          started_at: started_at.iso8601,
          completed_at: nil,
          heartbeat_at: started_at.iso8601,
          candidates_found: 0,
          token_signatures_backfilled: 0,
          truncated: false,
          diagnostics: {},
          stale_recovered: false,
          error_code: nil,
          **counters,
        )

        signature_count = SessionSignatureRecorder.backfill_active_tokens!
        discovery_pairs, truncated, exact_index, scan_context, temporal_index, diagnostics = build_discovery_context
        discovery_pairs = Set.new(discovery_pairs)
        diagnostics[:existing_pairs_total] = AccountCorrelation.count
        diagnostics[:discovery_pair_limit] = MAX_PAIR_CANDIDATES
        diagnostics[:discovery_pairs_selected] = discovery_pairs.length
        diagnostics[:discovery_truncated] = truncated

        processed_since_status = 0
        scan_record_scope.find_each(batch_size: STATUS_BATCH_SIZE) do |correlation|
          pair = [correlation.user_a_id.to_i, correlation.user_b_id.to_i].sort
          discovery_pairs.delete(pair)
          process_pair!(
            pair,
            counters: counters,
            source_kind: :existing,
            exact_index: exact_index,
            scan_context: scan_context,
            temporal_index: temporal_index,
            observed_at: started_at,
            scan_source: scan_source,
          )
          processed_since_status += 1
          if processed_since_status >= STATUS_BATCH_SIZE
            write_running_status!(
              requested_by_id: requested_by_id,
              source: scan_source,
              started_at: started_at,
              signature_count: signature_count,
              truncated: truncated,
              diagnostics: diagnostics,
              counters: counters,
            )
            processed_since_status = 0
          end
        end

        diagnostics[:discovery_pairs_deduplicated_against_existing] =
          diagnostics[:discovery_pairs_selected].to_i - discovery_pairs.length

        discovery_pairs.to_a.sort.each_slice(STATUS_BATCH_SIZE) do |batch|
          batch.each do |pair|
            process_pair!(
              pair,
              counters: counters,
              source_kind: :discovery,
              exact_index: exact_index,
              scan_context: scan_context,
              temporal_index: temporal_index,
              observed_at: started_at,
              scan_source: scan_source,
            )
          end
          write_running_status!(
            requested_by_id: requested_by_id,
            source: scan_source,
            started_at: started_at,
            signature_count: signature_count,
            truncated: truncated,
            diagnostics: diagnostics,
            counters: counters,
          )
        end

        diagnostics[:existing_pairs_processed] = counters[:existing_pairs_processed]
        diagnostics[:discovery_pairs_processed] = counters[:discovery_pairs_processed]
        diagnostics[:total_pairs_processed] = counters[:pairs_processed]
        diagnostics[:total_candidate_pairs] =
          counters[:existing_pairs_processed] + diagnostics[:discovery_pairs_selected].to_i -
            diagnostics[:discovery_pairs_deduplicated_against_existing].to_i

        Statistics.increment!(correlation_scans: 1)
        write_status(
          state: "completed",
          requested_by_id: requested_by_id,
          source: scan_source,
          started_at: started_at.iso8601,
          completed_at: Time.zone.now.iso8601,
          heartbeat_at: Time.zone.now.iso8601,
          candidates_found: legacy_candidates_found(counters),
          token_signatures_backfilled: signature_count,
          truncated: truncated,
          diagnostics: diagnostics,
          stale_recovered: false,
          error_code: nil,
          **counters,
        )
      end
      status
    rescue StandardError => e
      Rails.logger.warn("[account_security] account correlation scan failed class=#{e.class}")
      write_status(
        state: "failed",
        requested_by_id: requested_by_id,
        source: safe_source(source),
        completed_at: Time.zone.now.iso8601,
        heartbeat_at: Time.zone.now.iso8601,
        error_code: "scan_failed",
      )
      status
    end

    def status
      current = read_status
      return current unless stale_status?(current)

      recovered = current.merge(
        state: "failed",
        completed_at: Time.zone.now.iso8601,
        error_code: "scan_stale",
        stale_recovered: true,
      )
      persist_status(recovered)
      recovered
    end

    # Compatibility/introspection helper. The actual full scan processes every
    # existing persisted correlation independently from the bounded discovery
    # set, so existing scores can never be starved by the new-candidate cap.
    def candidate_pairs
      pairs, truncated, exact_index, scan_context, temporal_index, diagnostics = build_discovery_context
      preview = Set.new(pairs)
      existing_pairs_added = 0
      existing_pairs_total = AccountCorrelation.count

      AccountCorrelation.order(:id).pluck(:user_a_id, :user_b_id).each do |user_a_id, user_b_id|
        break if preview.length >= MAX_PAIR_CANDIDATES
        pair = [user_a_id.to_i, user_b_id.to_i].sort
        next if pair.first <= 0 || pair.first == pair.last || preview.include?(pair)

        preview << pair
        existing_pairs_added += 1
      end

      diagnostics = diagnostics.merge(
        existing_pairs_total: existing_pairs_total,
        existing_pairs_added: existing_pairs_added,
        total_candidate_pairs: preview.length,
      )
      [preview.to_a.sort, truncated, exact_index, scan_context, temporal_index, diagnostics]
    end

    def build_discovery_context
      exact_index = CoreIpEvidence.build_scan_index
      pairs = exact_index.pair_set(max_group_users: MAX_GROUP_USERS, max_pairs: MAX_PAIR_CANDIDATES)
      truncated = pairs.length > MAX_PAIR_CANDIDATES
      pairs = Set.new(pairs.to_a.sort.first(MAX_PAIR_CANDIDATES)) if truncated

      diagnostics = exact_index.diagnostics.dup
      temporal_index = TemporalCorrelationEvidence.build_scan_index
      diagnostics.merge!(temporal_index.diagnostics)
      scan_context = AccountCorrelationScanContext.new

      unless truncated
        diagnostics.merge!(
          scan_context.add_candidate_pairs!(
            pairs,
            max_group_users: MAX_GROUP_USERS,
            max_pairs: MAX_PAIR_CANDIDATES,
          ),
        )
        if pairs.length > MAX_PAIR_CANDIDATES
          pairs = Set.new(pairs.to_a.sort.first(MAX_PAIR_CANDIDATES))
          truncated = true
        end
      else
        diagnostics.merge!(scan_context.diagnostics)
      end

      diagnostics[:discovery_pair_limit] = MAX_PAIR_CANDIDATES
      diagnostics[:discovery_pairs_selected] = pairs.length
      diagnostics[:discovery_truncated] = truncated
      diagnostics[:total_candidate_pairs] = pairs.length

      [pairs.to_a.sort, truncated, exact_index, scan_context, temporal_index, diagnostics]
    end

    def process_pair!(pair, counters:, source_kind:, exact_index:, scan_context:, temporal_index:, observed_at:, scan_source:)
      user_a_id, user_b_id = pair
      counters[:pairs_processed] += 1
      if source_kind == :existing
        counters[:existing_pairs_processed] += 1
      else
        counters[:discovery_pairs_processed] += 1
      end

      exact_details = exact_index.shared_details(user_a_id, user_b_id)
      supplemental = scan_context.evidence_for_pair(user_a_id, user_b_id)
      core_auth_complete = exact_index.diagnostics[:auth_log_truncated] != true
      supplemental["core_auth_history_complete"] = core_auth_complete
      supplemental["exact_ip_population_complete"] = core_auth_complete
      supplemental["temporal_evidence"] = temporal_index.evidence_for_pair(
        user_a_id,
        user_b_id,
        shared_ips: exact_details.map { |detail| detail["ip_address"] },
      )
      result = AccountCorrelationService.recalculate_pair_with_result!(
        user_a_id,
        user_b_id,
        observed_at: observed_at,
        source: scan_source == "scheduled" ? "scheduled_scan" : "backfill_scan",
        precomputed_ip_details: exact_details,
        precomputed_supplemental: supplemental,
      )
      count_outcome!(counters, result.outcome)
    rescue StandardError => e
      counters[:pairs_failed] += 1
      Rails.logger.warn("[account_security] correlation scan pair failed class=#{e.class}")
    end

    def count_outcome!(counters, outcome)
      case outcome.to_s
      when "created"
        counters[:new_candidates] += 1
      when "updated"
        counters[:existing_candidates_updated] += 1
      when "retained_below_threshold"
        counters[:existing_candidates_below_threshold] += 1
      when "not_candidate"
        counters[:new_candidates_below_threshold] += 1
      when "error"
        counters[:pairs_failed] += 1
      else
        counters[:pairs_skipped] += 1
      end
    end

    def write_running_status!(requested_by_id:, source:, started_at:, signature_count:, truncated:, diagnostics:, counters:)
      write_status(
        state: "running",
        requested_by_id: requested_by_id,
        source: source,
        started_at: started_at.iso8601,
        heartbeat_at: Time.zone.now.iso8601,
        candidates_found: legacy_candidates_found(counters),
        token_signatures_backfilled: signature_count,
        truncated: truncated,
        diagnostics: diagnostics.merge(
          existing_pairs_processed: counters[:existing_pairs_processed],
          discovery_pairs_processed: counters[:discovery_pairs_processed],
          total_pairs_processed: counters[:pairs_processed],
        ),
        **counters,
      )
    end

    def legacy_candidates_found(counters)
      counters[:new_candidates].to_i +
        counters[:existing_candidates_updated].to_i +
        counters[:existing_candidates_below_threshold].to_i
    end

    def empty_counters
      COUNTER_KEYS.index_with { 0 }
    end

    def scan_record_scope
      AccountCorrelation.all
    end

    def read_status
      raw = Discourse.redis.get(STATUS_KEY)
      return { state: "never" } if raw.blank?

      JSON.parse(raw, symbolize_names: true).slice(
        :state,
        :requested_by_id,
        :source,
        :queued_at,
        :started_at,
        :completed_at,
        :heartbeat_at,
        :pairs_processed,
        :existing_pairs_processed,
        :discovery_pairs_processed,
        :new_candidates,
        :existing_candidates_updated,
        :existing_candidates_below_threshold,
        :new_candidates_below_threshold,
        :pairs_skipped,
        :pairs_failed,
        :candidates_found,
        :token_signatures_backfilled,
        :truncated,
        :diagnostics,
        :stale_recovered,
        :error_code,
      )
    rescue JSON::ParserError, TypeError
      { state: "unknown" }
    end

    def stale_status?(current)
      state = current[:state].to_s
      return false unless %w[queued running].include?(state)

      timestamp =
        if state == "running"
          current[:heartbeat_at].presence || current[:started_at].presence
        else
          current[:queued_at].presence
        end
      parsed = parse_status_time(timestamp)
      parsed.present? && parsed < STALE_STATUS_AFTER.seconds.ago
    end

    def parse_status_time(value)
      return nil if value.blank?
      Time.zone.parse(value.to_s)
    rescue ArgumentError, TypeError
      nil
    end

    def write_status(**values)
      payload = read_status.merge(values)
      payload.delete_if { |_key, value| value.nil? }
      persist_status(payload)
    end

    def persist_status(payload)
      Discourse.redis.set(STATUS_KEY, payload.to_json, ex: STATUS_TTL)
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
