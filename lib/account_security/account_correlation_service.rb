# frozen_string_literal: true

require "set"

module ::AccountSecurity
  module AccountCorrelationService
    module_function

    MAX_NETWORK_GROUP_USERS = 20
    MAX_CANDIDATES_PER_OBSERVATION = 50
    MAX_EXISTING_CANDIDATES_PER_OBSERVATION = 25
    MAX_SHARED_NETWORKS_IN_PAYLOAD = 8
    MAX_SHARED_IPS_IN_PAYLOAD = CoreIpEvidence::MAX_STORED_SHARED_IPS

    RecalculationResult = Struct.new(:correlation, :outcome, :candidate_now, keyword_init: true)

    CANDIDATE_PRIORITY = {
      existing: 0,
      exact_ip: 1,
      session_signature: 2,
      shared_network: 3,
    }.freeze

    def observe!(user:, ip:, trigger:, network: nil, session_signature: nil)
      return [] unless enabled?
      return [] if user.blank? || !user.human? || user.staged? || user.id.to_i <= 0

      normalized_ip = IpNormalizer.normalize(ip)
      return [] if normalized_ip.blank?
      public_ip = IpNormalizer.normalize_public(normalized_ip)
      network ||= IpNormalizer.familiarity_network(public_ip) if public_ip.present?

      candidate_user_ids_for_observation(
        user_id: user.id,
        normalized_ip: normalized_ip,
        network: network,
        session_signature: session_signature,
      ).filter_map do |other_id|
        recalculate_pair!(user.id, other_id, observed_at: Time.zone.now, source: trigger.to_s)
      end
    rescue StandardError => e
      Rails.logger.warn("[account_security] account correlation observation failed class=#{e.class}")
      []
    end

    def recalculate_pair!(first_user_id, second_user_id, observed_at: nil, source: nil, precomputed_ip_details: nil, precomputed_supplemental: nil)
      recalculate_pair_with_result!(
        first_user_id,
        second_user_id,
        observed_at: observed_at,
        source: source,
        precomputed_ip_details: precomputed_ip_details,
        precomputed_supplemental: precomputed_supplemental,
      ).correlation
    end

    def recalculate_pair_with_result!(first_user_id, second_user_id, observed_at: nil, source: nil, precomputed_ip_details: nil, precomputed_supplemental: nil)
      return RecalculationResult.new(outcome: "disabled", candidate_now: false) unless enabled?

      user_a_id, user_b_id = [first_user_id.to_i, second_user_id.to_i].sort
      if user_a_id <= 0 || user_a_id == user_b_id
        return RecalculationResult.new(outcome: "invalid_pair", candidate_now: false)
      end

      users = User.human_users.where(id: [user_a_id, user_b_id], staged: false).index_by(&:id)
      user_a = users[user_a_id]
      user_b = users[user_b_id]
      if user_a.blank? || user_b.blank?
        return RecalculationResult.new(outcome: "ineligible_users", candidate_now: false)
      end

      evidence = build_evidence(
        user_a,
        user_b,
        precomputed_ip_details: precomputed_ip_details,
        precomputed_supplemental: precomputed_supplemental,
      )
      result = AccountCorrelationPolicy.score_with_breakdown(evidence)
      score = result[:score]
      evidence["score_breakdown"] = result[:breakdown]
      confidence = AccountCorrelationPolicy.confidence(score)
      existing = AccountCorrelation.find_by(user_a_id: user_a_id, user_b_id: user_b_id)
      candidate_now = AccountCorrelationPolicy.store_candidate?(score, evidence)
      if existing.blank? && !candidate_now
        return RecalculationResult.new(outcome: "not_candidate", candidate_now: false)
      end

      now = observed_at || Time.zone.now
      correlation = existing || AccountCorrelation.new(
        user_a_id: user_a_id,
        user_b_id: user_b_id,
        first_seen_at: now,
        status: "open",
      )
      correlation.assign_attributes(
        score: score,
        confidence: confidence,
        evidence: evidence.merge("last_source" => safe_source(source)),
        last_seen_at: [correlation.last_seen_at, now].compact.max,
      )
      created = correlation.new_record?
      correlation.save!
      Statistics.increment!(correlation_candidates: 1) if created
      CorrelationIncidentNotifier.notify_if_needed!(correlation, source: source)

      outcome =
        if created
          "created"
        elsif candidate_now
          "updated"
        else
          "retained_below_threshold"
        end
      RecalculationResult.new(correlation: correlation, outcome: outcome, candidate_now: candidate_now)
    rescue ActiveRecord::RecordNotUnique
      recalculate_pair_with_result!(
        user_a_id,
        user_b_id,
        observed_at: observed_at,
        source: source,
        precomputed_ip_details: precomputed_ip_details,
        precomputed_supplemental: precomputed_supplemental,
      )
    rescue StandardError => e
      Rails.logger.warn("[account_security] account correlation recalculation failed class=#{e.class}")
      RecalculationResult.new(outcome: "error", candidate_now: false)
    end

    def build_evidence(user_a, user_b, precomputed_ip_details: nil, precomputed_supplemental: nil)
      exact_details =
        if precomputed_ip_details.nil?
          CoreIpEvidence.shared_details_for_pair(user_a.id, user_b.id)
        else
          Array(precomputed_ip_details)
        end

      if precomputed_supplemental.is_a?(Hash)
        shared_networks = Array(precomputed_supplemental["shared_networks"]).map(&:to_s).uniq
        signature = {
          count: precomputed_supplemental["shared_session_signature_count"].to_i,
          client_count: precomputed_supplemental["shared_session_client_signature_count"].to_i,
          repeated_count: precomputed_supplemental["repeated_shared_session_signature_count"].to_i,
          repeated_client_count: precomputed_supplemental["repeated_shared_session_client_signature_count"].to_i,
          paired_observations: precomputed_supplemental["shared_session_signature_paired_observations"].to_i,
          span_days: precomputed_supplemental["shared_session_signature_span_days"].to_i,
        }
        browser = {
          count: precomputed_supplemental["browser_continuity_count"].to_i,
          max_users: precomputed_supplemental["max_browser_continuity_users"].to_i,
          repeated_count: precomputed_supplemental["repeated_browser_continuity_count"].to_i,
          paired_observations: precomputed_supplemental["browser_continuity_paired_observations"].to_i,
          span_days: precomputed_supplemental["browser_continuity_span_days"].to_i,
        }
        network_user_counts =
          Hash(precomputed_supplemental["shared_network_user_counts"]).each_with_object({}) do |(network_key, count), memo|
            key = network_key.to_s
            memo[key] = count.to_i if key.present?
          end
        max_network_users = [precomputed_supplemental["max_shared_network_users"].to_i, network_user_counts.values.max.to_i].max
        core_auth_history_complete =
          !precomputed_supplemental.key?("core_auth_history_complete") ||
            precomputed_supplemental["core_auth_history_complete"] == true
        exact_ip_population_complete =
          !precomputed_supplemental.key?("exact_ip_population_complete") ||
            precomputed_supplemental["exact_ip_population_complete"] == true
        temporal = normalize_temporal_evidence(precomputed_supplemental["temporal_evidence"])
      else
        shared_networks = shared_network_keys(user_a.id, user_b.id).reject { |network| trusted_network?(network) }
        signature = shared_session_signature_summary(user_a.id, user_b.id, shared_networks)
        browser = BrowserContinuityRecorder.shared_summary(user_a.id, user_b.id)
        network_user_counts = shared_networks.index_with { |network| distinct_users_on_network(network) }
        max_network_users = network_user_counts.values.max.to_i
        core_auth_history_complete = true
        exact_ip_population_complete = true
        temporal = TemporalCorrelationEvidence.for_pair(
          user_a.id,
          user_b.id,
          shared_ips: exact_details.map { |detail| detail["ip_address"] },
        )
      end

      registration_details = exact_details.select { |detail| both_source?(detail, "registration") }
      current_details = exact_details.select { |detail| both_source?(detail, "current") }
      history_details = exact_details.select { |detail| historical_source?(detail) }
      core_history_details = exact_details.select { |detail| core_history_source?(detail) }
      auth_details = exact_details.select { |detail| auth_source?(detail) }
      public_details = exact_details.select { |detail| detail["public"] == true }
      untrusted_public_details = public_details.reject { |detail| detail["trusted"] == true }
      nonpublic_details = exact_details.reject { |detail| detail["public"] == true }
      trusted_details = exact_details.select { |detail| detail["trusted"] == true }

      exact_counts = exact_details.map { |detail| detail["user_count"].to_i }
      registration_delta = ((user_a.created_at - user_b.created_at).abs / 60).round

      exact_network_keys = exact_details.filter_map do |detail|
        IpNormalizer.familiarity_network(detail["ip_address"])
      end.to_set
      independent_shared_networks = shared_networks.reject { |network| exact_network_keys.include?(network.to_s) }
      overlapping_shared_networks = shared_networks.select { |network| exact_network_keys.include?(network.to_s) }
      max_independent_shared_network_users = independent_shared_networks.map do |network|
        network_user_counts[network.to_s].to_i
      end.max.to_i

      # SessionSignature and historical auth-signature evidence are both based
      # on the same site-local HMAC of the normalized user agent. Keep the v2
      # fields untouched, but expose a conservative v3-ready group count using
      # the maximum rather than summing both sources. This prevents the same
      # client characteristic from being rewarded twice without persisting or
      # exposing the signature hashes themselves.
      session_client_signature_count = signature[:client_count].to_i
      auth_client_signature_count = temporal["shared_auth_client_signature_count"].to_i
      repeated_session_client_signature_count = signature[:repeated_client_count].to_i
      repeated_auth_client_signature_count = temporal["repeated_shared_auth_client_signature_count"].to_i
      client_signature_source_count = [session_client_signature_count, auth_client_signature_count].count(&:positive?)

      {
        "scoring_version" => AccountCorrelationPolicy::SCORING_VERSION,
        "shared_registration_ip" => registration_details.any?,
        "shared_registration_ip_public" => registration_details.any? { |detail| detail["public"] == true && detail["trusted"] != true },
        "shared_registration_ip_nonpublic" => registration_details.any? { |detail| detail["public"] != true },
        "same_current_ip" => current_details.any?,
        "same_current_ip_public" => current_details.any? { |detail| detail["public"] == true && detail["trusted"] != true },
        "same_current_ip_nonpublic" => current_details.any? { |detail| detail["public"] != true },
        "shared_exact_ip_count" => exact_details.length,
        "shared_public_ip_count" => public_details.length,
        "untrusted_public_ip_count" => untrusted_public_details.length,
        "shared_nonpublic_ip_count" => nonpublic_details.length,
        "shared_history_ip_count" => history_details.length,
        "shared_core_history_ip_count" => core_history_details.length,
        "shared_auth_ip_count" => auth_details.length,
        "core_auth_history_complete" => core_auth_history_complete,
        "exact_ip_population_complete" => exact_ip_population_complete,
        "trusted_shared_ip_count" => trusted_details.length,
        "tor_shared_ip_count" => exact_details.count { |detail| detail["tor"] == true },
        "hosting_shared_ip_count" => exact_details.count { |detail| detail["hosting"] == true },
        "mobile_shared_ip_count" => exact_details.count { |detail| detail["mobile"] == true },
        "local_blacklist_shared_ip_count" => exact_details.count { |detail| detail["local_blacklist"] == true },
        "shared_ip_details" => exact_details.first(MAX_SHARED_IPS_IN_PAYLOAD),
        # Keep the v2 shared-network fields unchanged. The independent fields
        # give scoring v3 a deduplicated network signal so an IPv4 /32 (or an
        # IPv6 familiarity network containing an already shared exact IP) is
        # not rewarded twice.
        "shared_network_count" => shared_networks.length,
        "shared_networks" => shared_networks.first(MAX_SHARED_NETWORKS_IN_PAYLOAD),
        "shared_independent_network_count" => independent_shared_networks.length,
        "shared_exact_ip_network_overlap_count" => overlapping_shared_networks.length,
        "shared_independent_networks" => independent_shared_networks.first(MAX_SHARED_NETWORKS_IN_PAYLOAD),
        "max_independent_shared_network_users" => max_independent_shared_network_users,
        "shared_session_signature_count" => signature[:count].to_i,
        "shared_session_client_signature_count" => session_client_signature_count,
        "repeated_shared_session_signature_count" => signature[:repeated_count].to_i,
        "repeated_shared_session_client_signature_count" => repeated_session_client_signature_count,
        "client_signature_group_count" => [session_client_signature_count, auth_client_signature_count].max,
        "repeated_client_signature_group_count" => [repeated_session_client_signature_count, repeated_auth_client_signature_count].max,
        "client_signature_evidence_source_count" => client_signature_source_count,
        "shared_session_signature_paired_observations" => signature[:paired_observations].to_i,
        "shared_session_signature_span_days" => signature[:span_days].to_i,
        "browser_continuity_count" => browser[:count].to_i,
        "max_browser_continuity_users" => browser[:max_users].to_i,
        "repeated_browser_continuity_count" => browser[:repeated_count].to_i,
        "browser_continuity_paired_observations" => browser[:paired_observations].to_i,
        "browser_continuity_span_days" => browser[:span_days].to_i,
        "browser_continuity_positive_only" => true,
        "registration_delta_minutes" => registration_delta,
        "max_shared_network_users" => [max_network_users, exact_counts.max.to_i].max,
        "max_shared_exact_ip_users" => exact_counts.max.to_i,
        "large_shared_network" => [max_network_users, exact_counts.max.to_i].max >= 10,
        "raw_user_agent_stored" => false,
      }.merge(temporal)
    end

    def normalize_temporal_evidence(value)
      return TemporalCorrelationEvidence.empty_evidence unless value.is_a?(Hash)

      TemporalCorrelationEvidence.empty_evidence.merge(value.slice(
        "temporal_evidence_version",
        "temporal_auth_history_complete",
        "temporal_ip_population_complete",
        "temporal_population_window_basis",
        "timed_shared_ip_count",
        "temporal_within_15m_count",
        "temporal_within_1h_count",
        "temporal_within_6h_count",
        "temporal_within_24h_count",
        "temporal_within_72h_count",
        "temporal_within_7d_count",
        "temporal_public_within_24h_count",
        "temporal_public_within_7d_count",
        "temporal_repeated_public_alignment",
        "closest_shared_ip_gap_seconds",
        "max_temporal_ip_users_24h",
        "max_temporal_ip_users_7d",
        "max_temporal_ip_users_30d",
        "temporal_ip_details",
        "temporal_ip_details_truncated",
        "temporal_score_effect",
        "auth_pattern_evidence_version",
        "auth_pattern_history_complete",
        "auth_proximity_closest_gap_seconds",
        "auth_proximity_within_5m_count",
        "auth_proximity_within_30m_count",
        "auth_proximity_within_1h_count",
        "auth_proximity_within_6h_count",
        "auth_proximity_within_24h_count",
        "auth_proximity_within_72h_count",
        "auth_proximity_within_7d_count",
        "auth_proximity_same_client_within_30m_count",
        "auth_proximity_public_ip_count",
        "auth_proximity_public_ip_within_24h_count",
        "auth_proximity_public_ip_within_7d_count",
        "auth_proximity_details",
        "auth_proximity_details_truncated",
        "shared_auth_client_signature_count",
        "repeated_shared_auth_client_signature_count",
        "shared_auth_client_signature_paired_observations",
        "max_shared_auth_client_signature_users",
        "auth_client_signature_population_complete",
        "public_ip_transition_match_count",
        "public_ip_transition_pattern_count",
        "public_ip_transition_closest_gap_seconds",
        "aligned_public_ip_transition_1h_count",
        "aligned_public_ip_transition_6h_count",
        "aligned_public_ip_transition_24h_count",
        "aligned_public_ip_transition_3d_count",
        "aligned_public_ip_transition_7d_count",
        "aligned_public_ip_transition_30d_count",
        "aligned_public_ip_transition_90d_count",
        "aligned_public_ip_transition_180d_count",
        "public_ip_transition_beyond_180d_count",
        "public_ip_transition_unaligned_count",
        "public_ip_transition_population_complete",
        "max_public_ip_transition_users",
        "max_public_ip_transition_users_24h",
        "max_public_ip_transition_users_7d",
        "public_ip_transition_details",
        "public_ip_transition_details_truncated",
        "auth_pattern_score_effect",
      ))
    end

    def shared_network_keys(user_a_id, user_b_id)
      cutoff = SessionSignatureRecorder.retention_cutoff
      a = Set.new(UserNetwork.where(user_id: user_a_id).where("last_seen_at >= ?", cutoff).pluck(:network_key).map(&:to_s))
      b = Set.new(UserNetwork.where(user_id: user_b_id).where("last_seen_at >= ?", cutoff).pluck(:network_key).map(&:to_s))
      a.merge(SessionSignature.where(user_id: user_a_id).where("last_seen_at >= ?", cutoff).pluck(:network_key).map(&:to_s))
      b.merge(SessionSignature.where(user_id: user_b_id).where("last_seen_at >= ?", cutoff).pluck(:network_key).map(&:to_s))
      (a & b).to_a.sort
    end

    def shared_session_signature_summary(user_a_id, user_b_id, allowed_networks)
      empty = { count: 0, client_count: 0, repeated_count: 0, repeated_client_count: 0, paired_observations: 0, span_days: 0 }
      return empty if allowed_networks.blank?

      cutoff = SessionSignatureRecorder.retention_cutoff
      rows_a =
        SessionSignature
          .where(user_id: user_a_id, network_key: allowed_networks)
          .where("last_seen_at >= ?", cutoff)
          .pluck(:network_key, :signature_hash, :first_seen_at, :last_seen_at, :observation_count)
          .index_by { |row| [row[0].to_s, row[1].to_s] }
      return empty if rows_a.empty?

      rows_b =
        SessionSignature
          .where(user_id: user_b_id, network_key: allowed_networks)
          .where("last_seen_at >= ?", cutoff)
          .pluck(:network_key, :signature_hash, :first_seen_at, :last_seen_at, :observation_count)
          .index_by { |row| [row[0].to_s, row[1].to_s] }
      shared = rows_a.keys & rows_b.keys
      return empty if shared.empty?

      repeated_count = 0
      repeated_client_signatures = Set.new
      paired_observations = 0
      max_span_seconds = 0
      shared.each do |key|
        row_a = rows_a[key]
        row_b = rows_b[key]
        observations_a = row_a[4].to_i
        observations_b = row_b[4].to_i
        if observations_a >= 2 && observations_b >= 2
          repeated_count += 1
          repeated_client_signatures << key[1].to_s
        end
        paired_observations += [observations_a, observations_b].min

        starts = [row_a[2], row_b[2]].compact
        finishes = [row_a[3], row_b[3]].compact
        if starts.any? && finishes.any?
          max_span_seconds = [max_span_seconds, (finishes.max - starts.min).to_i].max
        end
      end

      {
        count: shared.length,
        client_count: shared.map { |network, signature| signature.to_s }.uniq.length,
        repeated_count: repeated_count,
        repeated_client_count: repeated_client_signatures.length,
        paired_observations: paired_observations,
        span_days: (max_span_seconds.to_f / 1.day.to_i).floor,
      }
    rescue ActiveRecord::StatementInvalid
      empty || { count: 0, client_count: 0, repeated_count: 0, repeated_client_count: 0, paired_observations: 0, span_days: 0 }
    end

    def distinct_users_on_network(network)
      ids = UserNetwork.where(network_key: network).distinct.pluck(:user_id)
      ids |= SessionSignature.where(network_key: network).distinct.pluck(:user_id)
      ids.length
    end

    def candidate_user_ids_for_observation(user_id:, normalized_ip:, network:, session_signature:)
      user_id = user_id.to_i
      candidates = {}

      existing_other_user_ids(user_id).each do |id|
        add_prioritized_candidate!(candidates, id, CANDIDATE_PRIORITY[:existing], user_id)
      end

      CoreIpEvidence.candidate_user_ids_for_ip(
        normalized_ip,
        current_user_id: user_id,
        max_group_users: MAX_NETWORK_GROUP_USERS,
      ).sort.each do |id|
        add_prioritized_candidate!(candidates, id, CANDIDATE_PRIORITY[:exact_ip], user_id)
      end

      if session_signature
        small_group_user_ids(
          SessionSignature.where(
            network_key: session_signature.network_key,
            signature_hash: session_signature.signature_hash,
          ),
          user_id,
        ).each do |id|
          add_prioritized_candidate!(candidates, id, CANDIDATE_PRIORITY[:session_signature], user_id)
        end
      end

      if network.present?
        small_group_user_ids(UserNetwork.where(network_key: network), user_id).each do |id|
          add_prioritized_candidate!(candidates, id, CANDIDATE_PRIORITY[:shared_network], user_id)
        end
      end

      candidates
        .sort_by { |id, priority| [priority, id] }
        .first(MAX_CANDIDATES_PER_OBSERVATION)
        .map(&:first)
    end

    def add_prioritized_candidate!(target, candidate_id, priority, current_user_id)
      candidate_id = candidate_id.to_i
      return if candidate_id <= 0 || candidate_id == current_user_id.to_i

      current_priority = target[candidate_id]
      target[candidate_id] = priority if current_priority.nil? || priority < current_priority
    end

    def small_group_user_ids(scope, current_user_id)
      ids = scope.distinct.order(:user_id).limit(MAX_NETWORK_GROUP_USERS + 1).pluck(:user_id).map(&:to_i).uniq
      return [] if ids.length > MAX_NETWORK_GROUP_USERS

      ids.select { |id| id.positive? && id != current_user_id.to_i }
    end

    def existing_other_user_ids(user_id)
      AccountCorrelation
        .where("user_a_id = :user_id OR user_b_id = :user_id", user_id: user_id.to_i)
        .order(score: :desc, last_seen_at: :desc, id: :asc)
        .limit(MAX_EXISTING_CANDIDATES_PER_OBSERVATION)
        .pluck(:user_a_id, :user_b_id)
        .map { |user_a_id, user_b_id| user_a_id.to_i == user_id.to_i ? user_b_id.to_i : user_a_id.to_i }
        .uniq
    end

    def both_source?(detail, source)
      Array(detail["sources_a"]).include?(source) && Array(detail["sources_b"]).include?(source)
    end

    def historical_source?(detail)
      sources = Array(detail["sources_a"]) | Array(detail["sources_b"])
      (sources & %w[history auth_session active_session]).any?
    end

    def core_history_source?(detail)
      sources = Array(detail["sources_a"]) | Array(detail["sources_b"])
      sources.include?("history")
    end

    def auth_source?(detail)
      sources = Array(detail["sources_a"]) | Array(detail["sources_b"])
      (sources & %w[auth_session active_session]).any?
    end

    def trusted_network?(network)
      TrustedNetwork.active.where("?::inet <<= network", network.to_s).exists?
    rescue ActiveRecord::StatementInvalid
      false
    end

    def safe_source(value)
      token = value.to_s
      token.match?(/\A[a-z0-9_:-]{1,40}\z/i) ? token : nil
    end

    def enabled?
      SiteSetting.account_security_enabled && SiteSetting.account_security_account_correlation_enabled
    end
  end
end
