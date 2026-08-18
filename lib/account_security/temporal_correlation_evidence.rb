# frozen_string_literal: true

require "set"

module ::AccountSecurity
  module TemporalCorrelationEvidence
    module_function

    EVIDENCE_VERSION = 5
    AUTH_PATTERN_EVIDENCE_VERSION = 4
    MAX_AUTH_ROWS = 100_000
    MAX_PAIR_AUTH_ROWS_PER_USER = 5_000
    MAX_SESSION_OBSERVATION_ROWS = 500_000
    MAX_PAIR_SESSION_OBSERVATION_ROWS_PER_USER = 1_000
    SESSION_OBSERVATION_EVIDENCE_HORIZON = 90.days
    EVENT_DEDUP_WINDOW = 10.minutes
    MAX_DETAILS = 8
    MAX_AUTH_PROXIMITY_DETAILS = 6
    MAX_TRANSITION_DETAILS = 6

    AUTH_PROXIMITY_WINDOWS = {
      within_5m_count: 5.minutes.to_i,
      within_30m_count: 30.minutes.to_i,
      within_1h_count: 1.hour.to_i,
      within_6h_count: 6.hours.to_i,
      within_24h_count: 24.hours.to_i,
      within_72h_count: 72.hours.to_i,
      within_7d_count: 7.days.to_i,
    }.freeze
    AUTH_PROXIMITY_WINDOW = AUTH_PROXIMITY_WINDOWS[:within_7d_count]

    TRANSITION_ALIGNMENT_WINDOWS = {
      within_1h_count: 1.hour.to_i,
      within_6h_count: 6.hours.to_i,
      within_24h_count: 24.hours.to_i,
      within_3d_count: 3.days.to_i,
      within_7d_count: 7.days.to_i,
      within_30d_count: 30.days.to_i,
      within_90d_count: 90.days.to_i,
      within_180d_count: 180.days.to_i,
    }.freeze

    TEMPORAL_POPULATION_WINDOWS = {
      users_24h: 24.hours.to_i,
      users_7d: 7.days.to_i,
      users_30d: 30.days.to_i,
    }.freeze
    TIMED_SOURCES = %w[registration history auth_session session_observation].freeze

    class ScanIndex
      attr_reader :diagnostics

      def initialize(population_complete: false, auth_history_complete: false, session_history_complete: nil)
        @times_by_user = Hash.new do |users, user_id|
          users[user_id] = Hash.new { |ips, ip| ips[ip] = [] }
        end
        @times_by_ip = Hash.new do |ips, ip|
          ips[ip] = Hash.new { |users, user_id| users[user_id] = [] }
        end
        @normalized_ip_population_times_cache = {}
        @auth_events_by_user = Hash.new { |hash, user_id| hash[user_id] = [] }
        @auth_signature_users = Hash.new { |hash, signature| hash[signature] = Set.new }
        @normalized_auth_events_cache = {}
        @auth_events_by_ip_cache = {}
        @auth_signature_counts_cache = {}
        @public_transition_times_cache = {}
        @public_transition_population_cache = nil
        @public_cache = {}
        @population_complete = population_complete == true
        @auth_history_complete = auth_history_complete == true
        @session_history_complete =
          if session_history_complete.nil?
            !SiteSetting.account_security_session_observation_enabled
          else
            session_history_complete == true
          end
        @diagnostics = {
          temporal_observation_rows: 0,
          temporal_registration_rows: 0,
          temporal_history_rows: 0,
          temporal_auth_session_rows: 0,
          temporal_session_observation_rows: 0,
          temporal_auth_log_truncated: false,
          temporal_session_observation_truncated: false,
          session_observation_history_complete: @session_history_complete,
          session_observation_evidence_horizon_days: (SESSION_OBSERVATION_EVIDENCE_HORIZON / 1.day).to_i,
          auth_pattern_rows: 0,
          auth_pattern_signature_rows: 0,
          auth_pattern_history_complete: pattern_history_complete?,
          temporal_ip_population_complete: @population_complete,
          public_transition_population_complete: @population_complete && pattern_history_complete?,
        }
      end

      def mark_population_complete!
        @population_complete = true
        diagnostics[:temporal_ip_population_complete] = true
        diagnostics[:public_transition_population_complete] = pattern_history_complete?
      end

      def mark_auth_history_complete!
        @auth_history_complete = true
        diagnostics[:auth_pattern_history_complete] = pattern_history_complete?
        diagnostics[:public_transition_population_complete] = @population_complete && pattern_history_complete?
      end

      def mark_session_history_complete!
        @session_history_complete = true
        diagnostics[:session_observation_history_complete] = true
        diagnostics[:auth_pattern_history_complete] = pattern_history_complete?
        diagnostics[:public_transition_population_complete] = @population_complete && pattern_history_complete?
      end

      def add(user_id, ip_value, source, observed_at)
        user_id = user_id.to_i
        source = source.to_s
        return if user_id <= 0 || !TIMED_SOURCES.include?(source)

        ip = IpNormalizer.normalize(ip_value)
        time = normalize_time(observed_at)
        return if ip.blank? || time.blank?

        @times_by_user[user_id][ip] << time
        @times_by_ip[ip][user_id] << time
        @normalized_ip_population_times_cache.delete([ip, user_id])
        diagnostics[:temporal_observation_rows] += 1
        key = "temporal_#{source}_rows".to_sym
        diagnostics[key] += 1 if diagnostics.key?(key)
      end

      def add_auth_event(user_id, ip_value, user_agent, observed_at)
        user_id = user_id.to_i
        ip = IpNormalizer.normalize(ip_value)
        time = normalize_time(observed_at)
        return if user_id <= 0 || ip.blank? || time.blank?

        add(user_id, ip, "auth_session", time)

        signature = SessionSignatureRecorder.signature_for(user_agent)
        event = {
          ip: ip,
          at: time,
          signature: signature,
          source: "auth_session",
        }
        @auth_events_by_user[user_id] << event
        @normalized_auth_events_cache.delete(user_id)
        @auth_events_by_ip_cache.delete(user_id)
        @auth_signature_counts_cache.delete(user_id)
        @public_transition_times_cache.delete(user_id)
        @public_transition_population_cache = nil
        diagnostics[:auth_pattern_rows] += 1

        if signature.present?
          @auth_signature_users[signature] << user_id
          diagnostics[:auth_pattern_signature_rows] += 1
        end
      end

      def add_session_event(user_id, ip_value, signature_hash, observed_at)
        user_id = user_id.to_i
        ip = IpNormalizer.normalize(ip_value)
        time = normalize_time(observed_at)
        signature = signature_hash.to_s.match?(/\A[0-9a-f]{64}\z/) ? signature_hash.to_s : nil
        return if user_id <= 0 || ip.blank? || time.blank?

        add(user_id, ip, "session_observation", time)
        event = { ip: ip, at: time, signature: signature, source: "session_observation" }
        @auth_events_by_user[user_id] << event
        @normalized_auth_events_cache.delete(user_id)
        @auth_events_by_ip_cache.delete(user_id)
        @auth_signature_counts_cache.delete(user_id)
        @public_transition_times_cache.delete(user_id)
        @public_transition_population_cache = nil
        diagnostics[:auth_pattern_rows] += 1
        if signature.present?
          @auth_signature_users[signature] << user_id
          diagnostics[:auth_pattern_signature_rows] += 1
        end
      end

      def mark_auth_log_truncated!
        @auth_history_complete = false
        diagnostics[:temporal_auth_log_truncated] = true
        diagnostics[:auth_pattern_history_complete] = false
        diagnostics[:temporal_ip_population_complete] = false
        diagnostics[:public_transition_population_complete] = false
      end

      def mark_session_log_truncated!
        @session_history_complete = false
        diagnostics[:temporal_session_observation_truncated] = true
        diagnostics[:session_observation_history_complete] = false
        diagnostics[:auth_pattern_history_complete] = false
        diagnostics[:temporal_ip_population_complete] = false
        diagnostics[:public_transition_population_complete] = false
      end

      def evidence_for_pair(user_a_id, user_b_id, shared_ips: nil)
        user_a_id = user_a_id.to_i
        user_b_id = user_b_id.to_i
        a = @times_by_user[user_a_id]
        b = @times_by_user[user_b_id]
        ips = Array(shared_ips).map { |value| IpNormalizer.normalize(value) }.compact.uniq
        ips = a.keys & b.keys if ips.empty?

        details = ips.filter_map do |ip|
          times_a = normalized_times(a[ip])
          times_b = normalized_times(b[ip])
          next if times_a.empty? || times_b.empty?

          closest = closest_pair(times_a, times_b)
          next if closest.nil?

          detail = {
            "ip_address" => ip,
            "public" => public_ip?(ip),
            "closest_gap_seconds" => closest[:gap],
            "observations_a" => times_a.length,
            "observations_b" => times_b.length,
            "temporal_population_complete" => @population_complete,
          }
          if @population_complete
            center = midpoint(closest[:a], closest[:b])
            TEMPORAL_POPULATION_WINDOWS.each do |key, seconds|
              detail["temporal_population_#{key}"] =
                closest[:gap] <= seconds ? population_count_for_ip(ip, center, seconds) : nil
            end
          end
          detail.compact
        end

        details.sort_by! { |detail| [detail["closest_gap_seconds"].to_i, detail["ip_address"].to_s] }
        closest_gap = details.map { |detail| detail["closest_gap_seconds"].to_i }.min
        within_15m = count_within(details, 15.minutes.to_i)
        within_1h = count_within(details, 1.hour.to_i)
        within_6h = count_within(details, 6.hours.to_i)
        within_24h = count_within(details, 24.hours.to_i)
        within_72h = count_within(details, 72.hours.to_i)
        within_7d = count_within(details, 7.days.to_i)
        public_within_24h = details.count do |detail|
          detail["public"] == true && detail["closest_gap_seconds"].to_i <= 24.hours.to_i
        end
        public_within_7d = details.count do |detail|
          detail["public"] == true && detail["closest_gap_seconds"].to_i <= 7.days.to_i
        end

        {
          "temporal_evidence_version" => EVIDENCE_VERSION,
          "temporal_auth_history_complete" => @auth_history_complete,
          "session_observation_history_complete" => @session_history_complete,
          "combined_session_login_history_complete" => pattern_history_complete?,
          "session_observation_evidence_horizon_days" => (SESSION_OBSERVATION_EVIDENCE_HORIZON / 1.day).to_i,
          "temporal_ip_population_complete" => @population_complete,
          "temporal_population_window_basis" => "closest_pair_midpoint",
          "timed_shared_ip_count" => details.length,
          "temporal_within_15m_count" => within_15m,
          "temporal_within_1h_count" => within_1h,
          "temporal_within_6h_count" => within_6h,
          "temporal_within_24h_count" => within_24h,
          "temporal_within_72h_count" => within_72h,
          "temporal_within_7d_count" => within_7d,
          "temporal_public_within_24h_count" => public_within_24h,
          "temporal_public_within_7d_count" => public_within_7d,
          "temporal_repeated_public_alignment" => public_within_24h >= 2,
          "closest_shared_ip_gap_seconds" => closest_gap,
          "max_temporal_ip_users_24h" => max_detail_value(details, "temporal_population_users_24h"),
          "max_temporal_ip_users_7d" => max_detail_value(details, "temporal_population_users_7d"),
          "max_temporal_ip_users_30d" => max_detail_value(details, "temporal_population_users_30d"),
          "temporal_ip_details" => details.first(MAX_DETAILS),
          "temporal_ip_details_truncated" => details.length > MAX_DETAILS,
          "temporal_score_effect" => "none",
        }.compact.merge(authentication_pattern_evidence(user_a_id, user_b_id, shared_ips: ips))
      end

      private

      def authentication_pattern_evidence(user_a_id, user_b_id, shared_ips:)
        events_a = auth_events_for(user_a_id)
        events_b = auth_events_for(user_b_id)
        empty = TemporalCorrelationEvidence.empty_auth_pattern_evidence.merge(
          "auth_pattern_history_complete" => pattern_history_complete?,
        )
        return empty if events_a.empty? || events_b.empty?

        shared_ip_set = Array(shared_ips).map { |value| IpNormalizer.normalize(value) }.compact.to_set
        if shared_ip_set.empty?
          shared_ip_set = auth_events_by_ip(user_a_id).keys.to_set & auth_events_by_ip(user_b_id).keys.to_set
        end

        proximity_details = build_auth_proximity_details(
          auth_events_by_ip(user_a_id),
          auth_events_by_ip(user_b_id),
          shared_ip_set,
        )
        proximity_totals = AUTH_PROXIMITY_WINDOWS.keys.to_h do |key|
          [key, proximity_details.sum { |detail| detail[key.to_s].to_i }]
        end
        same_client = proximity_details.sum { |detail| detail["same_client_within_30m_count"].to_i }
        public_proximity_ips = proximity_details.count do |detail|
          detail["public"] == true && detail["within_30m_count"].to_i.positive?
        end
        public_proximity_24h = proximity_details.count do |detail|
          detail["public"] == true && detail["within_24h_count"].to_i.positive?
        end
        public_proximity_7d = proximity_details.count do |detail|
          detail["public"] == true && detail["within_7d_count"].to_i.positive?
        end

        signature_summary = shared_client_signature_summary(user_a_id, user_b_id)
        transition_summary = shared_public_transition_summary(user_a_id, user_b_id)

        TemporalCorrelationEvidence.empty_auth_pattern_evidence.merge(
          "auth_pattern_evidence_version" => AUTH_PATTERN_EVIDENCE_VERSION,
          "auth_pattern_history_complete" => pattern_history_complete?,
          "auth_proximity_closest_gap_seconds" => max_detail_value(proximity_details, "closest_gap_seconds", mode: :min),
          "auth_proximity_within_5m_count" => proximity_totals[:within_5m_count],
          "auth_proximity_within_30m_count" => proximity_totals[:within_30m_count],
          "auth_proximity_within_1h_count" => proximity_totals[:within_1h_count],
          "auth_proximity_within_6h_count" => proximity_totals[:within_6h_count],
          "auth_proximity_within_24h_count" => proximity_totals[:within_24h_count],
          "auth_proximity_within_72h_count" => proximity_totals[:within_72h_count],
          "auth_proximity_within_7d_count" => proximity_totals[:within_7d_count],
          "auth_proximity_same_client_within_30m_count" => same_client,
          "auth_proximity_public_ip_count" => public_proximity_ips,
          "auth_proximity_public_ip_within_24h_count" => public_proximity_24h,
          "auth_proximity_public_ip_within_7d_count" => public_proximity_7d,
          "auth_proximity_details" => proximity_details.first(MAX_AUTH_PROXIMITY_DETAILS),
          "auth_proximity_details_truncated" => proximity_details.length > MAX_AUTH_PROXIMITY_DETAILS,
          "shared_auth_client_signature_count" => signature_summary[:count],
          "repeated_shared_auth_client_signature_count" => signature_summary[:repeated_count],
          "shared_auth_client_signature_paired_observations" => signature_summary[:paired_observations],
          "max_shared_auth_client_signature_users" => signature_summary[:max_users],
          "auth_client_signature_population_complete" => @population_complete,
          # Keep the legacy match_count key for stored-evidence compatibility.
          # v3 receives separate long-horizon alignment and population context.
          "public_ip_transition_match_count" => transition_summary[:pattern_count],
          "public_ip_transition_pattern_count" => transition_summary[:pattern_count],
          "public_ip_transition_closest_gap_seconds" => transition_summary[:closest_gap_seconds],
          "aligned_public_ip_transition_1h_count" => transition_summary[:within_1h_count],
          "aligned_public_ip_transition_6h_count" => transition_summary[:within_6h_count],
          "aligned_public_ip_transition_24h_count" => transition_summary[:within_24h_count],
          "aligned_public_ip_transition_3d_count" => transition_summary[:within_3d_count],
          "aligned_public_ip_transition_7d_count" => transition_summary[:within_7d_count],
          "aligned_public_ip_transition_30d_count" => transition_summary[:within_30d_count],
          "aligned_public_ip_transition_90d_count" => transition_summary[:within_90d_count],
          "aligned_public_ip_transition_180d_count" => transition_summary[:within_180d_count],
          "public_ip_transition_beyond_180d_count" => transition_summary[:beyond_180d_count],
          "public_ip_transition_unaligned_count" => transition_summary[:unaligned_count],
          "public_ip_transition_population_complete" => transition_summary[:population_complete],
          "max_public_ip_transition_users" => transition_summary[:max_users],
          "max_public_ip_transition_users_24h" => transition_summary[:max_users_24h],
          "max_public_ip_transition_users_7d" => transition_summary[:max_users_7d],
          "public_ip_transition_details" => transition_summary[:details].first(MAX_TRANSITION_DETAILS),
          "public_ip_transition_details_truncated" => transition_summary[:details].length > MAX_TRANSITION_DETAILS,
          "auth_pattern_score_effect" => "none",
        ).compact
      end

      def build_auth_proximity_details(events_by_ip_a, events_by_ip_b, shared_ip_set)
        shared_ip_set.filter_map do |ip|
          a = events_by_ip_a[ip]
          b = events_by_ip_b[ip]
          next if a.blank? || b.blank?

          closest = closest_event_pair(a, b)
          next if closest.nil? || closest[:gap] > AUTH_PROXIMITY_WINDOW

          detail = {
            "ip_address" => ip,
            "public" => public_ip?(ip),
            "closest_gap_seconds" => closest[:gap],
          }
          matches_by_window = AUTH_PROXIMITY_WINDOWS.to_h do |key, seconds|
            [key, matched_event_pairs(a, b, seconds)]
          end
          matches_by_window.each { |key, matches| detail[key.to_s] = matches.length }

          close_matches = matches_by_window[:within_30m_count]
          detail["same_client_within_30m_count"] = close_matches.count do |match|
            signature_a = match[:a][:signature]
            signature_b = match[:b][:signature]
            signature_a.present? && signature_a == signature_b
          end
          detail
        end.sort_by { |detail| [detail["closest_gap_seconds"].to_i, detail["ip_address"].to_s] }
      end

      def matched_event_pairs(events_a, events_b, window_seconds)
        # auth_events_by_ip is derived from auth_events_for, which is already
        # normalized and sorted by observed time. Avoid re-sorting the same
        # bounded arrays for every proximity horizon during large scans.
        a = events_a
        b = events_b
        i = 0
        j = 0
        matches = []

        while i < a.length && j < b.length
          left = a[i]
          right = b[j]
          gap = (left[:at] - right[:at]).abs.to_i

          if gap <= window_seconds
            matches << { a: left, b: right, gap: gap }
            i += 1
            j += 1
          elsif left[:at] < right[:at]
            i += 1
          else
            j += 1
          end
        end

        matches
      end

      def shared_client_signature_summary(user_a_id, user_b_id)
        a = auth_signature_counts(user_a_id)
        b = auth_signature_counts(user_b_id)
        shared = a.keys & b.keys
        return { count: 0, repeated_count: 0, paired_observations: 0, max_users: nil } if shared.empty?

        max_users =
          if @population_complete
            shared.map { |signature| @auth_signature_users[signature].length }.max.to_i
          end

        {
          count: shared.length,
          repeated_count: shared.count { |signature| a[signature].to_i >= 2 && b[signature].to_i >= 2 },
          paired_observations: shared.sum { |signature| [a[signature].to_i, b[signature].to_i].min },
          max_users: max_users,
        }
      end

      def shared_public_transition_summary(user_a_id, user_b_id)
        transitions_a = public_transition_times_for(user_a_id)
        transitions_b = public_transition_times_for(user_b_id)
        shared_keys = transitions_a.keys & transitions_b.keys
        population_complete = @population_complete && pattern_history_complete?

        details = shared_keys.filter_map do |key|
          closest = closest_pair(transitions_a[key], transitions_b[key])
          next if closest.nil?

          detail = {
            "from_ip" => key[0],
            "to_ip" => key[1],
            "closest_transition_gap_seconds" => closest[:gap],
            "transition_population_complete" => population_complete,
          }
          if population_complete
            population = transition_population_for(key)
            center = midpoint(closest[:a], closest[:b])
            detail["transition_user_count"] = population.length
            detail["transition_user_count_24h"] =
              closest[:gap] <= 24.hours.to_i ? population_count_for_transition(population, center, 24.hours.to_i) : nil
            detail["transition_user_count_7d"] =
              closest[:gap] <= 7.days.to_i ? population_count_for_transition(population, center, 7.days.to_i) : nil
          end
          detail.compact
        end
        details.sort_by! { |detail| [detail["closest_transition_gap_seconds"].to_i, detail["from_ip"], detail["to_ip"]] }

        counts = TRANSITION_ALIGNMENT_WINDOWS.keys.to_h do |key|
          seconds = TRANSITION_ALIGNMENT_WINDOWS[key]
          [key, details.count { |detail| detail["closest_transition_gap_seconds"].to_i <= seconds }]
        end

        {
          pattern_count: shared_keys.length,
          closest_gap_seconds: max_detail_value(details, "closest_transition_gap_seconds", mode: :min),
          within_1h_count: counts[:within_1h_count],
          within_6h_count: counts[:within_6h_count],
          within_24h_count: counts[:within_24h_count],
          within_3d_count: counts[:within_3d_count],
          within_7d_count: counts[:within_7d_count],
          within_30d_count: counts[:within_30d_count],
          within_90d_count: counts[:within_90d_count],
          within_180d_count: counts[:within_180d_count],
          beyond_180d_count: [shared_keys.length - counts[:within_180d_count], 0].max,
          # Legacy meaning: patterns not aligned within seven days.
          unaligned_count: [shared_keys.length - counts[:within_7d_count], 0].max,
          population_complete: population_complete,
          max_users: max_detail_value(details, "transition_user_count"),
          max_users_24h: max_detail_value(details, "transition_user_count_24h"),
          max_users_7d: max_detail_value(details, "transition_user_count_7d"),
          details: details,
        }
      end

      def auth_events_for(user_id)
        user_id = user_id.to_i
        @normalized_auth_events_cache[user_id] ||= normalized_auth_events(@auth_events_by_user[user_id])
      end

      def auth_events_by_ip(user_id)
        user_id = user_id.to_i
        @auth_events_by_ip_cache[user_id] ||= auth_events_for(user_id).group_by { |event| event[:ip] }
      end

      def auth_signature_counts(user_id)
        user_id = user_id.to_i
        @auth_signature_counts_cache[user_id] ||= auth_events_for(user_id).filter_map { |event| event[:signature] }.tally
      end

      def public_transition_times_for(user_id)
        user_id = user_id.to_i
        @public_transition_times_cache[user_id] ||= public_transition_times(auth_events_for(user_id))
      end

      def public_transition_times(events)
        public_events = events.select { |event| public_ip?(event[:ip]) }.sort_by { |event| event[:at] }
        collapsed = []
        public_events.each do |event|
          if collapsed.empty? || collapsed.last[:ip] != event[:ip]
            collapsed << event
          else
            # Keep the latest observation on the same IP so the transition time
            # reflects when the next distinct public IP was first observed.
            collapsed[-1] = event
          end
        end

        transitions = Hash.new { |hash, key| hash[key] = [] }
        collapsed.each_cons(2) do |from, to|
          next if from[:ip] == to[:ip]
          transitions[[from[:ip], to[:ip]]] << to[:at]
        end
        transitions
      end

      def transition_population_for(key)
        public_transition_population[key] || {}
      end

      def public_transition_population
        @public_transition_population_cache ||= begin
          population = Hash.new { |hash, key| hash[key] = Hash.new { |users, user_id| users[user_id] = [] } }
          @auth_events_by_user.keys.sort.each do |user_id|
            public_transition_times_for(user_id).each do |key, times|
              population[key][user_id].concat(times)
            end
          end
          population
        end
      end

      def population_count_for_transition(population, center, window_seconds)
        start_at = center - (window_seconds / 2.0)
        end_at = center + (window_seconds / 2.0)
        population.count do |_user_id, times|
          time_in_range?(normalized_times(times), start_at, end_at)
        end
      end

      def population_count_for_ip(ip, center, window_seconds)
        start_at = center - (window_seconds / 2.0)
        end_at = center + (window_seconds / 2.0)
        @times_by_ip[ip].count do |user_id, times|
          cache_key = [ip, user_id]
          normalized = @normalized_ip_population_times_cache[cache_key] ||= normalized_times(times)
          time_in_range?(normalized, start_at, end_at)
        end
      end

      def time_in_range?(times, start_at, end_at)
        candidate = times.bsearch { |value| value >= start_at }
        candidate.present? && candidate <= end_at
      end

      def midpoint(left, right)
        Time.at((left.to_f + right.to_f) / 2.0).in_time_zone
      end

      def closest_event_pair(events_a, events_b)
        closest_pair(
          Array(events_a).map { |event| event[:at] }.compact.sort,
          Array(events_b).map { |event| event[:at] }.compact.sort,
        )
      end

      def max_detail_value(details, key, mode: :max)
        values = Array(details).filter_map do |detail|
          value = detail[key]
          value.nil? ? nil : value.to_i
        end
        return nil if values.empty?

        mode == :min ? values.min : values.max
      end

      def normalized_auth_events(values)
        ordered = Array(values).compact.sort_by { |event| [event[:at], event[:source].to_s] }
        collapsed = []
        ordered.each do |event|
          previous = collapsed.last
          duplicate = previous && previous[:ip] == event[:ip] && previous[:signature] == event[:signature] &&
            (event[:at] - previous[:at]).abs <= EVENT_DEDUP_WINDOW
          if duplicate
            # A login and the first page observation often occur seconds apart.
            # Keep one event, preferring the authentication event when present.
            collapsed[-1] = event if previous[:source] != "auth_session" && event[:source] == "auth_session"
          else
            collapsed << event
          end
        end
        collapsed
      end

      def pattern_history_complete?
        @auth_history_complete && @session_history_complete
      end

      def normalized_times(values)
        Array(values).compact.uniq.sort
      end

      def closest_pair(times_a, times_b)
        index_a = 0
        index_b = 0
        best = nil

        while index_a < times_a.length && index_b < times_b.length
          a = times_a[index_a]
          b = times_b[index_b]
          gap = (a - b).abs.to_i
          if best.nil? || gap < best[:gap]
            best = { gap: gap, a: a, b: b }
          end
          break if best[:gap].zero?

          if a < b
            index_a += 1
          else
            index_b += 1
          end
        end

        best
      end

      def closest_gap(times_a, times_b)
        closest_pair(times_a, times_b)&.dig(:gap)
      end

      def count_within(details, seconds)
        details.count { |detail| detail["closest_gap_seconds"].to_i <= seconds }
      end

      def public_ip?(ip)
        return @public_cache[ip] if @public_cache.key?(ip)
        @public_cache[ip] = IpNormalizer.normalize_public(ip).present?
      end

      def normalize_time(value)
        return value.in_time_zone if value.respond_to?(:in_time_zone)
        Time.zone.parse(value.to_s) if value.present?
      rescue ArgumentError, TypeError
        nil
      end
    end

    def build_scan_index
      index = ScanIndex.new(population_complete: false)
      user_ids = User.human_users.where(staged: false).where("users.id > 0").pluck(:id)
      return index if user_ids.blank?

      User.human_users
        .where(id: user_ids, staged: false)
        .where.not(registration_ip_address: nil)
        .pluck(:id, :registration_ip_address, :created_at)
        .each { |user_id, ip, at| index.add(user_id, ip, "registration", at) }

      if defined?(::UserIpAddressHistory)
        ::UserIpAddressHistory
          .where(user_id: user_ids)
          .where.not(ip_address: nil)
          .pluck(:user_id, :ip_address, :created_at)
          .each { |user_id, ip, at| index.add(user_id, ip, "history", at) }
      end

      auth_log_truncated = true
      if defined?(::UserAuthTokenLog)
        rows =
          ::UserAuthTokenLog
            .where(user_id: user_ids, action: "generate")
            .where.not(client_ip: nil)
            .order(created_at: :desc, id: :desc)
            .limit(MAX_AUTH_ROWS + 1)
            .pluck(:user_id, :client_ip, :user_agent, :created_at)
        auth_log_truncated = rows.length > MAX_AUTH_ROWS
        if auth_log_truncated
          index.mark_auth_log_truncated!
          rows = rows.first(MAX_AUTH_ROWS)
        end
        rows.each { |user_id, ip, user_agent, at| index.add_auth_event(user_id, ip, user_agent, at) }
        index.mark_auth_history_complete! unless auth_log_truncated
      end

      session_history_truncated = false
      if defined?(::AccountSecurity::SessionObservation) && SiteSetting.account_security_session_observation_enabled
        rows =
          SessionObservation
            .where(user_id: user_ids)
            .where("observed_at >= ?", SESSION_OBSERVATION_EVIDENCE_HORIZON.ago)
            .order(observed_at: :desc, id: :desc)
            .limit(MAX_SESSION_OBSERVATION_ROWS + 1)
            .pluck(:user_id, :ip_address, :client_signature_hash, :observed_at)
        session_history_truncated = rows.length > MAX_SESSION_OBSERVATION_ROWS
        if session_history_truncated
          index.mark_session_log_truncated!
          rows = rows.first(MAX_SESSION_OBSERVATION_ROWS)
        end
        rows.each { |user_id, ip, signature, at| index.add_session_event(user_id, ip, signature, at) }
        index.mark_session_history_complete! unless session_history_truncated
      end

      index.mark_population_complete! if !auth_log_truncated && !session_history_truncated
      index
    rescue ActiveRecord::StatementInvalid => e
      Rails.logger.warn("[account_security] temporal correlation scan index failed class=#{e.class}")
      ScanIndex.new
    end

    def for_pair(user_a_id, user_b_id, shared_ips: nil)
      ids = [user_a_id.to_i, user_b_id.to_i].uniq.select(&:positive?)
      return empty_evidence if ids.length != 2

      index = ScanIndex.new(population_complete: false)
      User.human_users
        .where(id: ids, staged: false)
        .where.not(registration_ip_address: nil)
        .pluck(:id, :registration_ip_address, :created_at)
        .each { |user_id, ip, at| index.add(user_id, ip, "registration", at) }

      if defined?(::UserIpAddressHistory)
        ::UserIpAddressHistory
          .where(user_id: ids)
          .where.not(ip_address: nil)
          .pluck(:user_id, :ip_address, :created_at)
          .each { |user_id, ip, at| index.add(user_id, ip, "history", at) }
      end

      auth_history_truncated = false
      if defined?(::UserAuthTokenLog)
        ids.sort.each do |user_id|
          rows =
            ::UserAuthTokenLog
              .where(user_id: user_id, action: "generate")
              .where.not(client_ip: nil)
              .order(created_at: :desc, id: :desc)
              .limit(MAX_PAIR_AUTH_ROWS_PER_USER + 1)
              .pluck(:user_id, :client_ip, :user_agent, :created_at)
          if rows.length > MAX_PAIR_AUTH_ROWS_PER_USER
            auth_history_truncated = true
            rows = rows.first(MAX_PAIR_AUTH_ROWS_PER_USER)
          end
          rows.each { |id, ip, user_agent, at| index.add_auth_event(id, ip, user_agent, at) }
        end
        index.mark_auth_history_complete! unless auth_history_truncated
      end

      session_history_truncated = false
      if defined?(::AccountSecurity::SessionObservation) && SiteSetting.account_security_session_observation_enabled
        ids.sort.each do |user_id|
          rows =
            SessionObservation
              .where(user_id: user_id)
              .where("observed_at >= ?", SESSION_OBSERVATION_EVIDENCE_HORIZON.ago)
              .order(observed_at: :desc, id: :desc)
              .limit(MAX_PAIR_SESSION_OBSERVATION_ROWS_PER_USER + 1)
              .pluck(:user_id, :ip_address, :client_signature_hash, :observed_at)
          if rows.length > MAX_PAIR_SESSION_OBSERVATION_ROWS_PER_USER
            session_history_truncated = true
            rows = rows.first(MAX_PAIR_SESSION_OBSERVATION_ROWS_PER_USER)
          end
          rows.each { |id, ip, signature, at| index.add_session_event(id, ip, signature, at) }
        end
        index.mark_session_history_complete! unless session_history_truncated
        index.mark_session_log_truncated! if session_history_truncated
      end

      index.evidence_for_pair(user_a_id, user_b_id, shared_ips: shared_ips)
    rescue ActiveRecord::StatementInvalid => e
      Rails.logger.warn("[account_security] temporal correlation pair lookup failed class=#{e.class}")
      empty_evidence
    end

    def empty_auth_pattern_evidence
      {
        "auth_pattern_evidence_version" => AUTH_PATTERN_EVIDENCE_VERSION,
        "auth_pattern_history_complete" => false,
        "auth_proximity_closest_gap_seconds" => nil,
        "auth_proximity_within_5m_count" => 0,
        "auth_proximity_within_30m_count" => 0,
        "auth_proximity_within_1h_count" => 0,
        "auth_proximity_within_6h_count" => 0,
        "auth_proximity_within_24h_count" => 0,
        "auth_proximity_within_72h_count" => 0,
        "auth_proximity_within_7d_count" => 0,
        "auth_proximity_same_client_within_30m_count" => 0,
        "auth_proximity_public_ip_count" => 0,
        "auth_proximity_public_ip_within_24h_count" => 0,
        "auth_proximity_public_ip_within_7d_count" => 0,
        "auth_proximity_details" => [],
        "auth_proximity_details_truncated" => false,
        "shared_auth_client_signature_count" => 0,
        "repeated_shared_auth_client_signature_count" => 0,
        "shared_auth_client_signature_paired_observations" => 0,
        "max_shared_auth_client_signature_users" => nil,
        "auth_client_signature_population_complete" => false,
        "public_ip_transition_match_count" => 0,
        "public_ip_transition_pattern_count" => 0,
        "public_ip_transition_closest_gap_seconds" => nil,
        "aligned_public_ip_transition_1h_count" => 0,
        "aligned_public_ip_transition_6h_count" => 0,
        "aligned_public_ip_transition_24h_count" => 0,
        "aligned_public_ip_transition_3d_count" => 0,
        "aligned_public_ip_transition_7d_count" => 0,
        "aligned_public_ip_transition_30d_count" => 0,
        "aligned_public_ip_transition_90d_count" => 0,
        "aligned_public_ip_transition_180d_count" => 0,
        "public_ip_transition_beyond_180d_count" => 0,
        "public_ip_transition_unaligned_count" => 0,
        "public_ip_transition_population_complete" => false,
        "max_public_ip_transition_users" => nil,
        "max_public_ip_transition_users_24h" => nil,
        "max_public_ip_transition_users_7d" => nil,
        "public_ip_transition_details" => [],
        "public_ip_transition_details_truncated" => false,
        "auth_pattern_score_effect" => "none",
      }
    end

    def empty_evidence
      {
        "temporal_evidence_version" => EVIDENCE_VERSION,
        "temporal_auth_history_complete" => false,
        "session_observation_history_complete" => !SiteSetting.account_security_session_observation_enabled,
        "combined_session_login_history_complete" => false,
        "session_observation_evidence_horizon_days" => (SESSION_OBSERVATION_EVIDENCE_HORIZON / 1.day).to_i,
        "temporal_ip_population_complete" => false,
        "temporal_population_window_basis" => "closest_pair_midpoint",
        "timed_shared_ip_count" => 0,
        "temporal_within_15m_count" => 0,
        "temporal_within_1h_count" => 0,
        "temporal_within_6h_count" => 0,
        "temporal_within_24h_count" => 0,
        "temporal_within_72h_count" => 0,
        "temporal_within_7d_count" => 0,
        "temporal_public_within_24h_count" => 0,
        "temporal_public_within_7d_count" => 0,
        "temporal_repeated_public_alignment" => false,
        "closest_shared_ip_gap_seconds" => nil,
        "max_temporal_ip_users_24h" => nil,
        "max_temporal_ip_users_7d" => nil,
        "max_temporal_ip_users_30d" => nil,
        "temporal_ip_details" => [],
        "temporal_ip_details_truncated" => false,
        "temporal_score_effect" => "none",
      }.merge(empty_auth_pattern_evidence)
    end
  end
end
