# frozen_string_literal: true

require "set"

module ::AccountSecurity
  module TemporalCorrelationEvidence
    module_function

    EVIDENCE_VERSION = 2
    AUTH_PATTERN_EVIDENCE_VERSION = 1
    MAX_AUTH_ROWS = 100_000
    MAX_PAIR_AUTH_ROWS_PER_USER = 5_000
    MAX_DETAILS = 8
    MAX_AUTH_PROXIMITY_DETAILS = 6
    MAX_TRANSITION_DETAILS = 6
    AUTH_PROXIMITY_WINDOW = 30.minutes.to_i
    AUTH_TIGHT_PROXIMITY_WINDOW = 5.minutes.to_i
    TRANSITION_ALIGNMENT_WINDOW = 7.days.to_i
    TRANSITION_TIGHT_ALIGNMENT_WINDOW = 24.hours.to_i
    TIMED_SOURCES = %w[registration history auth_session].freeze

    class ScanIndex
      attr_reader :diagnostics

      def initialize(population_complete: false)
        @times_by_user = Hash.new do |users, user_id|
          users[user_id] = Hash.new { |ips, ip| ips[ip] = [] }
        end
        @auth_events_by_user = Hash.new { |hash, user_id| hash[user_id] = [] }
        @auth_signature_users = Hash.new { |hash, signature| hash[signature] = Set.new }
        @normalized_auth_events_cache = {}
        @auth_events_by_ip_cache = {}
        @auth_signature_counts_cache = {}
        @public_transition_times_cache = {}
        @public_cache = {}
        @population_complete = population_complete == true
        @diagnostics = {
          temporal_observation_rows: 0,
          temporal_registration_rows: 0,
          temporal_history_rows: 0,
          temporal_auth_session_rows: 0,
          temporal_auth_log_truncated: false,
          auth_pattern_rows: 0,
          auth_pattern_signature_rows: 0,
        }
      end

      def mark_population_complete!
        @population_complete = true
      end

      def add(user_id, ip_value, source, observed_at)
        user_id = user_id.to_i
        source = source.to_s
        return if user_id <= 0 || !TIMED_SOURCES.include?(source)

        ip = IpNormalizer.normalize(ip_value)
        time = normalize_time(observed_at)
        return if ip.blank? || time.blank?

        @times_by_user[user_id][ip] << time
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
        }
        @auth_events_by_user[user_id] << event
        @normalized_auth_events_cache.delete(user_id)
        @auth_events_by_ip_cache.delete(user_id)
        @auth_signature_counts_cache.delete(user_id)
        @public_transition_times_cache.delete(user_id)
        diagnostics[:auth_pattern_rows] += 1

        if signature.present?
          @auth_signature_users[signature] << user_id
          diagnostics[:auth_pattern_signature_rows] += 1
        end
      end

      def mark_auth_log_truncated!
        diagnostics[:temporal_auth_log_truncated] = true
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

          gap_seconds = closest_gap(times_a, times_b)
          next if gap_seconds.nil?

          {
            "ip_address" => ip,
            "public" => public_ip?(ip),
            "closest_gap_seconds" => gap_seconds,
            "observations_a" => times_a.length,
            "observations_b" => times_b.length,
          }
        end

        details.sort_by! { |detail| [detail["closest_gap_seconds"].to_i, detail["ip_address"].to_s] }
        closest_gap = details.map { |detail| detail["closest_gap_seconds"].to_i }.min
        within_15m = count_within(details, 15.minutes.to_i)
        within_1h = count_within(details, 1.hour.to_i)
        within_24h = count_within(details, 24.hours.to_i)
        within_7d = count_within(details, 7.days.to_i)
        public_within_24h = details.count do |detail|
          detail["public"] == true && detail["closest_gap_seconds"].to_i <= 24.hours.to_i
        end

        {
          "temporal_evidence_version" => EVIDENCE_VERSION,
          "timed_shared_ip_count" => details.length,
          "temporal_within_15m_count" => within_15m,
          "temporal_within_1h_count" => within_1h,
          "temporal_within_24h_count" => within_24h,
          "temporal_within_7d_count" => within_7d,
          "temporal_public_within_24h_count" => public_within_24h,
          "temporal_repeated_public_alignment" => public_within_24h >= 2,
          "closest_shared_ip_gap_seconds" => closest_gap,
          "temporal_ip_details" => details.first(MAX_DETAILS),
          "temporal_ip_details_truncated" => details.length > MAX_DETAILS,
          "temporal_score_effect" => "none",
        }.merge(authentication_pattern_evidence(user_a_id, user_b_id, shared_ips: ips))
      end

      private

      def authentication_pattern_evidence(user_a_id, user_b_id, shared_ips:)
        events_a = auth_events_for(user_a_id)
        events_b = auth_events_for(user_b_id)
        return TemporalCorrelationEvidence.empty_auth_pattern_evidence if events_a.empty? || events_b.empty?

        shared_ip_set = Array(shared_ips).map { |value| IpNormalizer.normalize(value) }.compact.to_set
        if shared_ip_set.empty?
          shared_ip_set = auth_events_by_ip(user_a_id).keys.to_set & auth_events_by_ip(user_b_id).keys.to_set
        end

        proximity_details = build_auth_proximity_details(
          auth_events_by_ip(user_a_id),
          auth_events_by_ip(user_b_id),
          shared_ip_set,
        )
        close_30m = proximity_details.sum { |detail| detail["within_30m_count"].to_i }
        close_5m = proximity_details.sum { |detail| detail["within_5m_count"].to_i }
        same_client = proximity_details.sum { |detail| detail["same_client_within_30m_count"].to_i }
        public_proximity_ips = proximity_details.count do |detail|
          detail["public"] == true && detail["within_30m_count"].to_i.positive?
        end

        signature_summary = shared_client_signature_summary(user_a_id, user_b_id)
        transition_summary = shared_public_transition_summary(user_a_id, user_b_id)

        TemporalCorrelationEvidence.empty_auth_pattern_evidence.merge(
          "auth_pattern_evidence_version" => AUTH_PATTERN_EVIDENCE_VERSION,
          "auth_proximity_within_5m_count" => close_5m,
          "auth_proximity_within_30m_count" => close_30m,
          "auth_proximity_same_client_within_30m_count" => same_client,
          "auth_proximity_public_ip_count" => public_proximity_ips,
          "auth_proximity_details" => proximity_details.first(MAX_AUTH_PROXIMITY_DETAILS),
          "auth_proximity_details_truncated" => proximity_details.length > MAX_AUTH_PROXIMITY_DETAILS,
          "shared_auth_client_signature_count" => signature_summary[:count],
          "repeated_shared_auth_client_signature_count" => signature_summary[:repeated_count],
          "shared_auth_client_signature_paired_observations" => signature_summary[:paired_observations],
          "max_shared_auth_client_signature_users" => signature_summary[:max_users],
          "auth_client_signature_population_complete" => @population_complete,
          "public_ip_transition_match_count" => transition_summary[:match_count],
          "aligned_public_ip_transition_24h_count" => transition_summary[:within_24h_count],
          "aligned_public_ip_transition_7d_count" => transition_summary[:within_7d_count],
          "public_ip_transition_details" => transition_summary[:details].first(MAX_TRANSITION_DETAILS),
          "public_ip_transition_details_truncated" => transition_summary[:details].length > MAX_TRANSITION_DETAILS,
          "auth_pattern_score_effect" => "none",
        )
      end

      def build_auth_proximity_details(events_by_ip_a, events_by_ip_b, shared_ip_set)
        shared_ip_set.filter_map do |ip|
          a = events_by_ip_a[ip]
          b = events_by_ip_b[ip]
          next if a.blank? || b.blank?

          matches = matched_event_pairs(a, b, AUTH_PROXIMITY_WINDOW)
          next if matches.empty?

          {
            "ip_address" => ip,
            "public" => public_ip?(ip),
            "closest_gap_seconds" => matches.map { |match| match[:gap] }.min,
            "within_5m_count" => matches.count { |match| match[:gap] <= AUTH_TIGHT_PROXIMITY_WINDOW },
            "within_30m_count" => matches.length,
            "same_client_within_30m_count" => matches.count do |match|
              signature_a = match[:a][:signature]
              signature_b = match[:b][:signature]
              signature_a.present? && signature_a == signature_b
            end,
          }
        end.sort_by { |detail| [detail["closest_gap_seconds"].to_i, detail["ip_address"].to_s] }
      end

      def matched_event_pairs(events_a, events_b, window_seconds)
        a = events_a.sort_by { |event| event[:at] }
        b = events_b.sort_by { |event| event[:at] }
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

        details = shared_keys.filter_map do |key|
          gap = closest_gap(transitions_a[key], transitions_b[key])
          next if gap.nil? || gap > TRANSITION_ALIGNMENT_WINDOW

          {
            "from_ip" => key[0],
            "to_ip" => key[1],
            "closest_transition_gap_seconds" => gap,
          }
        end
        details.sort_by! { |detail| [detail["closest_transition_gap_seconds"].to_i, detail["from_ip"], detail["to_ip"]] }

        {
          match_count: shared_keys.length,
          within_24h_count: details.count { |detail| detail["closest_transition_gap_seconds"].to_i <= TRANSITION_TIGHT_ALIGNMENT_WINDOW },
          within_7d_count: details.length,
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

      def normalized_auth_events(values)
        Array(values).compact.uniq { |event| [event[:ip], event[:at], event[:signature]] }.sort_by { |event| event[:at] }
      end

      def normalized_times(values)
        Array(values).compact.uniq.sort
      end

      def closest_gap(times_a, times_b)
        index_a = 0
        index_b = 0
        best = nil

        while index_a < times_a.length && index_b < times_b.length
          a = times_a[index_a]
          b = times_b[index_b]
          gap = (a - b).abs.to_i
          best = gap if best.nil? || gap < best
          break if best.zero?

          if a < b
            index_a += 1
          else
            index_b += 1
          end
        end

        best
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

      if defined?(::UserAuthTokenLog)
        rows =
          ::UserAuthTokenLog
            .where(user_id: user_ids, action: "generate")
            .where.not(client_ip: nil)
            .order(created_at: :desc)
            .limit(MAX_AUTH_ROWS + 1)
            .pluck(:user_id, :client_ip, :user_agent, :created_at)
        auth_log_truncated = rows.length > MAX_AUTH_ROWS
        if auth_log_truncated
          index.mark_auth_log_truncated!
          rows = rows.first(MAX_AUTH_ROWS)
        end
        rows.each { |user_id, ip, user_agent, at| index.add_auth_event(user_id, ip, user_agent, at) }
        index.mark_population_complete! unless auth_log_truncated
      end

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

      if defined?(::UserAuthTokenLog)
        ids.each do |user_id|
          ::UserAuthTokenLog
            .where(user_id: user_id, action: "generate")
            .where.not(client_ip: nil)
            .order(created_at: :desc)
            .limit(MAX_PAIR_AUTH_ROWS_PER_USER)
            .pluck(:user_id, :client_ip, :user_agent, :created_at)
            .each { |id, ip, user_agent, at| index.add_auth_event(id, ip, user_agent, at) }
        end
      end

      index.evidence_for_pair(user_a_id, user_b_id, shared_ips: shared_ips)
    rescue ActiveRecord::StatementInvalid => e
      Rails.logger.warn("[account_security] temporal correlation pair lookup failed class=#{e.class}")
      empty_evidence
    end

    def empty_auth_pattern_evidence
      {
        "auth_pattern_evidence_version" => AUTH_PATTERN_EVIDENCE_VERSION,
        "auth_proximity_within_5m_count" => 0,
        "auth_proximity_within_30m_count" => 0,
        "auth_proximity_same_client_within_30m_count" => 0,
        "auth_proximity_public_ip_count" => 0,
        "auth_proximity_details" => [],
        "auth_proximity_details_truncated" => false,
        "shared_auth_client_signature_count" => 0,
        "repeated_shared_auth_client_signature_count" => 0,
        "shared_auth_client_signature_paired_observations" => 0,
        "max_shared_auth_client_signature_users" => nil,
        "auth_client_signature_population_complete" => false,
        "public_ip_transition_match_count" => 0,
        "aligned_public_ip_transition_24h_count" => 0,
        "aligned_public_ip_transition_7d_count" => 0,
        "public_ip_transition_details" => [],
        "public_ip_transition_details_truncated" => false,
        "auth_pattern_score_effect" => "none",
      }
    end

    def empty_evidence
      {
        "temporal_evidence_version" => EVIDENCE_VERSION,
        "timed_shared_ip_count" => 0,
        "temporal_within_15m_count" => 0,
        "temporal_within_1h_count" => 0,
        "temporal_within_24h_count" => 0,
        "temporal_within_7d_count" => 0,
        "temporal_public_within_24h_count" => 0,
        "temporal_repeated_public_alignment" => false,
        "closest_shared_ip_gap_seconds" => nil,
        "temporal_ip_details" => [],
        "temporal_ip_details_truncated" => false,
        "temporal_score_effect" => "none",
      }.merge(empty_auth_pattern_evidence)
    end
  end
end
