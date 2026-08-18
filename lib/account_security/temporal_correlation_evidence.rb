# frozen_string_literal: true

module ::AccountSecurity
  module TemporalCorrelationEvidence
    module_function

    EVIDENCE_VERSION = 1
    MAX_AUTH_ROWS = 100_000
    MAX_PAIR_AUTH_ROWS_PER_USER = 5_000
    MAX_DETAILS = 8
    TIMED_SOURCES = %w[registration history auth_session].freeze

    class ScanIndex
      attr_reader :diagnostics

      def initialize
        @times_by_user = Hash.new do |users, user_id|
          users[user_id] = Hash.new { |ips, ip| ips[ip] = [] }
        end
        @public_cache = {}
        @diagnostics = {
          temporal_observation_rows: 0,
          temporal_registration_rows: 0,
          temporal_history_rows: 0,
          temporal_auth_session_rows: 0,
          temporal_auth_log_truncated: false,
        }
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
        }
      end

      private

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
      index = ScanIndex.new
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
            .pluck(:user_id, :client_ip, :created_at)
        if rows.length > MAX_AUTH_ROWS
          index.mark_auth_log_truncated!
          rows = rows.first(MAX_AUTH_ROWS)
        end
        rows.each { |user_id, ip, at| index.add(user_id, ip, "auth_session", at) }
      end

      index
    rescue ActiveRecord::StatementInvalid => e
      Rails.logger.warn("[account_security] temporal correlation scan index failed class=#{e.class}")
      ScanIndex.new
    end

    def for_pair(user_a_id, user_b_id, shared_ips: nil)
      ids = [user_a_id.to_i, user_b_id.to_i].uniq.select(&:positive?)
      return empty_evidence if ids.length != 2

      index = ScanIndex.new
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
            .pluck(:user_id, :client_ip, :created_at)
            .each { |id, ip, at| index.add(id, ip, "auth_session", at) }
        end
      end

      index.evidence_for_pair(user_a_id, user_b_id, shared_ips: shared_ips)
    rescue ActiveRecord::StatementInvalid => e
      Rails.logger.warn("[account_security] temporal correlation pair lookup failed class=#{e.class}")
      empty_evidence
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
      }
    end
  end
end
