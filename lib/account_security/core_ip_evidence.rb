# frozen_string_literal: true

require "set"

module ::AccountSecurity
  module CoreIpEvidence
    module_function

    SOURCES = %w[registration current history auth_session active_session].freeze
    MAX_STORED_SHARED_IPS = 12
    MAX_AUTH_INDEX_ROWS = 100_000

    class ScanIndex
      attr_reader :diagnostics

      def initialize
        @by_ip = Hash.new { |hash, ip| hash[ip] = Hash.new { |users, user_id| users[user_id] = Set.new } }
        @by_user = Hash.new { |hash, user_id| hash[user_id] = Hash.new { |ips, ip| ips[ip] = Set.new } }
        @context_cache = {}
        @diagnostics = {
          relation_rows: 0,
          registration_rows: 0,
          current_rows: 0,
          history_rows: 0,
          auth_session_rows: 0,
          active_session_rows: 0,
          exact_ip_groups: 0,
          public_ip_groups: 0,
          nonpublic_ip_groups: 0,
          large_ip_groups_skipped: 0,
          exact_ip_pairs_generated: 0,
          auth_log_truncated: false,
        }
      end

      def add(user_id, ip_value, source)
        user_id = user_id.to_i
        return if user_id <= 0 || !SOURCES.include?(source.to_s)

        ip = IpNormalizer.normalize(ip_value)
        return if ip.blank?

        source = source.to_s
        before = @by_user[user_id][ip].length
        @by_user[user_id][ip] << source
        @by_ip[ip][user_id] << source
        return if @by_user[user_id][ip].length == before

        diagnostics[:relation_rows] += 1
        key = "#{source}_rows".to_sym
        diagnostics[key] += 1 if diagnostics.key?(key)
      end

      def pair_set(max_group_users:, max_pairs:)
        pairs = Set.new

        @by_ip.each do |ip, users|
          count = users.length
          next if count < 2

          diagnostics[:exact_ip_groups] += 1
          if IpNormalizer.normalize_public(ip).present?
            diagnostics[:public_ip_groups] += 1
          else
            diagnostics[:nonpublic_ip_groups] += 1
          end

          if count > max_group_users
            diagnostics[:large_ip_groups_skipped] += 1
            next
          end

          users.keys.sort.combination(2) do |pair|
            pairs << pair
            if pairs.length > max_pairs
              diagnostics[:exact_ip_pairs_generated] = pairs.length
              return pairs
            end
          end
        end

        diagnostics[:exact_ip_pairs_generated] = pairs.length
        pairs
      end

      def shared_details(user_a_id, user_b_id)
        a = @by_user[user_a_id.to_i]
        b = @by_user[user_b_id.to_i]
        shared = a.keys & b.keys

        shared.map do |ip|
          CoreIpEvidence.detail_for(
            ip,
            a[ip],
            b[ip],
            @by_ip[ip].length,
            context_cache: @context_cache,
          )
        end.sort_by { |detail| CoreIpEvidence.detail_sort_key(detail) }
      end
    end

    def build_scan_index
      index = ScanIndex.new
      user_ids = User.human_users.where(staged: false).where("users.id > 0").pluck(:id)
      return index if user_ids.blank?

      User.human_users.where(id: user_ids, staged: false).pluck(:id, :registration_ip_address, :ip_address).each do |user_id, registration_ip, current_ip|
        index.add(user_id, registration_ip, "registration") if registration_ip.present?
        index.add(user_id, current_ip, "current") if current_ip.present?
      end

      if defined?(::UserIpAddressHistory)
        ::UserIpAddressHistory.where(user_id: user_ids).pluck(:user_id, :ip_address).each do |user_id, ip|
          index.add(user_id, ip, "history")
        end
      end

      if defined?(::UserAuthTokenLog)
        rows =
          ::UserAuthTokenLog
            .where(user_id: user_ids, action: "generate")
            .where.not(client_ip: nil)
            .distinct
            .limit(MAX_AUTH_INDEX_ROWS + 1)
            .pluck(:user_id, :client_ip)
        if rows.length > MAX_AUTH_INDEX_ROWS
          index.diagnostics[:auth_log_truncated] = true
          rows = rows.first(MAX_AUTH_INDEX_ROWS)
        end
        rows.each { |user_id, ip| index.add(user_id, ip, "auth_session") }
      end

      if defined?(::UserAuthToken)
        ::UserAuthToken
          .unexpired
          .where(user_id: user_ids)
          .where.not(client_ip: nil)
          .distinct
          .pluck(:user_id, :client_ip)
          .each { |user_id, ip| index.add(user_id, ip, "active_session") }
      end

      index
    rescue ActiveRecord::StatementInvalid => e
      Rails.logger.warn("[account_security] core IP scan index failed class=#{e.class}")
      ScanIndex.new
    end

    def candidate_user_ids_for_ip(ip_value, current_user_id:, max_group_users:)
      ip = IpNormalizer.normalize(ip_value)
      return [] if ip.blank?

      ids = Set.new
      eligible_ids = eligible_user_ids_scope
      append_ids!(ids, User.human_users.where(staged: false, registration_ip_address: ip).where("users.id > 0"), :id, max_group_users)
      append_ids!(ids, User.human_users.where(staged: false, ip_address: ip).where("users.id > 0"), :id, max_group_users)
      if defined?(::UserIpAddressHistory)
        append_ids!(ids, ::UserIpAddressHistory.where(ip_address: ip, user_id: eligible_ids), :user_id, max_group_users)
      end
      if defined?(::UserAuthTokenLog)
        append_ids!(ids, ::UserAuthTokenLog.where(client_ip: ip, action: "generate", user_id: eligible_ids), :user_id, max_group_users)
      end
      if defined?(::UserAuthToken)
        append_ids!(ids, ::UserAuthToken.unexpired.where(client_ip: ip, user_id: eligible_ids), :user_id, max_group_users)
      end

      ids.delete(current_user_id.to_i)
      return [] if ids.length > max_group_users
      ids.to_a.select(&:positive?).uniq
    rescue ActiveRecord::StatementInvalid
      []
    end

    def shared_details_for_pair(user_a_id, user_b_id)
      a = user_ip_sources(user_a_id)
      b = user_ip_sources(user_b_id)
      shared = a.keys & b.keys
      context_cache = {}

      shared.map do |ip|
        detail_for(
          ip,
          a[ip],
          b[ip],
          distinct_user_count(ip),
          context_cache: context_cache,
        )
      end.sort_by { |detail| detail_sort_key(detail) }
    rescue ActiveRecord::StatementInvalid => e
      Rails.logger.warn("[account_security] pair IP evidence failed class=#{e.class}")
      []
    end

    def user_ip_sources(user_id)
      user_id = user_id.to_i
      data = Hash.new { |hash, ip| hash[ip] = Set.new }
      user = User.human_users.where(staged: false).where("users.id > 0").find_by(id: user_id)
      return data if user.blank?

      add_source!(data, user.registration_ip_address, "registration")
      add_source!(data, user.ip_address, "current")

      if defined?(::UserIpAddressHistory)
        ::UserIpAddressHistory.where(user_id: user_id).pluck(:ip_address).each do |ip|
          add_source!(data, ip, "history")
        end
      end

      if defined?(::UserAuthTokenLog)
        ::UserAuthTokenLog
          .where(user_id: user_id, action: "generate")
          .where.not(client_ip: nil)
          .distinct
          .pluck(:client_ip)
          .each { |ip| add_source!(data, ip, "auth_session") }
      end

      if defined?(::UserAuthToken)
        ::UserAuthToken
          .unexpired
          .where(user_id: user_id)
          .where.not(client_ip: nil)
          .distinct
          .pluck(:client_ip)
          .each { |ip| add_source!(data, ip, "active_session") }
      end

      data
    end

    def detail_for(ip, sources_a, sources_b, user_count, context_cache: {})
      context = context_cache[ip] ||= context_for(ip)
      {
        "ip_address" => ip.to_s,
        "sources_a" => source_values(sources_a).map(&:to_s).sort,
        "sources_b" => source_values(sources_b).map(&:to_s).sort,
        "user_count" => user_count.to_i,
        "public" => context[:public],
        "trusted" => context[:trusted],
        "tor" => context[:tor],
        "local_blacklist" => context[:local_blacklist],
        "usage_type" => context[:usage_type],
        "isp" => context[:isp],
        "hosting" => context[:hosting],
        "mobile" => context[:mobile],
      }.compact
    end

    def source_values(value)
      return [] if value.nil?
      value.respond_to?(:to_a) ? value.to_a : Array(value)
    end

    def detail_sort_key(detail)
      sources_a = Array(detail["sources_a"])
      sources_b = Array(detail["sources_b"])
      registration = sources_a.include?("registration") && sources_b.include?("registration")
      current = sources_a.include?("current") && sources_b.include?("current")
      [detail["public"] == true ? 0 : 1, registration ? 0 : 1, current ? 0 : 1, detail["user_count"].to_i, detail["ip_address"].to_s]
    end

    def context_for(ip_value)
      normalized = IpNormalizer.normalize(ip_value)
      public_ip = IpNormalizer.normalize_public(normalized)
      trusted = trusted_ip?(normalized)
      return { public: false, trusted: trusted, tor: false, local_blacklist: false, hosting: false, mobile: false } if public_ip.blank?

      intelligence = IpIntelligence.find_by(ip_address: public_ip)
      usage_type = intelligence&.usage_type.to_s.presence
      usage_downcase = usage_type.to_s.downcase
      {
        public: true,
        trusted: trusted,
        tor: FeedEntry.where(source: "tor", ip_address: public_ip).exists? || intelligence&.is_tor == true,
        local_blacklist:
          FeedEntry.where(source: "abuseipdb_blacklist", ip_address: public_ip).exists? ||
            intelligence&.local_blacklist_match == true,
        usage_type: usage_type,
        isp: intelligence&.isp.to_s.presence,
        hosting: usage_downcase.match?(/data center|hosting|transit|content delivery/),
        mobile: usage_downcase.include?("mobile"),
      }
    rescue ActiveRecord::StatementInvalid
      { public: public_ip.present?, trusted: false, tor: false, local_blacklist: false, hosting: false, mobile: false }
    end

    def distinct_user_count(ip_value)
      ip = IpNormalizer.normalize(ip_value)
      return 0 if ip.blank?

      ids = Set.new
      eligible_ids = eligible_user_ids_scope
      append_ids!(ids, User.human_users.where(staged: false, registration_ip_address: ip).where("users.id > 0"), :id, nil)
      append_ids!(ids, User.human_users.where(staged: false, ip_address: ip).where("users.id > 0"), :id, nil)
      append_ids!(ids, ::UserIpAddressHistory.where(ip_address: ip, user_id: eligible_ids), :user_id, nil) if defined?(::UserIpAddressHistory)
      append_ids!(ids, ::UserAuthTokenLog.where(client_ip: ip, action: "generate", user_id: eligible_ids), :user_id, nil) if defined?(::UserAuthTokenLog)
      append_ids!(ids, ::UserAuthToken.unexpired.where(client_ip: ip, user_id: eligible_ids), :user_id, nil) if defined?(::UserAuthToken)
      ids.length
    end

    def eligible_user_ids_scope
      User.human_users.where(staged: false).where("users.id > 0").select(:id)
    end

    def trusted_ip?(ip)
      return false if ip.blank?
      TrustedNetwork.active.where("?::inet <<= network", ip.to_s).exists?
    rescue ActiveRecord::StatementInvalid
      false
    end

    def add_source!(data, ip_value, source)
      ip = IpNormalizer.normalize(ip_value)
      data[ip] << source if ip.present?
    end

    def append_ids!(target, scope, column, max_group_users)
      limit = max_group_users ? max_group_users + 1 : nil
      relation = scope.distinct
      relation = relation.limit(limit) if limit
      relation.pluck(column).each do |id|
        target << id.to_i if id.to_i.positive?
        return if max_group_users && target.length > max_group_users
      end
    end
  end
end
