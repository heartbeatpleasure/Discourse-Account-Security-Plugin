# frozen_string_literal: true

module ::AccountSecurity
  module NetworkContext
    module_function

    MAX_TEXT_BYTES = 160

    def for_ip(ip_value, locale: I18n.locale)
      normalized = IpNormalizer.normalize(ip_value)
      public_ip = IpNormalizer.normalize_public(normalized)
      trusted = trusted_ip?(normalized)

      return nonpublic_context(normalized, trusted: trusted) if public_ip.blank?

      maxmind = maxmind_for_ip(public_ip, locale: locale)
      intelligence = IpIntelligence.find_by(ip_address: public_ip)
      usage_type = safe_text(intelligence&.usage_type, 120)
      usage_downcase = usage_type.to_s.downcase
      provider_country_code = safe_country_code(intelligence&.country_code)
      maxmind_country_code = safe_country_code(maxmind[:country_code])

      {
        ip_address: public_ip,
        public: true,
        trusted: trusted,
        tor: tor?(public_ip, intelligence),
        local_blacklist: local_blacklist?(public_ip, intelligence),
        hosting: usage_downcase.match?(/data center|hosting|transit|content delivery/),
        mobile: usage_downcase.include?("mobile"),
        usage_type: usage_type,
        isp: safe_text(intelligence&.isp),
        provider_country_code: provider_country_code,
        maxmind_country_code: maxmind_country_code,
        country_mismatch:
          provider_country_code.present? && maxmind_country_code.present? &&
            provider_country_code != maxmind_country_code,
        maxmind: maxmind,
        sources: context_sources(maxmind, intelligence),
      }.compact
    rescue ActiveRecord::StatementInvalid => e
      Rails.logger.warn("[account_security] network context database lookup failed class=#{e.class}")
      maxmind_only_context(ip_value, locale: locale)
    rescue StandardError => e
      Rails.logger.warn("[account_security] network context lookup failed class=#{e.class}")
      fallback_context(ip_value)
    end

    def maxmind_for_ip(ip_value, locale: I18n.locale)
      public_ip = IpNormalizer.normalize_public(ip_value)
      return {} if public_ip.blank? || !defined?(::DiscourseIpInfo)

      info = ::DiscourseIpInfo.get(public_ip, locale: locale, resolve_hostname: false)
      return {} unless info.is_a?(Hash)

      asn = Integer(info[:asn], exception: false)
      asn = nil unless asn&.positive?
      {
        source: "discourse_geolite2",
        asn: asn,
        organization: safe_text(info[:organization]),
        country: safe_text(info[:country]),
        country_code: safe_country_code(info[:country_code]),
        region: safe_text(info[:region]),
        city: safe_text(info[:city]),
        location: safe_text(info[:location], 240),
        location_is_approximate: true,
      }.compact
    rescue StandardError => e
      Rails.logger.warn("[account_security] local MaxMind context lookup failed class=#{e.class}")
      {}
    end

    def database_status
      city = database_file_status("GeoLite2-City")
      asn = database_file_status("GeoLite2-ASN")
      overall =
        if city[:available] && asn[:available]
          "available"
        elsif city[:available] || asn[:available]
          "partial"
        else
          "unavailable"
        end

      {
        overall: overall,
        city: city,
        asn: asn,
        external_request_required: false,
        lookup_source: "discourse_local_maxmind",
      }
    rescue StandardError => e
      Rails.logger.warn("[account_security] MaxMind database status failed class=#{e.class}")
      {
        overall: "unknown",
        city: { available: false },
        asn: { available: false },
        external_request_required: false,
        lookup_source: "discourse_local_maxmind",
      }
    end

    def context_summary(details)
      rows = Array(details).select { |row| row.is_a?(Hash) }
      maxmind_rows = rows.filter_map do |row|
        value = row[:network_context] || row["network_context"]
        value.is_a?(Hash) ? value : nil
      end
      asns = maxmind_rows.filter_map { |row| positive_integer(row.dig(:maxmind, :asn) || row.dig("maxmind", "asn")) }.uniq
      organizations = maxmind_rows.filter_map do |row|
        safe_text(row.dig(:maxmind, :organization) || row.dig("maxmind", "organization"))
      end.uniq.first(8)
      countries = maxmind_rows.filter_map do |row|
        safe_country_code(
          row.dig(:maxmind, :country_code) || row.dig("maxmind", "country_code") ||
            row[:maxmind_country_code] || row["maxmind_country_code"],
        )
      end.uniq

      asn_counts = Hash.new(0)
      maxmind_rows.each do |row|
        asn = positive_integer(row.dig(:maxmind, :asn) || row.dig("maxmind", "asn"))
        asn_counts[asn] += 1 if asn
      end

      {
        locally_enriched_ip_count: maxmind_rows.count { |row| row[:maxmind].present? || row["maxmind"].present? },
        distinct_asn_count: asns.length,
        asns: asns.first(8),
        organizations: organizations,
        country_codes: countries.first(8),
        repeated_asn_across_shared_ips: asn_counts.any? { |_asn, count| count >= 2 },
        provider_country_mismatch_count: maxmind_rows.count { |row| row[:country_mismatch] == true || row["country_mismatch"] == true },
        score_effect: "none",
      }
    end

    def database_file_status(name)
      return { available: false } unless defined?(::DiscourseIpInfo)

      path = ::DiscourseIpInfo.mmdb_path(name)
      return { available: false } unless File.file?(path)

      {
        available: true,
        updated_at: File.mtime(path).utc.iso8601,
      }
    rescue StandardError
      { available: false }
    end

    def nonpublic_context(ip, trusted: false)
      {
        ip_address: ip.to_s.presence,
        public: false,
        trusted: trusted,
        tor: false,
        local_blacklist: false,
        hosting: false,
        mobile: false,
        maxmind: {},
        sources: [],
      }.compact
    end

    def maxmind_only_context(ip_value, locale:)
      normalized = IpNormalizer.normalize(ip_value)
      public_ip = IpNormalizer.normalize_public(normalized)
      return nonpublic_context(normalized, trusted: false) if public_ip.blank?

      maxmind = maxmind_for_ip(public_ip, locale: locale)
      {
        ip_address: public_ip,
        public: true,
        trusted: false,
        tor: false,
        local_blacklist: false,
        hosting: false,
        mobile: false,
        maxmind: maxmind,
        maxmind_country_code: safe_country_code(maxmind[:country_code]),
        sources: maxmind.present? ? ["discourse_geolite2"] : [],
      }.compact
    end

    def fallback_context(ip_value)
      normalized = IpNormalizer.normalize(ip_value)
      public_ip = IpNormalizer.normalize_public(normalized)
      return nonpublic_context(normalized, trusted: false) if public_ip.blank?

      {
        ip_address: public_ip,
        public: true,
        trusted: false,
        tor: false,
        local_blacklist: false,
        hosting: false,
        mobile: false,
        maxmind: {},
        sources: [],
      }
    end

    def context_sources(maxmind, intelligence)
      sources = []
      sources << "discourse_geolite2" if maxmind.present?
      sources << "abuseipdb_cache" if intelligence.present?
      sources
    end

    def tor?(public_ip, intelligence)
      FeedEntry.where(source: "tor", ip_address: public_ip).exists? || intelligence&.is_tor == true
    end

    def local_blacklist?(public_ip, intelligence)
      FeedEntry.where(source: "abuseipdb_blacklist", ip_address: public_ip).exists? ||
        intelligence&.local_blacklist_match == true
    end

    def trusted_ip?(ip)
      return false if ip.blank?
      TrustedNetwork.active.where("?::inet <<= network", ip.to_s).exists?
    rescue ActiveRecord::StatementInvalid
      false
    end

    def safe_text(value, limit = MAX_TEXT_BYTES)
      SafeText.plain(value, max_chars: limit)
    end

    def safe_country_code(value)
      token = value.to_s.upcase
      token.match?(/\A[A-Z]{2}\z/) ? token : nil
    end

    def positive_integer(value)
      number = Integer(value, exception: false)
      number&.positive? ? number : nil
    end
  end
end
