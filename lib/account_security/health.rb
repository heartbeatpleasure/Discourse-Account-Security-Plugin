# frozen_string_literal: true
module ::AccountSecurity
  module Health
    module_function

    TEST_IP = "118.25.6.39"

    def payload
      usage = ProviderUsage.find_by(provider: "abuseipdb", endpoint: "check")
      tor = FeedSnapshot.find_by(source: "tor")
      blacklist = FeedSnapshot.find_by(source: "abuseipdb_blacklist")
      circuit = CircuitBreaker.state
      status = overall_status(usage, tor, blacklist, circuit)
      {
        generated_at: Time.zone.now.iso8601,
        overall: status,
        configuration: {
          enabled: SiteSetting.account_security_enabled,
          ip_reputation_enabled: SiteSetting.account_security_ip_reputation_enabled,
          api_key_configured: SiteSetting.account_security_abuseipdb_api_key.present?,
          usage_terms_acknowledged: SiteSetting.account_security_abuseipdb_usage_terms_acknowledged,
          abuse_reporting_enabled: SiteSetting.account_security_abuse_reporting_enabled,
          provider_host: "api.abuseipdb.com",
        },
        provider: serialize_usage(usage),
        circuit_breaker: circuit,
        feeds: {
          tor: serialize_feed(tor, 2.hours),
          abuseipdb_blacklist: serialize_feed(blacklist, 8.hours),
        },
        counts: {
          cached_addresses: safe_count(IpIntelligence),
          open_events: safe_count(RiskEvent.where(status: "open")),
          trusted_networks: safe_count(TrustedNetwork.active),
        },
        privacy: {
          provider_receives_only_public_ip: true,
          verbose_provider_reports_requested: false,
          usernames_or_email_sent_to_provider: false,
          automatic_abuse_reporting: false,
        },
      }
    rescue ActiveRecord::StatementInvalid
      { overall: "initializing", generated_at: Time.zone.now.iso8601 }
    end

    def test!
      return payload.merge(test_result: { success: false, error_code: "api_key_missing" }) if SiteSetting.account_security_abuseipdb_api_key.blank?
      return payload.merge(test_result: { success: false, error_code: "terms_not_acknowledged" }) unless SiteSetting.account_security_abuseipdb_usage_terms_acknowledged

      quota = QuotaManager.authorize("manual")
      return payload.merge(test_result: { success: false, error_code: quota.reason }) unless quota.allowed

      result = Providers::AbuseIpDb.new.check(TEST_IP)
      payload.merge(test_result: { success: result.success, status: result.status, error_code: result.error_code&.to_s, latency_ms: result.latency_ms })
    end

    def overall_status(usage, tor, blacklist, circuit)
      return "disabled" unless SiteSetting.account_security_enabled
      return "local_only" unless SiteSetting.account_security_ip_reputation_enabled
      return "misconfigured" if SiteSetting.account_security_abuseipdb_api_key.blank? || !SiteSetting.account_security_abuseipdb_usage_terms_acknowledged
      return "circuit_open" if circuit[:state] == "open"
      return "invalid_credentials" if usage&.last_status.to_i.in?([401, 403])
      return "quota_exhausted" if usage&.last_status.to_i == 429 || (usage&.remaining == 0 && usage&.reset_at.to_i > Time.zone.now.to_i)
      return "degraded" if SiteSetting.account_security_tor_feed_enabled && stale_feed?(tor, 2.hours)
      return "degraded" if SiteSetting.account_security_blacklist_sync_enabled && stale_feed?(blacklist, 8.hours)
      "healthy"
    end

    def serialize_usage(row)
      return { status: "never" } unless row
      {
        status: row.last_status.to_i.between?(200, 299) ? "connected" : "degraded",
        last_status: row.last_status,
        request_count: row.request_count,
        rate_limit: row.rate_limit,
        remaining: row.remaining,
        reset_at: row.reset_at&.iso8601,
        last_request_at: row.last_request_at&.iso8601,
      }
    end

    def serialize_feed(row, max_age)
      return { status: "never", stale: true, entry_count: 0 } unless row
      { status: row.status, stale: stale_feed?(row, max_age), entry_count: row.entry_count, fetched_at: row.fetched_at&.iso8601, error_code: row.error_code }
    end

    def stale_feed?(row, max_age)
      row.blank? || row.fetched_at.blank? || row.fetched_at < max_age.ago || row.status != "healthy"
    end

    def safe_count(scope)
      scope.count
    rescue StandardError
      0
    end
  end
end
