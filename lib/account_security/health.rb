# frozen_string_literal: true

module ::AccountSecurity
  module Health
    module_function

    TEST_IP = "118.25.6.39"
    MANUAL_BLACKLIST_SYNC_KEY = "account_security:health:manual_blacklist_sync"

    def payload
      usage = ProviderUsage.find_by(provider: "abuseipdb", endpoint: "check")
      tor = FeedSnapshot.find_by(source: "tor")
      blacklist = FeedSnapshot.find_by(source: "abuseipdb_blacklist")
      circuit = CircuitBreaker.state
      status, reason = overall_state(usage, tor, blacklist, circuit)
      {
        generated_at: Time.zone.now.iso8601,
        overall: status,
        overall_reason: reason,
        configuration: {
          enabled: SiteSetting.account_security_enabled,
          ip_reputation_enabled: SiteSetting.account_security_ip_reputation_enabled,
          api_key_configured: SiteSetting.account_security_abuseipdb_api_key.present?,
          abuse_reporting_enabled: SiteSetting.account_security_abuse_reporting_enabled,
          auth_abuse_detection_enabled: SiteSetting.account_security_auth_abuse_detection_enabled,
          account_correlation_enabled: SiteSetting.account_security_account_correlation_enabled,
          browser_continuity_enabled: SiteSetting.account_security_browser_continuity_enabled,
          correlation_auto_scan_frequency: SiteSetting.account_security_correlation_auto_scan_frequency,
          staff_notifications_enabled: SiteSetting.account_security_staff_notifications_enabled,
          notification_groups_configured: IncidentNotifier.notification_group_names.any?,
          user_notes_enabled: SiteSetting.account_security_user_notes_enabled,
          temporary_ip_blocks_enabled: SiteSetting.account_security_temporary_ip_blocks_enabled,
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
          active_temporary_ip_blocks: safe_count(TemporaryIpBlock.active),
          active_notification_suppressions: safe_count(NotificationSuppression.active),
          open_account_correlations: safe_count(AccountCorrelation.unresolved),
          session_signatures: safe_count(SessionSignature),
          browser_continuities: safe_count(BrowserContinuity),
        },
        privacy: {
          provider_receives_only_public_ip: true,
          verbose_provider_reports_requested: false,
          usernames_or_email_sent_to_provider: false,
          raw_authentication_identifiers_persisted_by_abuse_tracker: false,
          raw_user_agents_persisted_by_account_correlation: false,
          session_user_agent_correlation_uses_site_local_hmac: true,
          browser_continuity_raw_token_persisted: false,
          browser_continuity_is_positive_only_evidence: true,
          automatic_abuse_reporting: false,
        },
      }
    rescue ActiveRecord::StatementInvalid
      { overall: "initializing", overall_reason: "database_initializing", generated_at: Time.zone.now.iso8601 }
    end

    def test!
      return payload.merge(test_result: { success: false, error_code: "api_key_missing" }) if SiteSetting.account_security_abuseipdb_api_key.blank?

      quota = QuotaManager.authorize("manual")
      return payload.merge(test_result: { success: false, error_code: quota.reason }) unless quota.allowed

      result = Providers::AbuseIpDb.new.check(TEST_IP)
      payload.merge(
        test_result: {
          success: result.success,
          status: result.status,
          error_code: result.error_code&.to_s,
          latency_ms: result.latency_ms,
        },
      )
    end

    def sync_feed!(source)
      source = source.to_s
      result =
        case source
        when "tor"
          return payload.merge(feed_sync: { success: false, source: source, error_code: "feed_disabled" }) unless SiteSetting.account_security_tor_feed_enabled
          Feeds::TorExitList.sync!
        when "abuseipdb_blacklist"
          return payload.merge(feed_sync: { success: false, source: source, error_code: "feed_disabled" }) unless SiteSetting.account_security_blacklist_sync_enabled
          return payload.merge(feed_sync: { success: false, source: source, error_code: "api_key_missing" }) if SiteSetting.account_security_abuseipdb_api_key.blank?
          unless Discourse.redis.set(MANUAL_BLACKLIST_SYNC_KEY, Time.now.to_i.to_s, nx: true, ex: 20.hours.to_i)
            return payload.merge(feed_sync: { success: false, source: source, error_code: "manual_sync_rate_limited" })
          end
          Feeds::AbuseIpDbBlacklist.sync!
        else
          raise Discourse::InvalidParameters.new(:source)
        end

      payload.merge(
        feed_sync: {
          success: result[:success] == true,
          source: source,
          entry_count: result[:entry_count],
          error_code: result[:error].presence || result[:skipped].presence,
        }.compact,
      )
    end

    def overall_status(usage, tor, blacklist, circuit)
      overall_state(usage, tor, blacklist, circuit).first
    end

    def overall_state(usage, tor, blacklist, circuit)
      return ["disabled", "plugin_disabled"] unless SiteSetting.account_security_enabled
      return ["local_only", "ip_reputation_disabled"] unless SiteSetting.account_security_ip_reputation_enabled
      return ["misconfigured", "api_key_missing"] if SiteSetting.account_security_abuseipdb_api_key.blank?
      return ["circuit_open", "circuit_open"] if circuit[:state] == "open"
      return ["invalid_credentials", "invalid_credentials"] if usage&.last_status.to_i.in?([401, 403])
      if usage&.last_status.to_i == 429 || (usage&.remaining == 0 && usage&.reset_at.to_i > Time.zone.now.to_i)
        return ["quota_exhausted", "quota_exhausted"]
      end

      if SiteSetting.account_security_tor_feed_enabled && stale_feed?(tor, 2.hours)
        return ["degraded", feed_reason("tor", tor, 2.hours)]
      end
      if SiteSetting.account_security_blacklist_sync_enabled && stale_feed?(blacklist, 8.hours)
        return ["degraded", feed_reason("abuseipdb_blacklist", blacklist, 8.hours)]
      end
      if SiteSetting.account_security_staff_notifications_enabled && IncidentNotifier.notification_group_names.empty?
        return ["degraded", "notification_groups_missing"]
      end

      ["healthy", nil]
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
      {
        status: row.status,
        stale: stale_feed?(row, max_age),
        entry_count: row.entry_count,
        fetched_at: row.fetched_at&.iso8601,
        error_code: row.error_code,
      }
    end

    def stale_feed?(row, max_age)
      row.blank? || row.fetched_at.blank? || row.fetched_at < max_age.ago || row.status != "healthy"
    end

    def feed_reason(name, row, max_age)
      return "#{name}_never_synced" if row.blank? || row.fetched_at.blank?
      return "#{name}_error" if row.status != "healthy"
      return "#{name}_stale" if row.fetched_at < max_age.ago
      "#{name}_unhealthy"
    end

    def safe_count(scope)
      scope.count
    rescue StandardError
      0
    end
  end
end
