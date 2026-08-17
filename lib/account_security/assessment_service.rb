# frozen_string_literal: true
require "digest"
module ::AccountSecurity
  class AssessmentService
    Result = Struct.new(:success, :reason, :intelligence, :event, :new_network, :source, keyword_init: true)

    def self.call(ip:, user: nil, trigger:, force_remote: false, allow_remote: true, event_context: {}, familiarity: nil)
      new(
        ip: ip,
        user: user,
        trigger: trigger,
        force_remote: force_remote,
        allow_remote: allow_remote,
        event_context: event_context,
        familiarity: familiarity,
      ).call
    end

    def initialize(ip:, user:, trigger:, force_remote:, allow_remote:, event_context:, familiarity:)
      @ip = IpNormalizer.normalize_public(ip)
      @user = user
      @trigger = trigger.to_s
      @force_remote = force_remote == true
      @allow_remote = allow_remote == true
      @event_context = event_context.is_a?(Hash) ? event_context : {}
      @familiarity = familiarity.is_a?(Hash) ? familiarity : nil
    end

    def call
      return Result.new(success: false, reason: "disabled") unless SiteSetting.account_security_enabled
      return Result.new(success: false, reason: "module_disabled") unless SiteSetting.account_security_ip_reputation_enabled
      return Result.new(success: false, reason: "invalid_or_nonpublic_ip") if @ip.blank?

      Statistics.increment!(assessment_stats)
      registration = @trigger == "registration"
      familiarity = @familiarity || (@user ? NetworkFamiliarity.observe!(user: @user, ip: @ip, registration: registration) : { new_network: true, network: nil })

      trusted = trusted_network
      if trusted
        return Result.new(success: true, reason: "trusted_network", new_network: familiarity[:new_network], source: "trusted_network")
      end

      tor_match = feed_entry("tor").present?
      blacklist_entry = feed_entry("abuseipdb_blacklist")
      Statistics.increment!(tor_hits: 1) if tor_match
      Statistics.increment!(local_blacklist_hits: 1) if blacklist_entry

      intelligence = IpIntelligence.find_by(ip_address: @ip)
      if intelligence && CachePolicy.fresh?(intelligence) && !@force_remote
        intelligence.update_columns(
          is_tor: tor_match,
          local_blacklist_match: blacklist_entry.present?,
          last_seen_at: Time.zone.now,
          updated_at: Time.zone.now,
        )
        Statistics.increment!(cache_hits: 1)
        event = EventRecorder.record!(
          user: @user,
          ip: @ip,
          intelligence: intelligence,
          trigger: @trigger,
          new_network: familiarity[:new_network],
          familiarity_network: familiarity[:network],
          local_context: @event_context,
        )
        return Result.new(success: true, intelligence: intelligence, event: event, new_network: familiarity[:new_network], source: "cache")
      end

      if blacklist_entry && !@force_remote
        intelligence = persist_intelligence(
          existing: intelligence,
          score: blacklist_entry.score.to_i,
          data: {},
          tor_match: tor_match,
          blacklist_match: true,
          provider_checked_at: intelligence&.provider_checked_at,
        )
        event = EventRecorder.record!(
          user: @user,
          ip: @ip,
          intelligence: intelligence,
          trigger: @trigger,
          new_network: familiarity[:new_network],
          familiarity_network: familiarity[:network],
          local_context: @event_context,
        )
        return Result.new(success: true, intelligence: intelligence, event: event, new_network: familiarity[:new_network], source: "local_blacklist")
      end

      unless @allow_remote
        if intelligence
          intelligence.update_columns(is_tor: tor_match, local_blacklist_match: blacklist_entry.present?, last_seen_at: Time.zone.now, updated_at: Time.zone.now)
        end
        return Result.new(success: intelligence.present? || tor_match, reason: "local_preview", intelligence: intelligence,
                          new_network: familiarity[:new_network], source: "local_only")
      end

      provider_result = nil
      quota = nil
      mutex_key = "account-security-abuseipdb-check-#{Digest::SHA256.hexdigest(@ip)[0, 24]}"
      DistributedMutex.synchronize(mutex_key, validity: 15) do
        refreshed = IpIntelligence.find_by(ip_address: @ip)
        if refreshed && CachePolicy.fresh?(refreshed) && !@force_remote
          provider_result = :cache_after_lock
          intelligence = refreshed
        else
          # Authorize only after acquiring the per-IP lock and rechecking the
          # cache. Concurrent assessments for the same address therefore spend
          # one local quota slot only when one provider request is actually made.
          quota = QuotaManager.authorize(quota_trigger)
          provider_result = quota.allowed ? Providers::AbuseIpDb.new.check(@ip) : :quota_denied
        end
      end

      if provider_result == :quota_denied
        Statistics.increment!(quota_skips: 1) if quota.reason.to_s.include?("quota") || quota.reason == "protected_reserve"
        if intelligence
          intelligence.update_columns(is_tor: tor_match, local_blacklist_match: blacklist_entry.present?, last_seen_at: Time.zone.now, updated_at: Time.zone.now)
        end
        return Result.new(success: intelligence.present?, reason: quota.reason, intelligence: intelligence,
                          new_network: familiarity[:new_network], source: "local_only")
      end

      if provider_result == :cache_after_lock
        Statistics.increment!(cache_hits: 1)
        event = EventRecorder.record!(
          user: @user,
          ip: @ip,
          intelligence: intelligence,
          trigger: @trigger,
          new_network: familiarity[:new_network],
          familiarity_network: familiarity[:network],
          local_context: @event_context,
        )
        return Result.new(success: true, intelligence: intelligence, event: event, new_network: familiarity[:new_network], source: "cache")
      end

      unless provider_result&.success
        return Result.new(success: intelligence.present?, reason: provider_result&.error_code.to_s.presence || "provider_error",
                          intelligence: intelligence, new_network: familiarity[:new_network], source: "provider_error")
      end

      data = provider_result.data
      score = [data["abuseConfidenceScore"].to_i, blacklist_entry&.score.to_i].max
      intelligence = persist_intelligence(
        existing: intelligence,
        score: score,
        data: data,
        tor_match: tor_match || data["isTor"] == true,
        blacklist_match: blacklist_entry.present?,
        provider_checked_at: Time.zone.now,
      )
      event = EventRecorder.record!(
        user: @user,
        ip: @ip,
        intelligence: intelligence,
        trigger: @trigger,
        new_network: familiarity[:new_network],
        familiarity_network: familiarity[:network],
        local_context: @event_context,
      )
      Result.new(success: true, intelligence: intelligence, event: event, new_network: familiarity[:new_network], source: "abuseipdb")
    rescue StandardError => e
      Rails.logger.warn("[account_security] assessment failed trigger=#{@trigger.to_s.first(24)} class=#{e.class}")
      Result.new(success: false, reason: "internal_error")
    end

    private

    def assessment_stats
      stats = { assessments: 1 }
      stats[:registrations] = 1 if @trigger == "registration"
      stats[:logins] = 1 if @trigger.in?(%w[login staff_login])
      stats[:manual_lookups] = 1 if @trigger == "manual"
      stats
    end

    def quota_trigger
      case @trigger
      when "registration" then "registration"
      when "staff_login" then "staff_login"
      when "manual" then "manual"
      when "auth_failure", "registration_abuse" then "auth_failure"
      else "login"
      end
    end

    def trusted_network
      TrustedNetwork.active.where(scope: %w[bypass_lookup bypass_lookup_and_enforcement])
                    .where("?::inet <<= network", @ip).order(id: :desc).first
    end

    def feed_entry(source)
      FeedEntry.find_by(source: source, ip_address: @ip)
    end

    def persist_intelligence(existing:, score:, data:, tor_match:, blacklist_match:, provider_checked_at:)
      now = Time.zone.now
      risk = RiskPolicy.risk_level(score)
      last_reported = parse_time(data["lastReportedAt"])
      evidence = RiskPolicy.evidence_strength(
        score: score,
        last_reported_at: last_reported,
        distinct_reporters: data["numDistinctUsers"],
        local_blacklist_match: blacklist_match,
      )
      record = existing || IpIntelligence.new(ip_address: @ip, first_seen_at: now)
      record.assign_attributes(
        risk_level: risk,
        evidence_strength: evidence,
        primary_score: score,
        total_reports: data["totalReports"],
        distinct_reporters: data["numDistinctUsers"],
        last_reported_at: last_reported,
        usage_type: data["usageType"],
        isp: data["isp"],
        domain: data["domain"],
        country_code: data["countryCode"],
        is_tor: tor_match,
        local_blacklist_match: blacklist_match,
        provider_checked_at: provider_checked_at,
        next_check_after: now + CachePolicy.ttl_for(risk),
        last_seen_at: now,
        source_summary: {
          "provider" => data.present? ? "abuseipdb" : "local_feed",
          "is_whitelisted" => data["isWhitelisted"] == true,
          "schema_version" => 1,
        },
      )
      record.save!
      record
    end

    def parse_time(value)
      return nil if value.blank?
      Time.zone.parse(value.to_s)
    rescue ArgumentError, TypeError
      nil
    end
  end
end
