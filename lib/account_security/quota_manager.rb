# frozen_string_literal: true
module ::AccountSecurity
  module QuotaManager
    module_function

    BUCKETS = %w[registration staff_login manual login deferred].freeze

    Decision = Struct.new(:allowed, :reason, keyword_init: true)

    QUOTA_MUTEX_KEY = "account-security-provider-quota"

    def authorize(trigger)
      DistributedMutex.synchronize(QUOTA_MUTEX_KEY, validity: 5) do
        authorize_locked(trigger)
      end
    rescue StandardError => e
      Rails.logger.warn("[account_security] quota authorization failed class=#{e.class}")
      Decision.new(allowed: false, reason: "quota_state_error")
    end

    def authorize_locked(trigger)
      return Decision.new(allowed: false, reason: "disabled") unless SiteSetting.account_security_enabled
      return Decision.new(allowed: false, reason: "module_disabled") unless SiteSetting.account_security_ip_reputation_enabled
      return Decision.new(allowed: false, reason: "api_key_missing") if SiteSetting.account_security_abuseipdb_api_key.blank?
      return Decision.new(allowed: false, reason: "circuit_open") if CircuitBreaker.open?

      bucket = normalize_bucket(trigger)
      local_limit = SiteSetting.account_security_daily_check_budget.to_i.clamp(50, 50_000)
      usage = ProviderUsage.find_by(provider: "abuseipdb", endpoint: "check")
      provider_remaining = authoritative_remaining(usage)
      return Decision.new(allowed: false, reason: "provider_quota_exhausted") if provider_remaining == 0

      counts = BUCKETS.index_with { |name| redis_count(name) }
      total = redis_count("total")
      effective_remaining = [local_limit - total, provider_remaining].compact.min
      return Decision.new(allowed: false, reason: "local_quota_exhausted") if effective_remaining.to_i <= 0

      protected = protected_capacity(bucket, counts)
      if effective_remaining.to_i <= protected
        return Decision.new(allowed: false, reason: "protected_reserve")
      end

      increment!(bucket)
      Decision.new(allowed: true, reason: nil)
    end

    def record_response(endpoint:, status:, headers:)
      endpoint_name = endpoint.to_s.first(32)
      mutex_key = "account-security-provider-usage-#{endpoint_name}"
      DistributedMutex.synchronize(mutex_key, validity: 5) do
        now = Time.zone.now
        limit = nonnegative_integer(headers["x-ratelimit-limit"])
        remaining = nonnegative_integer(headers["x-ratelimit-remaining"])
        reset_epoch = nonnegative_integer(headers["x-ratelimit-reset"])
        reset_at = reset_epoch ? Time.at(reset_epoch).utc : nil

        row = ProviderUsage.find_or_initialize_by(provider: "abuseipdb", endpoint: endpoint_name)
        row.request_count = row.request_count.to_i + 1
        if status.to_i.between?(200, 299)
          row.success_count = row.success_count.to_i + 1
        else
          row.error_count = row.error_count.to_i + 1
        end
        row.rate_limit = limit if limit
        row.remaining = remaining if remaining
        row.reset_at = reset_at if reset_at
        row.last_status = status.to_i if status
        row.last_request_at = now
        row.save!
        row
      end
    rescue StandardError => e
      Rails.logger.warn("[account_security] provider usage update failed class=#{e.class}")
      nil
    end

    def normalize_bucket(trigger)
      value = trigger.to_s
      return value if BUCKETS.include?(value)
      value == "staff" ? "staff_login" : "login"
    end

    def protected_capacity(bucket, counts)
      reg_remaining = [SiteSetting.account_security_registration_reserve.to_i - counts["registration"].to_i, 0].max
      staff_remaining = [SiteSetting.account_security_staff_reserve.to_i - counts["staff_login"].to_i, 0].max
      manual_remaining = [SiteSetting.account_security_manual_reserve.to_i - counts["manual"].to_i, 0].max
      case bucket
      when "manual" then 0
      when "staff_login" then manual_remaining
      when "registration" then manual_remaining + staff_remaining
      else manual_remaining + staff_remaining + reg_remaining
      end
    end

    def authoritative_remaining(usage)
      return nil if usage.blank? || usage.remaining.nil?
      return nil if usage.reset_at.present? && usage.reset_at <= Time.zone.now
      usage.remaining.to_i
    end

    def increment!(bucket)
      ttl = 3.days.to_i
      ["total", bucket].each do |name|
        key = redis_key(name)
        Discourse.redis.incr(key)
        Discourse.redis.expire(key, ttl)
      end
    end

    def redis_count(name)
      Discourse.redis.get(redis_key(name)).to_i
    end

    def redis_key(name)
      "account_security:quota:#{Time.now.utc.strftime('%Y%m%d')}:#{name}"
    end

    def nonnegative_integer(value)
      number = Integer(value, exception: false)
      number && number >= 0 ? number : nil
    end
  end
end
