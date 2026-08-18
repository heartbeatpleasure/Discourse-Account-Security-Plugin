# frozen_string_literal: true
require "json"
module ::AccountSecurity
  module CircuitBreaker
    module_function

    FAILURE_KEY = "account_security:abuseipdb:failures"
    OPEN_UNTIL_KEY = "account_security:abuseipdb:open_until"
    STATE_MUTEX_KEY = "account-security-abuseipdb-circuit-state"
    MAX_OPEN_SECONDS = 48.hours.to_i

    def state
      open_until = integer_value(Discourse.redis.get(OPEN_UNTIL_KEY))
      now = Time.now.to_i
      if open_until && open_until > now + MAX_OPEN_SECONDS
        Discourse.redis.del(OPEN_UNTIL_KEY)
        return { state: "closed", open_until: nil }
      end
      if open_until && open_until > now
        { state: "open", open_until: Time.at(open_until).utc.iso8601 }
      else
        Discourse.redis.del(OPEN_UNTIL_KEY) if open_until
        { state: "closed", open_until: nil }
      end
    rescue StandardError
      { state: "unknown", open_until: nil }
    end

    def open?
      state[:state] == "open"
    end

    def record_success!
      DistributedMutex.synchronize(STATE_MUTEX_KEY, validity: 5) do
        Discourse.redis.del(FAILURE_KEY)
      end
      true
    rescue StandardError
      false
    end

    def record_failure!
      DistributedMutex.synchronize(STATE_MUTEX_KEY, validity: 5) do
        now = Time.now.to_i
        window = SiteSetting.account_security_circuit_breaker_window_minutes.to_i.clamp(1, 60).minutes.to_i
        threshold = SiteSetting.account_security_circuit_breaker_failure_count.to_i.clamp(2, 20)
        entries = failure_entries
        entries.select! { |timestamp| timestamp >= now - window }
        entries << now
        Discourse.redis.setex(FAILURE_KEY, window + 120, entries.to_json)

        if entries.length >= threshold
          duration = SiteSetting.account_security_circuit_breaker_open_minutes.to_i.clamp(1, 120).minutes.to_i
          set_open_until_locked(now + duration, now: now)
        end
      end
      true
    rescue StandardError => e
      Rails.logger.warn("[account_security] circuit breaker update failed class=#{e.class}")
      false
    end

    def open_until!(time)
      return false if time.blank?

      DistributedMutex.synchronize(STATE_MUTEX_KEY, validity: 5) do
        set_open_until_locked(time.to_i, now: Time.now.to_i)
      end
      true
    rescue StandardError => e
      Rails.logger.warn("[account_security] circuit breaker open failed class=#{e.class}")
      false
    end

    def reset!
      DistributedMutex.synchronize(STATE_MUTEX_KEY, validity: 5) do
        Discourse.redis.del(FAILURE_KEY, OPEN_UNTIL_KEY)
      end
      true
    rescue StandardError
      false
    end

    def failure_entries
      raw = Discourse.redis.get(FAILURE_KEY).presence || "[]"
      Array(JSON.parse(raw)).filter_map { |value| integer_value(value) }
    rescue JSON::ParserError
      []
    end

    def set_open_until_locked(timestamp, now:)
      requested = [timestamp.to_i, now + MAX_OPEN_SECONDS].min
      existing = integer_value(Discourse.redis.get(OPEN_UNTIL_KEY))
      existing = nil if existing && existing > now + MAX_OPEN_SECONDS
      effective = [requested, existing.to_i].max
      return if effective <= now

      ttl = [effective - now, 60].max
      Discourse.redis.setex(OPEN_UNTIL_KEY, ttl, effective.to_s)
    end

    def integer_value(value)
      Integer(value, exception: false)
    end
  end
end
