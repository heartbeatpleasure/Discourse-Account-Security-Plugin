# frozen_string_literal: true

require "digest"
require "openssl"

module ::AccountSecurity
  module AuthenticationAbuseTracker
    module_function

    FAMILY_CONFIG = {
      "failed_login" => { window: 10.minutes, threshold_setting: :account_security_failed_login_threshold },
      "login_code" => { window: 15.minutes, threshold_setting: :account_security_login_code_failure_threshold },
      "password_reset" => { window: 60.minutes, threshold_setting: :account_security_password_reset_threshold },
      "registration_rejected" => { window: 30.minutes, threshold_setting: :account_security_rejected_registration_threshold },
    }.freeze

    SINGLE_ACCOUNT_SETTING = :account_security_failed_login_single_account_threshold
    KEY_PREFIX = "account_security:auth_abuse"

    def failed_login(ip:, login: nil)
      capture(family: "failed_login", ip: ip, target_identifier: login)
    end

    def login_code_failure(ip:)
      capture(family: "login_code", ip: ip)
    end

    def password_reset(ip:, login: nil)
      capture(family: "password_reset", ip: ip, target_identifier: login)
    end

    def registration_rejected(ip:)
      capture(family: "registration_rejected", ip: ip)
    end

    def capture(family:, ip:, target_identifier: nil)
      return false unless enabled?

      config = FAMILY_CONFIG[family.to_s]
      return false unless config

      normalized_ip = IpNormalizer.normalize_public(ip)
      return false if normalized_ip.blank?

      threshold = setting_integer(config[:threshold_setting], 1, 10_000)
      window = config[:window]
      digest = Digest::SHA256.hexdigest(normalized_ip)[0, 32]
      cluster_key = "#{KEY_PREFIX}:#{family}:#{digest}"
      total_count = increment_fixed_window(cluster_key, window)
      cluster_ttl = safe_ttl(cluster_key, window)

      target_count = nil
      distinct_targets = 0
      staff_targeted = false
      if target_identifier.present?
        target_digest = target_token(target_identifier)
        if target_digest
          target_key = "#{cluster_key}:target:#{target_digest}"
          target_count = increment_fixed_window(target_key, window)
          distinct_key = "#{cluster_key}:targets"
          Discourse.redis.sadd(distinct_key, target_digest)
          ensure_expiry(distinct_key, cluster_ttl)
          distinct_targets = Discourse.redis.scard(distinct_key).to_i

          if staff_target?(target_identifier, target_digest, window)
            staff_key = "#{cluster_key}:staff"
            Discourse.redis.set(staff_key, "1", ex: cluster_ttl)
          end
        end
      end
      staff_targeted = Discourse.redis.get("#{cluster_key}:staff") == "1"

      single_threshold =
        family.to_s == "failed_login" ? setting_integer(SINGLE_ACCOUNT_SETTING, 1, 10_000) : nil
      base_reached = total_count >= threshold || (single_threshold && target_count.to_i >= single_threshold)
      return false unless base_reached

      escalation_reached =
        total_count >= (threshold * 2) ||
          (single_threshold && target_count.to_i >= (single_threshold * 2))
      phase = escalation_reached ? "escalation" : "assessment"
      gate_key = "#{cluster_key}:processed:#{phase}"
      return true unless Discourse.redis.set(gate_key, "1", nx: true, ex: cluster_ttl)

      Jobs.enqueue(
        :account_security_process_auth_abuse_cluster,
        ip: normalized_ip,
        family: family.to_s,
        failure_count: total_count,
        target_failure_count: target_count.to_i,
        distinct_targets: distinct_targets,
        staff_targeted: staff_targeted,
        threshold: threshold,
        single_account_threshold: single_threshold,
        window_minutes: (window / 1.minute).to_i,
        escalation: escalation_reached,
      )
      true
    rescue StandardError => e
      Rails.logger.warn("[account_security] local authentication-abuse telemetry failed family=#{family.to_s.first(32)} class=#{e.class}")
      false
    end

    def enabled?
      SiteSetting.account_security_enabled &&
        SiteSetting.account_security_auth_abuse_detection_enabled
    end

    def increment_fixed_window(key, window)
      ttl = window.to_i + 120
      return 1 if Discourse.redis.set(key, "1", nx: true, ex: ttl)

      count = Discourse.redis.incr(key).to_i
      ensure_expiry(key, ttl)
      count
    end

    def safe_ttl(key, window)
      ttl = Discourse.redis.ttl(key).to_i
      return ttl if ttl.positive?

      fallback = window.to_i + 120
      Discourse.redis.expire(key, fallback)
      fallback
    end

    def ensure_expiry(key, ttl)
      current = Discourse.redis.ttl(key).to_i
      Discourse.redis.expire(key, ttl) if current.negative?
    end

    def target_token(value)
      normalized = value.to_s.strip.downcase.byteslice(0, 320)
      return nil if normalized.blank?

      OpenSSL::HMAC.hexdigest("SHA256", Rails.application.secret_key_base.to_s, normalized)[0, 32]
    rescue StandardError
      nil
    end

    def staff_target?(identifier, token, window)
      cache_key = "#{KEY_PREFIX}:target_staff:#{token}"
      cached = Discourse.redis.get(cache_key)
      return cached == "1" unless cached.nil?

      candidate = identifier.to_s.strip.byteslice(0, 320)
      return false if candidate.blank?

      user = User.find_by_username_or_email(candidate)
      value = user&.staff? ? "1" : "0"
      Discourse.redis.set(cache_key, value, ex: [window.to_i, 1.hour.to_i].max)
      value == "1"
    rescue StandardError
      false
    end

    def setting_integer(name, min, max)
      SiteSetting.public_send(name).to_i.clamp(min, max)
    end
  end
end
