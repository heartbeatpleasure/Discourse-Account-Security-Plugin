# frozen_string_literal: true

require "openssl"
require "securerandom"
require "set"

module ::AccountSecurity
  module BrowserContinuityRecorder
    module_function

    COOKIE_NAME = "__Host-account_security_bc"
    TOKEN_BYTES = 32
    TOKEN_PATTERN = /\A[A-Za-z0-9_-]{43}\z/
    CONTEXT = "account_security:browser_continuity:v1"
    MAX_GROUP_USERS = 20

    def capture_login!(cookies:, user:)
      return nil unless enabled?
      return nil if user.blank? || !user.human? || user.staged? || user.id.to_i <= 0

      signed_cookies = cookies&.signed
      return nil if signed_cookies.blank?

      token = signed_cookies[COOKIE_NAME].to_s
      token = SecureRandom.urlsafe_base64(TOKEN_BYTES, false) unless valid_token?(token)

      # Refresh the expiry after each successful login while retaining the same
      # random token. The browser may still discard it (private browsing,
      # clearing site data, privacy controls, profile reset); that is why this
      # signal is strictly positive-only and supplemental; it never creates a
      # correlation candidate by itself.
      signed_cookies[COOKIE_NAME] = {
        value: token,
        expires: cookie_lifetime.from_now,
        path: "/",
        secure: true,
        httponly: true,
        same_site: :lax,
      }

      digest = token_hash(token)
      Jobs.enqueue(:account_security_record_browser_continuity, user_id: user.id, token_hash: digest)
      digest
    rescue StandardError => e
      Rails.logger.warn("[account_security] browser continuity capture failed class=#{e.class}")
      nil
    end

    def record!(user_id:, token_hash:, observed_at: Time.zone.now)
      return nil unless enabled?
      return nil unless valid_hash?(token_hash)

      user = User.human_users.where(staged: false).find_by(id: user_id.to_i)
      return nil if user.blank?

      record = BrowserContinuity.find_or_initialize_by(user_id: user.id, token_hash: token_hash)
      if record.new_record?
        record.first_seen_at = observed_at
        record.last_seen_at = observed_at
        record.observation_count = 1
      else
        record.first_seen_at = [record.first_seen_at, observed_at].compact.min
        record.last_seen_at = [record.last_seen_at, observed_at].compact.max
        record.observation_count = record.observation_count.to_i + 1
      end
      record.save!

      recalculate_related_pairs!(user.id, token_hash, observed_at)
      record
    rescue ActiveRecord::RecordNotUnique
      retry_record = BrowserContinuity.find_by(user_id: user_id.to_i, token_hash: token_hash)
      retry_record&.update_columns(
        last_seen_at: [retry_record.last_seen_at, observed_at].compact.max,
        observation_count: retry_record.observation_count.to_i + 1,
        updated_at: Time.zone.now,
      )
      recalculate_related_pairs!(user_id.to_i, token_hash, observed_at)
      retry_record
    rescue StandardError => e
      Rails.logger.warn("[account_security] browser continuity record failed class=#{e.class}")
      nil
    end

    def shared_summary(user_a_id, user_b_id)
      empty = {
        count: 0,
        max_users: 0,
        repeated_count: 0,
        paired_observations: 0,
        max_span_days: 0,
      }
      return empty unless enabled?

      cutoff = retention_cutoff
      rows_a =
        BrowserContinuity
          .where(user_id: user_a_id)
          .where("last_seen_at >= ?", cutoff)
          .pluck(:token_hash, :first_seen_at, :last_seen_at, :observation_count)
          .index_by(&:first)
      return empty if rows_a.empty?

      rows_b =
        BrowserContinuity
          .where(user_id: user_b_id, token_hash: rows_a.keys)
          .where("last_seen_at >= ?", cutoff)
          .pluck(:token_hash, :first_seen_at, :last_seen_at, :observation_count)
          .index_by(&:first)
      shared = rows_a.keys & rows_b.keys
      return empty if shared.empty?

      max_users =
        BrowserContinuity
          .where(token_hash: shared)
          .where("last_seen_at >= ?", cutoff)
          .group(:token_hash)
          .distinct
          .count(:user_id)
          .values
          .max
          .to_i

      repeated_count = 0
      paired_observations = 0
      max_span_seconds = 0
      shared.each do |token_hash|
        row_a = rows_a[token_hash]
        row_b = rows_b[token_hash]
        observations_a = row_a[3].to_i
        observations_b = row_b[3].to_i
        repeated_count += 1 if observations_a >= 2 && observations_b >= 2
        paired_observations += [observations_a, observations_b].min

        starts = [row_a[1], row_b[1]].compact
        finishes = [row_a[2], row_b[2]].compact
        if starts.any? && finishes.any?
          span = (finishes.max - starts.min).to_i
          max_span_seconds = [max_span_seconds, span].max
        end
      end

      {
        count: shared.length,
        max_users: max_users,
        repeated_count: repeated_count,
        paired_observations: paired_observations,
        max_span_days: (max_span_seconds.to_f / 1.day.to_i).floor,
      }
    rescue ActiveRecord::StatementInvalid
      empty || { count: 0, max_users: 0, repeated_count: 0, paired_observations: 0, max_span_days: 0 }
    end

    def cookie_lifetime
      SiteSetting.account_security_correlation_retention_days.to_i.clamp(30, 730).days
    end

    def retention_cutoff
      SiteSetting.account_security_correlation_retention_days.to_i.clamp(30, 730).days.ago
    end

    def token_hash(token)
      OpenSSL::HMAC.hexdigest("SHA256", hmac_key, token.to_s)
    end

    def valid_token?(value)
      value.to_s.match?(TOKEN_PATTERN)
    end

    def valid_hash?(value)
      value.to_s.match?(/\A[0-9a-f]{64}\z/)
    end

    def hmac_key
      @hmac_key ||= OpenSSL::HMAC.digest("SHA256", GlobalSetting.safe_secret_key_base, CONTEXT)
    end

    def enabled?
      SiteSetting.account_security_enabled &&
        SiteSetting.account_security_account_correlation_enabled &&
        SiteSetting.account_security_browser_continuity_enabled
    end

    def recalculate_related_pairs!(user_id, token_hash, observed_at)
      cutoff = retention_cutoff
      ids =
        BrowserContinuity
          .where(token_hash: token_hash)
          .where("last_seen_at >= ?", cutoff)
          .where.not(user_id: user_id)
          .distinct
          .limit(MAX_GROUP_USERS + 1)
          .pluck(:user_id)

      # A shared/public browser profile should not create an unbounded pair explosion.
      return if ids.length > MAX_GROUP_USERS

      ids.each do |other_id|
        AccountCorrelationService.recalculate_pair!(
          user_id,
          other_id,
          observed_at: observed_at,
          source: "browser_continuity",
        )
      end
    end
  end
end
