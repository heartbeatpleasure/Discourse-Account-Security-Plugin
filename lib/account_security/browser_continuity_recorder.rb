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

      digest = ensure_token_hash!(cookies: cookies)
      return nil if digest.blank?

      Jobs.enqueue(:account_security_record_browser_continuity, user_id: user.id, token_hash: digest)
      digest
    rescue StandardError => e
      Rails.logger.warn("[account_security] browser continuity capture failed class=#{e.class}")
      nil
    end


    def ensure_token_hash!(cookies:)
      return nil unless enabled?

      signed_cookies = cookies&.signed
      return nil if signed_cookies.blank?

      token = signed_cookies[COOKIE_NAME].to_s
      token = SecureRandom.urlsafe_base64(TOKEN_BYTES, false) unless valid_token?(token)

      # Refresh the expiry while retaining the same random browser-profile token.
      # A missing or different token is never interpreted negatively.
      signed_cookies[COOKIE_NAME] = {
        value: token,
        expires: cookie_lifetime.from_now,
        path: "/",
        secure: true,
        httponly: true,
        same_site: :lax,
      }

      token_hash(token)
    rescue StandardError => e
      Rails.logger.warn("[account_security] browser continuity cookie refresh failed class=#{e.class}")
      nil
    end

    def record!(user_id:, token_hash:, observed_at: Time.zone.now, recalculate: true)
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

      recalculate_related_pairs!(user.id, token_hash, observed_at) if recalculate
      record
    rescue ActiveRecord::RecordNotUnique
      retry_record = BrowserContinuity.find_by(user_id: user_id.to_i, token_hash: token_hash)
      retry_record&.update_columns(
        last_seen_at: [retry_record.last_seen_at, observed_at].compact.max,
        observation_count: retry_record.observation_count.to_i + 1,
        updated_at: Time.zone.now,
      )
      recalculate_related_pairs!(user_id.to_i, token_hash, observed_at) if recalculate
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
        account_switch_count: 0,
        account_switch_closest_gap_seconds: nil,
        account_switch_within_1h_count: 0,
        account_switch_within_6h_count: 0,
        account_switch_within_24h_count: 0,
        account_switch_within_7d_count: 0,
        account_switch_history_complete: false,
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

      switch_summary = account_switch_summary(user_a_id, user_b_id, shared)

      {
        count: shared.length,
        max_users: max_users,
        repeated_count: repeated_count,
        paired_observations: paired_observations,
        max_span_days: (max_span_seconds.to_f / 1.day.to_i).floor,
      }.merge(switch_summary)
    rescue ActiveRecord::StatementInvalid
      empty
    end

    def account_switch_summary(user_a_id, user_b_id, token_hashes = nil)
      empty = empty_switch_summary
      return empty unless defined?(SessionObservation)

      tokens = Array(token_hashes).map(&:to_s).select { |value| valid_hash?(value) }.uniq
      return empty if tokens.empty?

      rows =
        SessionObservation
          .where(user_id: [user_a_id.to_i, user_b_id.to_i], browser_token_hash: tokens)
          .where("observed_at >= ?", retention_cutoff)
          .order(:browser_token_hash, :observed_at, :id)
          .limit(10_001)
          .pluck(:browser_token_hash, :user_id, :observed_at)
      complete = rows.length <= 10_000
      rows = rows.first(10_000) unless complete

      switch_summary_from_rows(rows, user_a_id, user_b_id).merge(account_switch_history_complete: complete)
    rescue ActiveRecord::StatementInvalid
      empty
    end

    def switch_summary_from_rows(rows, user_a_id, user_b_id)
      pair_ids = [user_a_id.to_i, user_b_id.to_i].sort
      gaps = []

      Array(rows).group_by { |row| row[0].to_s }.each_value do |token_rows|
        collapsed = []
        token_rows.sort_by { |row| row[2] }.each do |_token, user_id, observed_at|
          user_id = user_id.to_i
          next unless pair_ids.include?(user_id) && observed_at.present?

          if collapsed.last&.dig(:user_id) == user_id
            collapsed[-1] = { user_id: user_id, at: observed_at }
          else
            collapsed << { user_id: user_id, at: observed_at }
          end
        end

        collapsed.each_cons(2) do |left, right|
          next if left[:user_id] == right[:user_id]
          gaps << (right[:at] - left[:at]).abs.to_i
        end
      end

      {
        account_switch_count: gaps.length,
        account_switch_closest_gap_seconds: gaps.min,
        account_switch_within_1h_count: gaps.count { |gap| gap <= 1.hour.to_i },
        account_switch_within_6h_count: gaps.count { |gap| gap <= 6.hours.to_i },
        account_switch_within_24h_count: gaps.count { |gap| gap <= 1.day.to_i },
        account_switch_within_7d_count: gaps.count { |gap| gap <= 7.days.to_i },
      }
    end

    def empty_switch_summary
      {
        account_switch_count: 0,
        account_switch_closest_gap_seconds: nil,
        account_switch_within_1h_count: 0,
        account_switch_within_6h_count: 0,
        account_switch_within_24h_count: 0,
        account_switch_within_7d_count: 0,
        account_switch_history_complete: false,
      }
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
