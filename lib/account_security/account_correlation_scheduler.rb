# frozen_string_literal: true

require "digest"
require "time"
require "tzinfo"

module ::AccountSecurity
  module AccountCorrelationScheduler
    module_function

    LAST_SLOT_KEY_PREFIX = "correlation_auto_scan_last_slot"
    FREQUENCIES = %w[off weekly monthly quarterly yearly].freeze
    WEEKDAYS = {
      "monday" => 1,
      "tuesday" => 2,
      "wednesday" => 3,
      "thursday" => 4,
      "friday" => 5,
      "saturday" => 6,
      "sunday" => 7,
    }.freeze
    DEFAULT_TIMEZONE = "UTC"

    def run_if_due!(now: Time.now.utc)
      return { enabled: false, frequency: frequency } unless enabled?

      now = now.utc
      slot = latest_slot(now)
      last = last_slot

      # A new or changed schedule establishes its current slot first. This avoids
      # unexpectedly launching a historical full scan immediately after upgrade
      # or after an administrator edits the cadence/timezone.
      if last.blank?
        store_last_slot(slot)
        return schedule_status(now: now).merge(initialized: true, enqueued: false)
      end

      return schedule_status(now: now).merge(enqueued: false) if last >= slot

      result = AccountCorrelationScanner.enqueue!(requested_by_id: nil, source: "scheduled")
      store_last_slot(slot) if result[:success]
      schedule_status(now: now).merge(
        enqueued: result[:success] == true,
        enqueue_result: result[:success] ? "queued" : result[:error_code],
      )
    rescue StandardError => e
      Rails.logger.warn("[account_security] correlation scheduler failed class=#{e.class}")
      schedule_status(now: now).merge(error_code: "scheduler_failed")
    end

    def schedule_status(now: Time.now.utc)
      now = now.utc
      config = configuration
      return config.merge(enabled: false, next_run_at: nil, last_scheduled_at: last_slot&.iso8601) unless enabled?

      config.merge(
        enabled: true,
        next_run_at: next_slot(now).iso8601,
        last_scheduled_at: last_slot&.iso8601,
      )
    rescue StandardError
      configuration.merge(enabled: enabled?, next_run_at: nil, last_scheduled_at: nil)
    end

    def health_status(now: Time.now.utc)
      now = now.utc
      schedule = schedule_status(now: now)
      return schedule.merge(state: "disabled", reason: nil, overdue: false) unless schedule[:enabled]

      last = last_slot
      expected = latest_slot(now)
      if last.blank?
        return schedule.merge(
          state: "initializing",
          reason: nil,
          overdue: false,
          expected_slot_at: expected.iso8601,
        )
      end

      overdue = last < expected && now >= expected + 45.minutes
      schedule.merge(
        state: overdue ? "degraded" : "healthy",
        reason: overdue ? "correlation_schedule_overdue" : nil,
        overdue: overdue,
        expected_slot_at: expected.iso8601,
      )
    rescue StandardError => e
      Rails.logger.warn("[account_security] correlation schedule health failed class=#{e.class}")
      configuration.merge(
        enabled: enabled?,
        state: "degraded",
        reason: "correlation_scheduler_failed",
        overdue: false,
        next_run_at: nil,
        last_scheduled_at: nil,
      )
    end

    def configuration
      {
        frequency: frequency,
        time: send_time,
        weekday: weekday,
        day_of_month: day_of_month,
        timezone: timezone,
      }
    end

    def enabled?
      SiteSetting.account_security_enabled &&
        SiteSetting.account_security_account_correlation_enabled &&
        frequency != "off"
    end

    def frequency
      value = SiteSetting.account_security_correlation_auto_scan_frequency.to_s
      FREQUENCIES.include?(value) ? value : "monthly"
    end

    def latest_slot(now)
      now = now.utc
      zone = time_zone
      local_now = now.in_time_zone(zone)
      hour, minute = send_time_parts

      candidate =
        case frequency
        when "weekly"
          target_cwday = WEEKDAYS.fetch(weekday, 7)
          date = local_now.to_date - ((local_now.to_date.cwday - target_cwday) % 7).days
          local_slot(date, hour, minute, zone)
        when "quarterly"
          quarterly_slot(local_now, hour, minute, zone)
        when "yearly"
          local_slot(Date.new(local_now.year, 1, day_of_month), hour, minute, zone)
        else
          local_slot(Date.new(local_now.year, local_now.month, day_of_month), hour, minute, zone)
        end

      if candidate > local_now
        candidate = previous_slot_from(candidate, hour, minute, zone)
      end

      candidate.utc
    end

    def next_slot(now)
      zone = time_zone
      latest_local = latest_slot(now).in_time_zone(zone)
      hour, minute = send_time_parts
      next_date =
        case frequency
        when "weekly"
          latest_local.to_date + 7.days
        when "quarterly"
          latest_local.to_date >> 3
        when "yearly"
          Date.new(latest_local.year + 1, 1, day_of_month)
        else
          latest_local.to_date >> 1
        end

      local_slot(next_date, hour, minute, zone).utc
    end

    def quarterly_slot(local_now, hour, minute, zone)
      quarter_month = ((local_now.month - 1) / 3) * 3 + 1
      local_slot(Date.new(local_now.year, quarter_month, day_of_month), hour, minute, zone)
    end

    def previous_slot_from(candidate, hour, minute, zone)
      previous_date =
        case frequency
        when "weekly"
          candidate.to_date - 7.days
        when "quarterly"
          candidate.to_date << 3
        when "yearly"
          Date.new(candidate.year - 1, 1, day_of_month)
        else
          candidate.to_date << 1
        end
      local_slot(previous_date, hour, minute, zone)
    end

    def local_slot(date, hour, minute, zone)
      zone.local(date.year, date.month, date.day, hour, minute)
    end

    def weekday
      value = SiteSetting.account_security_correlation_auto_scan_weekday.to_s
      WEEKDAYS.key?(value) ? value : "sunday"
    end

    def day_of_month
      SiteSetting.account_security_correlation_auto_scan_day_of_month.to_i.clamp(1, 28)
    end

    def send_time
      value = SiteSetting.account_security_correlation_auto_scan_time.to_s
      valid_send_time?(value) ? value : "03:00"
    end

    def send_time_parts
      match = /\A([01]\d|2[0-3]):([0-5]\d)\z/.match(send_time)
      [match[1].to_i, match[2].to_i]
    end

    def valid_send_time?(value)
      /\A(?:[01]\d|2[0-3]):[0-5]\d\z/.match?(value.to_s)
    end

    def timezone
      # The schedule is configured only through Installed Plugins -> Settings.
      # Use the site-contact account timezone as the stable site-level wall clock;
      # retain the hidden legacy value only as a compatibility fallback.
      contact = site_contact_timezone
      return contact if valid_timezone?(contact)

      configured = SiteSetting.account_security_correlation_auto_scan_timezone.to_s
      return configured if valid_timezone?(configured)

      DEFAULT_TIMEZONE
    end

    def site_contact_timezone
      username = SiteSetting.site_contact_username.to_s.downcase
      return nil if username.blank?
      User.find_by(username_lower: username)&.user_option&.timezone.to_s.presence
    rescue StandardError
      nil
    end

    def valid_timezone?(value)
      return false if value.blank? || value.bytesize > 100
      TZInfo::Timezone.get(value.to_s)
      true
    rescue TZInfo::InvalidTimezoneIdentifier
      false
    end

    def time_zone
      Time.find_zone(timezone) || Time.find_zone!(DEFAULT_TIMEZONE)
    end

    def last_slot
      value = PluginStore.get(STORE_NAMESPACE, last_slot_key)
      return nil if value.blank?
      Time.iso8601(value.to_s).utc
    rescue ArgumentError, TypeError
      nil
    end

    def store_last_slot(value)
      PluginStore.set(STORE_NAMESPACE, last_slot_key, value.utc.iso8601)
    end

    def last_slot_key
      fingerprint = Digest::SHA256.hexdigest(
        [frequency, send_time, weekday, day_of_month, timezone].join("|"),
      ).first(16)
      "#{LAST_SLOT_KEY_PREFIX}:#{fingerprint}"
    end

  end
end
