# frozen_string_literal: true

require "time"

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

    def run_if_due!(now: Time.now.utc)
      return { enabled: false, frequency: frequency } unless enabled?

      now = now.utc
      slot = latest_slot(now)
      last = last_slot

      # On first execution after installing/upgrading, establish the current slot
      # without launching an unexpected full scan immediately. Manual scan remains available.
      if last.blank?
        store_last_slot(slot)
        return schedule_status(now: now).merge(initialized: true, enqueued: false)
      end

      return schedule_status(now: now).merge(enqueued: false) if last >= slot

      result = AccountCorrelationScanner.enqueue!(requested_by_id: nil, source: "scheduled")
      store_last_slot(slot) if result[:success]
      schedule_status(now: now).merge(enqueued: result[:success] == true, enqueue_result: result[:success] ? "queued" : result[:error_code])
    rescue StandardError => e
      Rails.logger.warn("[account_security] correlation scheduler failed class=#{e.class}")
      schedule_status(now: now).merge(error_code: "scheduler_failed")
    end

    def schedule_status(now: Time.now.utc)
      now = now.utc
      return { enabled: false, frequency: frequency, timezone: "UTC", next_run_at: nil } unless enabled?

      {
        enabled: true,
        frequency: frequency,
        timezone: "UTC",
        next_run_at: next_slot(now).iso8601,
        last_scheduled_at: last_slot&.iso8601,
      }
    rescue StandardError
      { enabled: enabled?, frequency: frequency, timezone: "UTC", next_run_at: nil }
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
      hour, minute = send_time_parts
      case frequency
      when "weekly"
        target_cwday = WEEKDAYS.fetch(weekday, 7)
        date = now.to_date - ((now.to_date.cwday - target_cwday) % 7).days
        candidate = Time.utc(date.year, date.month, date.day, hour, minute)
        candidate -= 7.days if candidate > now
        candidate
      when "quarterly"
        quarterly_slot(now, hour, minute)
      when "yearly"
        candidate = Time.utc(now.year, 1, day_of_month, hour, minute)
        candidate = Time.utc(now.year - 1, 1, day_of_month, hour, minute) if candidate > now
        candidate
      else
        candidate = Time.utc(now.year, now.month, day_of_month, hour, minute)
        if candidate > now
          previous = now.to_date << 1
          candidate = Time.utc(previous.year, previous.month, day_of_month, hour, minute)
        end
        candidate
      end
    end

    def next_slot(now)
      latest = latest_slot(now)
      case frequency
      when "weekly"
        latest + 7.days
      when "quarterly"
        date = latest.to_date >> 3
        Time.utc(date.year, date.month, day_of_month, latest.hour, latest.min)
      when "yearly"
        Time.utc(latest.year + 1, 1, day_of_month, latest.hour, latest.min)
      else
        date = latest.to_date >> 1
        Time.utc(date.year, date.month, day_of_month, latest.hour, latest.min)
      end
    end

    def quarterly_slot(now, hour, minute)
      quarter_month = ((now.month - 1) / 3) * 3 + 1
      candidate = Time.utc(now.year, quarter_month, day_of_month, hour, minute)
      return candidate if candidate <= now

      date = candidate.to_date << 3
      Time.utc(date.year, date.month, day_of_month, hour, minute)
    end

    def weekday
      value = SiteSetting.account_security_correlation_auto_scan_weekday.to_s
      WEEKDAYS.key?(value) ? value : "sunday"
    end

    def day_of_month
      SiteSetting.account_security_correlation_auto_scan_day_of_month.to_i.clamp(1, 28)
    end

    def send_time_parts
      value = SiteSetting.account_security_correlation_auto_scan_time.to_s
      match = /\A([01]\d|2[0-3]):([0-5]\d)\z/.match(value)
      return [3, 0] if match.blank?
      [match[1].to_i, match[2].to_i]
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
      "#{LAST_SLOT_KEY_PREFIX}:#{frequency}"
    end
  end
end
