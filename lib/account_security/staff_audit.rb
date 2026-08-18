# frozen_string_literal: true

module ::AccountSecurity
  module StaffAudit
    module_function

    ALLOWED_ACTIONS = %w[
      event_review_changed
      event_refreshed
      user_note_added
      temporary_block_created
      temporary_block_released
      trusted_network_created
      trusted_network_deleted
      circuit_reset
      feed_synced
      notification_suppression_created
      notification_suppression_released
      abuse_reported
      account_correlation_review_changed
      account_correlation_user_note_added
      account_correlation_scan_started
    ].freeze

    SAFE_DETAIL_KEYS = %i[
      event_id
      status
      trusted_network_id
      temporary_block_id
      duration_minutes
      report_id
      notification_suppression_id
      duration_hours
      feed
      result
      correlation_id
    ].freeze

    SAFE_TOKEN = /\A[a-z0-9_.:-]{1,80}\z/i

    def log!(actor:, action:, details: {})
      return false unless actor&.admin?

      action = action.to_s
      return false unless ALLOWED_ACTIONS.include?(action)

      safe_details = { subject: "Account Security" }
      details.to_h.slice(*SAFE_DETAIL_KEYS).each do |key, value|
        sanitized = sanitize_detail(value)
        safe_details[key] = sanitized unless sanitized.nil?
      end

      StaffActionLogger.new(actor).log_custom("account_security_#{action}", safe_details)
      true
    rescue StandardError => e
      Rails.logger.warn("[account_security] staff audit failed class=#{e.class}")
      false
    end

    def sanitize_detail(value)
      return value if value.is_a?(Integer) && value >= 0

      token = value.to_s
      SAFE_TOKEN.match?(token) ? token : nil
    end
  end
end
