# frozen_string_literal: true

module ::AccountSecurity
  module RiskEventAuditTrail
    module_function

    ACTIONS = %w[
      event_created
      incident_escalated
      review_changed
      intelligence_refreshed
      user_note_added
      temporary_block_created
      temporary_block_released
      notification_suppression_created
      notification_suppression_released
      abuse_report_attempted
      abuse_reported
      staff_notified
    ].freeze

    SAFE_DETAIL_KEYS = %w[
      risk_level_from
      risk_level_to
      severity_from
      severity_to
      evidence_from
      evidence_to
      resolution_reason
      source
      result
      duration_minutes
      duration_hours
      temporary_block_id
      notification_suppression_id
      provider_report_id
      provider_status
      notification_kind
      automatic
    ].freeze

    def record!(event:, action:, actor: nil, from_status: nil, to_status: nil, details: {})
      return false unless event&.persisted?

      action = action.to_s
      return false unless ACTIONS.include?(action)

      RiskEventAudit.create!(
        risk_event_id: event.id,
        actor_user_id: actor&.id,
        action: action,
        from_status: safe_status(from_status),
        to_status: safe_status(to_status),
        details: sanitize_details(details),
        created_at: Time.zone.now,
      )
      true
    rescue StandardError => e
      Rails.logger.warn(
        "[account_security] risk-event audit failed event_id=#{event&.id} action=#{action.to_s.first(48)} class=#{e.class}",
      )
      false
    end

    def history_for(event_id, limit: 100)
      id = Integer(event_id, exception: false)
      return [] unless id&.positive?

      RiskEventAudit
        .includes(:actor_user)
        .where(risk_event_id: id)
        .order(created_at: :desc, id: :desc)
        .limit(limit.to_i.clamp(1, 250))
        .to_a
    rescue ActiveRecord::StatementInvalid
      []
    end

    def sanitize_details(details)
      source = details.is_a?(Hash) ? details : {}
      source.each_with_object({}) do |(key, value), safe|
        name = key.to_s
        next unless SAFE_DETAIL_KEYS.include?(name)

        sanitized = sanitize_value(name, value)
        safe[name] = sanitized unless sanitized.nil?
      end
    end

    def sanitize_value(name, value)
      return value == true if name == "automatic" && [true, false].include?(value)
      return value if value.is_a?(Integer) && value >= 0

      max = name == "resolution_reason" ? 240 : 80
      value.to_s.gsub(/[[:cntrl:]]+/, " ").squish.byteslice(0, max).presence
    end

    def safe_status(value)
      token = value.to_s
      RiskEvent::STATUSES.include?(token) ? token : nil
    end
  end
end
