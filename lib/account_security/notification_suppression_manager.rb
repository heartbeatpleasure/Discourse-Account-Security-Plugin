# frozen_string_literal: true

require "digest"

module ::AccountSecurity
  module NotificationSuppressionManager
    module_function

    ALLOWED_HOURS = [24, 168, 720, 2160].freeze

    class NotEligible < StandardError; end

    def active_for(event)
      key = network_key(event)
      return nil if event&.user_id.blank? || key.blank?

      NotificationSuppression.active.find_by(user_id: event.user_id, network_key: key)
    end

    def create!(event:, actor:, duration_hours:)
      raise Discourse::InvalidAccess unless actor&.admin?
      raise NotEligible unless SiteSetting.account_security_staff_notifications_enabled
      key = network_key(event)
      raise NotEligible if event&.user_id.blank? || key.blank?

      hours = Integer(duration_hours, exception: false)
      raise Discourse::InvalidParameters.new(:duration_hours) unless ALLOWED_HOURS.include?(hours)

      record = nil
      mutex = "account-security-notification-suppression-#{event.user_id}-#{Digest::SHA256.hexdigest(key)[0, 20]}"
      DistributedMutex.synchronize(mutex, validity: 10) do
        record = NotificationSuppression.find_or_initialize_by(user_id: event.user_id, network_key: key)
        record.assign_attributes(created_by_id: actor.id, expires_at: Time.zone.now + hours.hours)
        record.save!
      rescue ActiveRecord::RecordNotUnique
        record = NotificationSuppression.find_by!(user_id: event.user_id, network_key: key)
        record.update!(created_by_id: actor.id, expires_at: Time.zone.now + hours.hours)
      end

      StaffAudit.log!(
        actor: actor,
        action: "notification_suppression_created",
        details: { event_id: event.id, notification_suppression_id: record.id, duration_hours: hours },
      )
      record
    end

    def release!(event:, actor:)
      raise Discourse::InvalidAccess unless actor&.admin?
      record = active_for(event)
      raise NotEligible unless record

      id = record.id
      record.destroy!
      StaffAudit.log!(
        actor: actor,
        action: "notification_suppression_released",
        details: { event_id: event.id, notification_suppression_id: id },
      )
      record
    end

    def network_key(event)
      context = event&.context.is_a?(Hash) ? event.context : {}
      context["familiarity_network"].to_s.presence
    end
  end
end
