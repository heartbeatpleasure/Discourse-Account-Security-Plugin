# frozen_string_literal: true

module ::AccountSecurity
  module UserNoteWriter
    module_function

    NOTE_MUTEX_PREFIX = "account-security-user-note"

    def available?
      return false unless SiteSetting.account_security_user_notes_enabled
      return false unless defined?(::DiscourseUserNotes)
      return false unless SiteSetting.respond_to?(:user_notes_enabled) && SiteSetting.user_notes_enabled
      return false unless ::DiscourseUserNotes.respond_to?(:add_note)

      true
    end

    def eligible?(event, automatic: false)
      return false unless available?
      return false unless event&.user&.persisted?
      return false unless event.severity.in?(%w[high critical])
      return false if automatic && !automatic_escalation?(event)

      true
    end

    def record!(event:, actor: nil, automatic: false)
      return false unless eligible?(event, automatic: automatic)

      DistributedMutex.synchronize("#{NOTE_MUTEX_PREFIX}-#{event.id}", validity: 10) do
        current = RiskEvent.includes(:user).find_by(id: event.id)
        next false unless eligible?(current, automatic: automatic)
        next false if current.user_note_created_at.present?

        note = I18n.t(
          "account_security.user_note",
          event_id: current.id,
          event_type: current.event_type.to_s.humanize,
          severity: current.severity.to_s.humanize,
        )
        ::DiscourseUserNotes.add_note(current.user, note, Discourse::SYSTEM_USER_ID)
        current.update_columns(user_note_created_at: Time.zone.now, updated_at: Time.zone.now)
        StaffAudit.log!(actor: actor, action: "user_note_added", details: { event_id: current.id }) if actor
        RiskEventAuditTrail.record!(
          event: current,
          action: "user_note_added",
          actor: actor,
          details: { automatic: automatic == true },
        )
        true
      end
    rescue StandardError => e
      Rails.logger.warn("[account_security] user note failed class=#{e.class}")
      false
    end

    def automatic_escalation?(event)
      strong_signal = event.evidence_strength.in?(%w[strong corroborated])
      critical_registration = event.event_type == "registration" && event.severity == "critical" && strong_signal
      repeated_high_risk = event.severity.in?(%w[high critical]) && strong_signal && event.occurrence_count.to_i >= 3

      critical_registration || repeated_high_risk
    end
  end
end
