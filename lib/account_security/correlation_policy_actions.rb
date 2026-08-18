# frozen_string_literal: true

module ::AccountSecurity
  module CorrelationPolicyActions
    module_function

    NOTE_ACTION = "duplicate_user_note_added"
    NOTE_MUTEX_PREFIX = "account-security-correlation-user-note"

    class NotEligible < StandardError; end

    def state_for(correlation_ids)
      ids = Array(correlation_ids).map(&:to_i).select(&:positive?).uniq
      return {} if ids.empty?

      CorrelationReview
        .where(account_correlation_id: ids, action: NOTE_ACTION)
        .order(created_at: :desc, id: :desc)
        .to_a
        .group_by(&:account_correlation_id)
    end

    def payload(correlation, note_actions: nil)
      primary_id = correlation.primary_user_id&.to_i
      additional_id = additional_user_id(correlation)
      primary = correlation.primary_user if primary_id.present?
      additional = additional_user(correlation) if additional_id.present?
      actions = note_actions.nil? ? Array(state_for([correlation.id])[correlation.id]) : Array(note_actions)
      current_note =
        if primary_id.present?
          actions.find { |review| review.primary_user_id.to_i == primary_id }
        end

      {
        available: correlation.status == "confirmed_duplicate",
        ready:
          correlation.status == "confirmed_duplicate" &&
            primary.present? &&
            additional.present?,
        primary_user_id: primary_id,
        additional_user_id: additional_id,
        user_notes_enabled: UserNoteWriter.available?,
        duplicate_user_note_available:
          duplicate_user_note_eligible?(correlation, note_actions: actions),
        duplicate_user_note_added_at: current_note&.created_at&.iso8601,
      }
    end

    def duplicate_user_note_eligible?(correlation, note_actions: nil)
      return false unless UserNoteWriter.available?
      return false unless correlation&.status == "confirmed_duplicate"
      return false if correlation.primary_user_id.blank?
      return false if correlation.primary_user.blank?
      return false if additional_user(correlation).blank?

      actions = note_actions || state_for([correlation.id])[correlation.id]
      !Array(actions).any? { |review| review.primary_user_id.to_i == correlation.primary_user_id.to_i }
    end

    def add_duplicate_user_note!(correlation:, actor:)
      ensure_actor!(actor)

      DistributedMutex.synchronize("#{NOTE_MUTEX_PREFIX}-#{correlation.id}", validity: 10) do
        AccountCorrelation.transaction do
          current = AccountCorrelation.lock.find(correlation.id)
          raise NotEligible unless duplicate_user_note_eligible?(current)

          primary = current.primary_user
          additional = additional_user(current)
          raise NotEligible if primary.blank? || additional.blank?

          note =
            I18n.t(
              "account_security.correlation_duplicate_user_note",
              correlation_id: current.id,
              primary_username: primary.username,
            )

          ::DiscourseUserNotes.add_note(additional, note, Discourse::SYSTEM_USER_ID)

          CorrelationReview.create!(
            account_correlation_id: current.id,
            actor_user_id: actor.id,
            action: NOTE_ACTION,
            from_status: current.status,
            to_status: current.status,
            primary_user_id: primary.id,
          )
        end
      end

      StaffAudit.log!(
        actor: actor,
        action: "account_correlation_user_note_added",
        details: { correlation_id: correlation.id },
      )
      true
    rescue NotEligible
      raise
    rescue StandardError => e
      Rails.logger.warn("[account_security] correlation user note failed class=#{e.class}")
      false
    end

    def additional_user(correlation)
      id = additional_user_id(correlation)
      return nil if id.blank?
      return correlation.user_a if correlation.user_a_id.to_i == id
      return correlation.user_b if correlation.user_b_id.to_i == id

      User.find_by(id: id)
    end

    def additional_user_id(correlation)
      primary_id = correlation&.primary_user_id&.to_i
      return nil unless primary_id&.positive?

      ids = [correlation.user_a_id.to_i, correlation.user_b_id.to_i]
      return nil unless ids.include?(primary_id)

      ids.find { |id| id != primary_id }
    end

    def ensure_actor!(actor)
      raise Discourse::InvalidAccess unless actor&.admin?
    end
  end
end
