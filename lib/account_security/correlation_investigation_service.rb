# frozen_string_literal: true

module ::AccountSecurity
  module CorrelationInvestigationService
    module_function

    NOTE_REQUIRED_STATUSES = %w[expected_shared_network confirmed_duplicate dismissed].freeze
    HISTORY_LIMIT = 20

    def review!(correlation:, actor:, status:, note: nil, primary_user_id: nil, confirmed: false)
      ensure_actor!(actor)
      status = status.to_s
      raise Discourse::InvalidParameters.new(:status) unless AccountCorrelation::STATUSES.include?(status)
      raise Discourse::InvalidParameters.new(:confirmed) if status == "confirmed_duplicate" && confirmed != true

      note = normalize_note(note)
      primary_parameter_supplied = !primary_user_id.nil?
      requested_primary_user_id = normalize_primary_user_id(primary_user_id)

      AccountCorrelation.transaction do
        correlation.lock!
        from_status = correlation.status.to_s
        status_changed = status != from_status

        new_primary_user_id =
          if status == "confirmed_duplicate"
            if !status_changed && !primary_parameter_supplied
              correlation.primary_user_id
            else
              validate_primary_user_id!(correlation, requested_primary_user_id)
            end
          end
        primary_changed = correlation.primary_user_id.to_i != new_primary_user_id.to_i
        note_required =
          (status_changed &&
            (NOTE_REQUIRED_STATUSES.include?(status) || NOTE_REQUIRED_STATUSES.include?(from_status))) ||
            primary_changed

        raise Discourse::InvalidParameters.new(:review_note) if note_required && note.blank?

        if !status_changed && !primary_changed && note.blank?
          raise Discourse::InvalidParameters.new(:review_note)
        end

        action =
          if status_changed
            "status_changed"
          elsif primary_changed
            "primary_account_changed"
          else
            "note_added"
          end

        now = Time.zone.now
        correlation.update!(
          status: status,
          reviewed_by_id: actor.id,
          reviewed_at: now,
          resolution_reason: note&.each_char&.take(240)&.join,
          primary_user_id: new_primary_user_id,
        )
        CorrelationReview.create!(
          account_correlation_id: correlation.id,
          actor_user_id: actor.id,
          action: action,
          from_status: from_status,
          to_status: status,
          note: note,
          primary_user_id: new_primary_user_id,
        )
      end

      correlation.reload
    end

    def history_for(correlation_ids, limit_per_correlation: HISTORY_LIMIT)
      ids = Array(correlation_ids).map(&:to_i).select(&:positive?).uniq
      return {} if ids.empty?

      rows =
        CorrelationReview
          .where(account_correlation_id: ids)
          .includes(:actor_user, :primary_user)
          .order(account_correlation_id: :asc, created_at: :desc, id: :desc)
          .to_a

      rows.group_by(&:account_correlation_id).transform_values do |items|
        items.first(limit_per_correlation)
      end
    end

    def required_note_for?(status)
      NOTE_REQUIRED_STATUSES.include?(status.to_s)
    end

    def validate_primary_user_id!(correlation, value)
      return nil if value.nil?
      allowed = [correlation.user_a_id.to_i, correlation.user_b_id.to_i]
      raise Discourse::InvalidParameters.new(:primary_user_id) unless allowed.include?(value)
      value
    end

    def normalize_primary_user_id(value)
      return nil if value.blank?
      parsed = Integer(value, exception: false)
      raise Discourse::InvalidParameters.new(:primary_user_id) unless parsed&.positive?
      parsed
    end

    def normalize_note(value)
      SafeText.plain(value, max_chars: 1_000)
    end

    def ensure_actor!(actor)
      raise Discourse::InvalidAccess unless actor&.admin?
    end
  end
end
