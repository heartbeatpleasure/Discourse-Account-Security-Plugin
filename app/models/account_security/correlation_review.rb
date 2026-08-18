# frozen_string_literal: true

module ::AccountSecurity
  class CorrelationReview < ActiveRecord::Base
    self.table_name = "account_security_correlation_reviews"

    ACTIONS = %w[status_changed note_added primary_account_changed duplicate_user_note_added].freeze

    belongs_to :account_correlation,
               class_name: "::AccountSecurity::AccountCorrelation",
               foreign_key: :account_correlation_id
    belongs_to :actor_user, class_name: "::User", optional: true
    belongs_to :primary_user, class_name: "::User", optional: true

    validates :account_correlation_id, :action, presence: true
    validates :action, inclusion: { in: ACTIONS }
    validates :from_status, inclusion: { in: AccountCorrelation::STATUSES }, allow_nil: true
    validates :to_status, inclusion: { in: AccountCorrelation::STATUSES }, allow_nil: true
    validates :note, length: { maximum: 1_000 }, allow_nil: true
  end
end
