# frozen_string_literal: true

module ::AccountSecurity
  class AccountCorrelation < ActiveRecord::Base
    self.table_name = "account_security_account_correlations"

    STATUSES = %w[open monitor expected_shared_network confirmed_duplicate dismissed].freeze
    CONFIDENCES = %w[weak moderate strong very_strong].freeze

    belongs_to :user_a, class_name: "::User", optional: true
    belongs_to :user_b, class_name: "::User", optional: true
    belongs_to :reviewed_by, class_name: "::User", optional: true

    validates :user_a_id, :user_b_id, :score, :confidence, :status, :first_seen_at, :last_seen_at, presence: true
    validates :score, numericality: { only_integer: true, greater_than_or_equal_to: 0, less_than_or_equal_to: 100 }
    validates :confidence, inclusion: { in: CONFIDENCES }
    validates :status, inclusion: { in: STATUSES }
    validate :ordered_distinct_users

    scope :unresolved, -> { where(status: %w[open monitor]) }

    private

    def ordered_distinct_users
      return if user_a_id.blank? || user_b_id.blank?
      errors.add(:user_b_id, :invalid) unless user_a_id < user_b_id
    end
  end
end
