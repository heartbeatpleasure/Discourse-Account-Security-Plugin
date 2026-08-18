# frozen_string_literal: true

module ::AccountSecurity
  class AccountCorrelation < ActiveRecord::Base
    self.table_name = "account_security_account_correlations"

    STATUSES = %w[open monitor expected_shared_network confirmed_duplicate dismissed].freeze
    CONFIDENCES = %w[weak moderate strong very_strong].freeze

    belongs_to :user_a, class_name: "::User", optional: true
    belongs_to :user_b, class_name: "::User", optional: true
    belongs_to :reviewed_by, class_name: "::User", optional: true
    belongs_to :primary_user, class_name: "::User", optional: true
    has_many :reviews,
             class_name: "::AccountSecurity::CorrelationReview",
             foreign_key: :account_correlation_id,
             dependent: :delete_all

    validates :user_a_id, :user_b_id, :score, :confidence, :status, :first_seen_at, :last_seen_at, presence: true
    validates :score, numericality: { only_integer: true, greater_than_or_equal_to: 0, less_than_or_equal_to: 100 }
    validates :confidence, inclusion: { in: CONFIDENCES }
    validates :status, inclusion: { in: STATUSES }
    validates :notified_score, numericality: { only_integer: true, greater_than_or_equal_to: 0, less_than_or_equal_to: 100 }, allow_nil: true
    validates :notified_confidence, inclusion: { in: CONFIDENCES }, allow_nil: true
    validates :notified_public_ip_count, numericality: { only_integer: true, greater_than_or_equal_to: 0 }, allow_nil: true
    validate :ordered_distinct_users
    validate :primary_user_belongs_to_pair

    scope :unresolved, -> { where(status: %w[open monitor]) }

    private

    def ordered_distinct_users
      return if user_a_id.blank? || user_b_id.blank?
      errors.add(:user_b_id, :invalid) unless user_a_id < user_b_id
    end

    def primary_user_belongs_to_pair
      return if primary_user_id.blank? || user_a_id.blank? || user_b_id.blank?
      return if [user_a_id.to_i, user_b_id.to_i].include?(primary_user_id.to_i)

      errors.add(:primary_user_id, :invalid)
    end
  end
end
