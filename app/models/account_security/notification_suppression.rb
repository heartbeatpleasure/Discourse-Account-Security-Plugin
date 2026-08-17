# frozen_string_literal: true

module ::AccountSecurity
  class NotificationSuppression < ActiveRecord::Base
    self.table_name = "account_security_notification_suppressions"

    belongs_to :user
    belongs_to :created_by, class_name: "::User", optional: true

    validates :network_key, presence: true, length: { maximum: 128 }
    validates :expires_at, presence: true
    validates :user_id, uniqueness: { scope: :network_key }

    scope :active, -> { where("expires_at > ?", Time.zone.now) }
  end
end
