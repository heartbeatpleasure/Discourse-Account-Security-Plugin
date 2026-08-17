# frozen_string_literal: true

module ::AccountSecurity
  class TemporaryIpBlock < ActiveRecord::Base
    self.table_name = "account_security_temporary_ip_blocks"

    belongs_to :risk_event, class_name: "::AccountSecurity::RiskEvent"
    belongs_to :created_by, class_name: "::User", optional: true

    validates :risk_event_id, :screened_ip_address_id, :ip_address, :expires_at, presence: true

    scope :active, -> { where(released_at: nil).where("expires_at > ?", Time.zone.now) }
    scope :unreleased, -> { where(released_at: nil) }
  end
end
