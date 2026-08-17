# frozen_string_literal: true
module ::AccountSecurity
  class ProviderReport < ActiveRecord::Base
    self.table_name = "account_security_provider_reports"

    belongs_to :risk_event, class_name: "::AccountSecurity::RiskEvent"
    belongs_to :reported_by, class_name: "::User"

    validates :risk_event_id, :ip_address, :provider, :category, :status, presence: true
  end
end
