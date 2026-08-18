# frozen_string_literal: true

module ::AccountSecurity
  class RiskEventAudit < ActiveRecord::Base
    self.table_name = "account_security_risk_event_audits"

    belongs_to :risk_event, class_name: "::AccountSecurity::RiskEvent"
    belongs_to :actor_user, class_name: "::User", optional: true

    validates :action, presence: true, inclusion: { in: ->(_record) { RiskEventAuditTrail::ACTIONS } }

    def readonly?
      persisted? || super
    end
  end
end
