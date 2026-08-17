# frozen_string_literal: true

module ::AccountSecurity
  class RiskEvent < ActiveRecord::Base
    self.table_name = "account_security_risk_events"

    STATUSES = %w[open acknowledged benign monitor actioned auto_resolved].freeze
    EVENT_TYPES = %w[registration login_new_network login_familiar staff_login_new_network manual_lookup auth_failure_cluster other].freeze
    SEVERITIES = %w[elevated high critical].freeze

    belongs_to :user, optional: true
    belongs_to :ip_intelligence, class_name: "::AccountSecurity::IpIntelligence", optional: true
    belongs_to :reviewed_by, class_name: "::User", optional: true
    has_many :temporary_ip_blocks,
             class_name: "::AccountSecurity::TemporaryIpBlock",
             foreign_key: :risk_event_id

    validates :event_type, inclusion: { in: EVENT_TYPES }
    validates :severity, inclusion: { in: SEVERITIES }
    validates :status, inclusion: { in: STATUSES }
    before_validation :set_workflow_defaults

    validates :occurrence_count, numericality: { only_integer: true, greater_than: 0 }

    private

    def set_workflow_defaults
      self.occurrence_count = 1 if occurrence_count.to_i <= 0
      self.last_seen_at ||= Time.zone.now
    end
  end
end
