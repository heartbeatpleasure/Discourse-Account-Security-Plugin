# frozen_string_literal: true
module ::AccountSecurity
  class IpIntelligence < ActiveRecord::Base
    self.table_name = "account_security_ip_intelligence"

    RISK_LEVELS = %w[low observed elevated high critical].freeze
    EVIDENCE_LEVELS = %w[weak moderate strong corroborated].freeze

    validates :ip_address, presence: true, uniqueness: true
    validates :risk_level, inclusion: { in: RISK_LEVELS }
    validates :evidence_strength, inclusion: { in: EVIDENCE_LEVELS }
    validates :primary_score, inclusion: { in: 0..100 }, allow_nil: true
  end
end
