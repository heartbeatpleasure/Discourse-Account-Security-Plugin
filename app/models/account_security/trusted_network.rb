# frozen_string_literal: true
module ::AccountSecurity
  class TrustedNetwork < ActiveRecord::Base
    self.table_name = "account_security_trusted_networks"
    SCOPES = %w[bypass_lookup suppress_enforcement bypass_lookup_and_enforcement].freeze
    belongs_to :created_by, class_name: "::User"
    validates :network, :label, :reason, presence: true
    validates :scope, inclusion: { in: SCOPES }

    scope :active, -> { where("expires_at IS NULL OR expires_at > ?", Time.zone.now) }
  end
end
