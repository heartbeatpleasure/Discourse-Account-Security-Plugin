# frozen_string_literal: true

module ::AccountSecurity
  class SessionSignature < ActiveRecord::Base
    self.table_name = "account_security_session_signatures"

    belongs_to :user

    validates :network_key, :signature_hash, :first_seen_at, :last_seen_at, presence: true
    validates :signature_hash, format: { with: /\A[0-9a-f]{64}\z/ }
    validates :observation_count, numericality: { only_integer: true, greater_than: 0 }
  end
end
