# frozen_string_literal: true

module ::AccountSecurity
  class SessionObservation < ActiveRecord::Base
    self.table_name = "account_security_session_observations"

    belongs_to :user

    validates :ip_address, :observed_at, presence: true
    validates :browser_token_hash,
              format: { with: /\A[0-9a-f]{64}\z/ },
              allow_nil: true
    validates :client_signature_hash,
              format: { with: /\A[0-9a-f]{64}\z/ },
              allow_nil: true
  end
end
