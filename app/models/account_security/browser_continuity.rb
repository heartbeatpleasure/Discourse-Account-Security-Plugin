# frozen_string_literal: true

module ::AccountSecurity
  class BrowserContinuity < ActiveRecord::Base
    self.table_name = "account_security_browser_continuities"

    belongs_to :user

    validates :token_hash, :first_seen_at, :last_seen_at, presence: true
    validates :token_hash, format: { with: /\A[0-9a-f]{64}\z/ }
    validates :observation_count, numericality: { only_integer: true, greater_than: 0 }
  end
end
