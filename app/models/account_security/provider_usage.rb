# frozen_string_literal: true
module ::AccountSecurity
  class ProviderUsage < ActiveRecord::Base
    self.table_name = "account_security_provider_usages"
    validates :provider, :endpoint, presence: true
  end
end
