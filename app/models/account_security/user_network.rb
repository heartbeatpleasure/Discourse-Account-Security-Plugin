# frozen_string_literal: true
module ::AccountSecurity
  class UserNetwork < ActiveRecord::Base
    self.table_name = "account_security_user_networks"
    belongs_to :user
    validates :network_key, presence: true
    validates :address_family, inclusion: { in: %w[ipv4 ipv6] }
  end
end
