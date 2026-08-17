# frozen_string_literal: true
module ::AccountSecurity
  class FeedEntry < ActiveRecord::Base
    self.table_name = "account_security_feed_entries"
    validates :source, :ip_address, :generation, presence: true
  end
end
