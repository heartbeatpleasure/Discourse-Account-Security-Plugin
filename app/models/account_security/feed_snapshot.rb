# frozen_string_literal: true
module ::AccountSecurity
  class FeedSnapshot < ActiveRecord::Base
    self.table_name = "account_security_feed_snapshots"
    validates :source, presence: true, uniqueness: true
  end
end
