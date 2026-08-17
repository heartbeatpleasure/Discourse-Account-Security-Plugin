# frozen_string_literal: true
module ::AccountSecurity
  class DailyStat < ActiveRecord::Base
    self.table_name = "account_security_daily_stats"
  end
end
