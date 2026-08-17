# frozen_string_literal: true
class CreateAccountSecurityDailyStats < ActiveRecord::Migration[7.0]
  def change
    create_table :account_security_daily_stats do |t|
      t.date :stat_date, null: false
      t.integer :assessments, null: false, default: 0
      t.integer :registrations, null: false, default: 0
      t.integer :logins, null: false, default: 0
      t.integer :manual_lookups, null: false, default: 0
      t.integer :provider_calls, null: false, default: 0
      t.integer :cache_hits, null: false, default: 0
      t.integer :local_blacklist_hits, null: false, default: 0
      t.integer :tor_hits, null: false, default: 0
      t.integer :quota_skips, null: false, default: 0
      t.integer :provider_errors, null: false, default: 0
      t.integer :events_created, null: false, default: 0
      t.timestamps null: false
    end
    add_index :account_security_daily_stats, :stat_date, unique: true, name: "idx_as_daily_stat_date"
  end
end
