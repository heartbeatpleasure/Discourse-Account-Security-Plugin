# frozen_string_literal: true
class CreateAccountSecurityIpIntelligence < ActiveRecord::Migration[7.0]
  def change
    create_table :account_security_ip_intelligence do |t|
      t.inet :ip_address, null: false
      t.string :risk_level, null: false, limit: 16, default: "low"
      t.string :evidence_strength, null: false, limit: 16, default: "weak"
      t.integer :primary_score
      t.integer :total_reports
      t.integer :distinct_reporters
      t.datetime :last_reported_at
      t.string :usage_type, limit: 120
      t.string :isp, limit: 160
      t.string :domain, limit: 160
      t.string :country_code, limit: 2
      t.boolean :is_tor, null: false, default: false
      t.boolean :local_blacklist_match, null: false, default: false
      t.datetime :provider_checked_at
      t.datetime :next_check_after
      t.datetime :first_seen_at, null: false
      t.datetime :last_seen_at, null: false
      t.jsonb :source_summary, null: false, default: {}
      t.timestamps null: false
    end
    add_index :account_security_ip_intelligence, :ip_address, unique: true, name: "idx_as_intel_ip"
    add_index :account_security_ip_intelligence, :next_check_after, name: "idx_as_intel_next_check"
    add_index :account_security_ip_intelligence, [:risk_level, :last_seen_at], name: "idx_as_intel_risk_seen"
  end
end
