# frozen_string_literal: true
class CreateAccountSecurityProviderState < ActiveRecord::Migration[7.0]
  def change
    create_table :account_security_provider_usages do |t|
      t.string :provider, null: false, limit: 32
      t.string :endpoint, null: false, limit: 32
      t.integer :request_count, null: false, default: 0
      t.integer :success_count, null: false, default: 0
      t.integer :error_count, null: false, default: 0
      t.integer :rate_limit
      t.integer :remaining
      t.datetime :reset_at
      t.integer :last_status
      t.datetime :last_request_at
      t.timestamps null: false
    end
    add_index :account_security_provider_usages, [:provider, :endpoint], unique: true, name: "idx_as_provider_endpoint"

    create_table :account_security_provider_reports do |t|
      t.bigint :risk_event_id, null: false
      t.inet :ip_address, null: false
      t.string :provider, null: false, limit: 32
      t.string :category, null: false, limit: 32
      t.bigint :reported_by_id, null: false
      t.string :status, null: false, limit: 24
      t.integer :provider_status
      t.datetime :reported_at
      t.timestamps null: false
    end
    add_index :account_security_provider_reports, :risk_event_id, unique: true, name: "idx_as_reports_risk_event"
    add_index :account_security_provider_reports, [:ip_address, :provider, :created_at], name: "idx_as_reports_ip_time"
  end
end
