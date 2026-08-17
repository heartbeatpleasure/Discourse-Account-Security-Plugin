# frozen_string_literal: true
class CreateAccountSecurityRiskEvents < ActiveRecord::Migration[7.0]
  def change
    create_table :account_security_risk_events do |t|
      t.bigint :user_id
      t.inet :ip_address, null: false
      t.string :event_type, null: false, limit: 32
      t.string :severity, null: false, limit: 16
      t.string :risk_level, null: false, limit: 16
      t.string :evidence_strength, null: false, limit: 16
      t.bigint :ip_intelligence_id
      t.jsonb :context, null: false, default: {}
      t.string :status, null: false, limit: 20, default: "open"
      t.string :incident_key, limit: 96
      t.bigint :reviewed_by_id
      t.datetime :reviewed_at
      t.string :resolution_reason, limit: 240
      t.timestamps null: false
    end
    add_index :account_security_risk_events, [:created_at, :severity, :status], name: "idx_as_events_queue"
    add_index :account_security_risk_events, [:user_id, :created_at], name: "idx_as_events_user_time"
    add_index :account_security_risk_events, [:ip_address, :created_at], name: "idx_as_events_ip_time"
    add_index :account_security_risk_events, :incident_key, name: "idx_as_events_incident"
  end
end
