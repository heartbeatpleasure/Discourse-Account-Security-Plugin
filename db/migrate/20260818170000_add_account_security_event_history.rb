# frozen_string_literal: true

class AddAccountSecurityEventHistory < ActiveRecord::Migration[7.0]
  def change
    add_column :account_security_risk_events,
               :intelligence_snapshot,
               :jsonb,
               null: false,
               default: {}

    create_table :account_security_risk_event_audits do |t|
      t.bigint :risk_event_id, null: false
      t.bigint :actor_user_id
      t.string :action, null: false, limit: 48
      t.string :from_status, limit: 20
      t.string :to_status, limit: 20
      t.jsonb :details, null: false, default: {}
      t.datetime :created_at, null: false
    end

    add_index :account_security_risk_event_audits,
              [:risk_event_id, :created_at, :id],
              name: "idx_as_event_audits_event_time"
    add_index :account_security_risk_event_audits,
              [:actor_user_id, :created_at],
              name: "idx_as_event_audits_actor_time"
  end
end
