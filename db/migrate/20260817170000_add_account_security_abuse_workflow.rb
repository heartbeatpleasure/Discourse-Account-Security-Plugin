# frozen_string_literal: true

class AddAccountSecurityAbuseWorkflow < ActiveRecord::Migration[7.0]
  def change
    add_column :account_security_risk_events, :notified_at, :datetime
    add_column :account_security_risk_events, :notification_kind, :string, limit: 48
    add_index :account_security_risk_events, :notified_at, name: "idx_as_events_notified_at"

    add_column :account_security_daily_stats, :auth_abuse_clusters, :integer, null: false, default: 0
    add_column :account_security_daily_stats, :notifications_sent, :integer, null: false, default: 0

    create_table :account_security_notification_suppressions do |t|
      t.bigint :user_id, null: false
      t.string :network_key, null: false, limit: 128
      t.bigint :created_by_id
      t.datetime :expires_at, null: false
      t.timestamps null: false
    end

    add_index :account_security_notification_suppressions,
              [:user_id, :network_key],
              unique: true,
              name: "idx_as_notification_suppressions_user_network"
    add_index :account_security_notification_suppressions,
              :expires_at,
              name: "idx_as_notification_suppressions_expiry"
  end
end
