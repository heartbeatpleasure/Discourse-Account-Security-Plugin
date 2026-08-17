# frozen_string_literal: true

class AddAccountSecurityAccountCorrelation < ActiveRecord::Migration[7.0]
  def change
    create_table :account_security_session_signatures do |t|
      t.bigint :user_id, null: false
      t.cidr :network_key, null: false
      t.string :signature_hash, null: false, limit: 64
      t.datetime :first_seen_at, null: false
      t.datetime :last_seen_at, null: false
      t.integer :observation_count, null: false, default: 1
      t.timestamps null: false
    end

    add_index :account_security_session_signatures,
              [:user_id, :network_key, :signature_hash],
              unique: true,
              name: "idx_as_session_sig_unique"
    add_index :account_security_session_signatures,
              [:network_key, :signature_hash],
              name: "idx_as_session_sig_network_hash"
    add_index :account_security_session_signatures,
              [:network_key, :last_seen_at],
              name: "idx_as_session_sig_network_seen"
    add_index :account_security_session_signatures,
              :last_seen_at,
              name: "idx_as_session_sig_seen"

    create_table :account_security_account_correlations do |t|
      t.bigint :user_a_id, null: false
      t.bigint :user_b_id, null: false
      t.integer :score, null: false, default: 0
      t.string :confidence, null: false, limit: 20, default: "weak"
      t.string :status, null: false, limit: 32, default: "open"
      t.jsonb :evidence, null: false, default: {}
      t.datetime :first_seen_at, null: false
      t.datetime :last_seen_at, null: false
      t.bigint :reviewed_by_id
      t.datetime :reviewed_at
      t.string :resolution_reason, limit: 240
      t.timestamps null: false
    end

    add_check_constraint :account_security_account_correlations,
                         "user_a_id < user_b_id",
                         name: "chk_as_correlation_user_order"
    add_index :account_security_account_correlations,
              [:user_a_id, :user_b_id],
              unique: true,
              name: "idx_as_correlation_pair"
    add_index :account_security_account_correlations,
              [:status, :score, :last_seen_at],
              name: "idx_as_correlation_queue"
    add_index :account_security_account_correlations,
              [:user_a_id, :last_seen_at],
              name: "idx_as_correlation_user_a"
    add_index :account_security_account_correlations,
              [:user_b_id, :last_seen_at],
              name: "idx_as_correlation_user_b"

    add_column :account_security_daily_stats, :correlation_candidates, :integer, null: false, default: 0
    add_column :account_security_daily_stats, :correlation_scans, :integer, null: false, default: 0
  end
end
