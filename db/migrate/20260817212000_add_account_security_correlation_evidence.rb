# frozen_string_literal: true

class AddAccountSecurityCorrelationEvidence < ActiveRecord::Migration[7.0]
  def change
    create_table :account_security_browser_continuities do |t|
      t.bigint :user_id, null: false
      t.string :token_hash, null: false, limit: 64
      t.datetime :first_seen_at, null: false
      t.datetime :last_seen_at, null: false
      t.integer :observation_count, null: false, default: 1
      t.timestamps null: false
    end

    add_index :account_security_browser_continuities,
              [:user_id, :token_hash],
              unique: true,
              name: "idx_as_browser_continuity_unique"
    add_index :account_security_browser_continuities,
              [:token_hash, :last_seen_at],
              name: "idx_as_browser_continuity_hash_seen"
    add_index :account_security_browser_continuities,
              [:user_id, :last_seen_at],
              name: "idx_as_browser_continuity_user_seen"
  end
end
