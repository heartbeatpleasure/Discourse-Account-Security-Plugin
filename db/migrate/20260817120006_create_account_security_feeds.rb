# frozen_string_literal: true
class CreateAccountSecurityFeeds < ActiveRecord::Migration[7.0]
  def change
    create_table :account_security_feed_entries do |t|
      t.string :source, null: false, limit: 32
      t.inet :ip_address, null: false
      t.integer :score
      t.string :generation, null: false, limit: 64
      t.timestamps null: false
    end
    add_index :account_security_feed_entries, [:source, :ip_address], unique: true, name: "idx_as_feed_source_ip"
    add_index :account_security_feed_entries, [:source, :generation], name: "idx_as_feed_generation"

    create_table :account_security_feed_snapshots do |t|
      t.string :source, null: false, limit: 32
      t.datetime :fetched_at
      t.string :checksum, limit: 128
      t.integer :entry_count, null: false, default: 0
      t.string :status, null: false, limit: 24, default: "never"
      t.string :error_code, limit: 64
      t.timestamps null: false
    end
    add_index :account_security_feed_snapshots, :source, unique: true, name: "idx_as_feed_snapshot_source"
  end
end
