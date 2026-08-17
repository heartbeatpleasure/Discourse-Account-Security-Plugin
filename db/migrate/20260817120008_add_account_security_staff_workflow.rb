# frozen_string_literal: true

class AddAccountSecurityStaffWorkflow < ActiveRecord::Migration[7.0]
  def up
    add_column :account_security_risk_events, :occurrence_count, :integer, null: false, default: 1
    add_column :account_security_risk_events, :last_seen_at, :datetime
    add_column :account_security_risk_events, :user_note_created_at, :datetime

    execute <<~SQL
      UPDATE account_security_risk_events
      SET last_seen_at = created_at
      WHERE last_seen_at IS NULL
    SQL
    change_column_null :account_security_risk_events, :last_seen_at, false
    add_index :account_security_risk_events, [:status, :last_seen_at], name: "idx_as_events_status_last_seen"

    create_table :account_security_temporary_ip_blocks do |t|
      t.bigint :risk_event_id, null: false
      t.bigint :screened_ip_address_id, null: false
      t.inet :ip_address, null: false
      t.bigint :created_by_id
      t.datetime :expires_at, null: false
      t.datetime :released_at
      t.string :release_reason, limit: 64
      t.timestamps null: false
    end

    add_index :account_security_temporary_ip_blocks,
              :screened_ip_address_id,
              unique: true,
              name: "idx_as_temp_block_screened_unique"
    add_index :account_security_temporary_ip_blocks,
              [:risk_event_id, :released_at],
              name: "idx_as_temp_block_event_state"
    add_index :account_security_temporary_ip_blocks,
              :expires_at,
              where: "released_at IS NULL",
              name: "idx_as_temp_block_active_expiry"
  end

  def down
    drop_table :account_security_temporary_ip_blocks
    remove_index :account_security_risk_events, name: "idx_as_events_status_last_seen"
    remove_column :account_security_risk_events, :user_note_created_at
    remove_column :account_security_risk_events, :last_seen_at
    remove_column :account_security_risk_events, :occurrence_count
  end
end
