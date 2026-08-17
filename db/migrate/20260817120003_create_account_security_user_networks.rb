# frozen_string_literal: true
class CreateAccountSecurityUserNetworks < ActiveRecord::Migration[7.0]
  def change
    create_table :account_security_user_networks do |t|
      t.bigint :user_id, null: false
      t.string :address_family, null: false, limit: 8
      t.cidr :network_key, null: false
      t.datetime :first_seen_at, null: false
      t.datetime :last_seen_at, null: false
      t.integer :successful_login_count, null: false, default: 0
      t.boolean :registration_origin, null: false, default: false
      t.timestamps null: false
    end
    add_index :account_security_user_networks, [:user_id, :network_key], unique: true, name: "idx_as_user_network_unique"
    add_index :account_security_user_networks, :last_seen_at, name: "idx_as_user_network_seen"
  end
end
