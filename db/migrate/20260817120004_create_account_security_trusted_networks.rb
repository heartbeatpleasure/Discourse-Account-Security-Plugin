# frozen_string_literal: true
class CreateAccountSecurityTrustedNetworks < ActiveRecord::Migration[7.0]
  def change
    create_table :account_security_trusted_networks do |t|
      t.cidr :network, null: false
      t.string :label, null: false, limit: 120
      t.string :reason, null: false, limit: 240
      t.string :scope, null: false, limit: 32, default: "bypass_lookup_and_enforcement"
      t.bigint :created_by_id, null: false
      t.datetime :expires_at
      t.timestamps null: false
    end
    add_index :account_security_trusted_networks, :network, unique: true, name: "idx_as_trusted_network"
    add_index :account_security_trusted_networks, :expires_at, name: "idx_as_trusted_expiry"
  end
end
