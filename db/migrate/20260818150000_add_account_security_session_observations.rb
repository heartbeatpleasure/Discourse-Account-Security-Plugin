# frozen_string_literal: true

class AddAccountSecuritySessionObservations < ActiveRecord::Migration[7.0]
  def change
    create_table :account_security_session_observations do |t|
      t.bigint :user_id, null: false
      t.inet :ip_address, null: false
      t.string :browser_token_hash, limit: 64
      t.string :client_signature_hash, limit: 64
      t.datetime :observed_at, null: false
      t.timestamps null: false
    end

    add_index :account_security_session_observations,
              [:user_id, :observed_at],
              name: "idx_as_session_observation_user_seen"
    add_index :account_security_session_observations,
              [:ip_address, :observed_at],
              name: "idx_as_session_observation_ip_seen"
    add_index :account_security_session_observations,
              [:browser_token_hash, :observed_at],
              name: "idx_as_session_observation_browser_seen",
              where: "browser_token_hash IS NOT NULL"
    add_index :account_security_session_observations,
              [:client_signature_hash, :observed_at],
              name: "idx_as_session_observation_client_seen",
              where: "client_signature_hash IS NOT NULL"
  end
end
