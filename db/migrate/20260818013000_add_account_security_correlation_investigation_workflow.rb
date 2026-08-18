# frozen_string_literal: true

class AddAccountSecurityCorrelationInvestigationWorkflow < ActiveRecord::Migration[7.0]
  def change
    add_column :account_security_account_correlations, :primary_user_id, :bigint
    add_column :account_security_account_correlations, :notified_at, :datetime
    add_column :account_security_account_correlations, :notified_score, :integer
    add_column :account_security_account_correlations, :notified_confidence, :string, limit: 20
    add_column :account_security_account_correlations, :notified_public_ip_count, :integer

    add_index :account_security_account_correlations,
              :primary_user_id,
              name: "idx_as_correlation_primary_user"

    create_table :account_security_correlation_reviews do |t|
      t.bigint :account_correlation_id, null: false
      t.bigint :actor_user_id
      t.string :action, null: false, limit: 32
      t.string :from_status, limit: 32
      t.string :to_status, limit: 32
      t.text :note
      t.bigint :primary_user_id
      t.timestamps null: false
    end

    add_index :account_security_correlation_reviews,
              [:account_correlation_id, :created_at],
              name: "idx_as_correlation_reviews_timeline"
    add_index :account_security_correlation_reviews,
              :actor_user_id,
              name: "idx_as_correlation_reviews_actor"
    add_index :account_security_correlation_reviews,
              :primary_user_id,
              name: "idx_as_correlation_reviews_primary_user"
  end
end
