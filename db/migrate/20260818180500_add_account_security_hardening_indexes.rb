# frozen_string_literal: true

class AddAccountSecurityHardeningIndexes < ActiveRecord::Migration[7.0]
  def change
    add_index :account_security_session_observations,
              :observed_at,
              name: "idx_as_session_observation_seen"

    add_index :account_security_account_correlations,
              [:confidence, :score, :last_seen_at],
              name: "idx_as_correlation_confidence_score"

    add_index :account_security_risk_events,
              [:user_id, :last_seen_at],
              name: "idx_as_events_user_last_seen"

    add_index :account_security_risk_events,
              [:severity, :status, :last_seen_at],
              name: "idx_as_events_severity_status_seen"
  end
end
