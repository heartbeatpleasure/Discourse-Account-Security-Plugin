# frozen_string_literal: true

module Jobs
  class AccountSecurityRecordSessionObservation < ::Jobs::Base
    def execute(args)
      ::AccountSecurity::SessionObservationRecorder.record!(
        user_id: args[:user_id],
        ip: args[:ip],
        browser_token_hash: args[:browser_token_hash],
        client_signature_hash: args[:client_signature_hash],
        observed_at: args[:observed_at],
      )
    end
  end
end
