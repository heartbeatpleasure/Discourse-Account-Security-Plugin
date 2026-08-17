# frozen_string_literal: true

module Jobs
  class AccountSecurityRecordBrowserContinuity < ::Jobs::Base
    def execute(args)
      ::AccountSecurity::BrowserContinuityRecorder.record!(
        user_id: args[:user_id] || args["user_id"],
        token_hash: args[:token_hash] || args["token_hash"],
      )
    end
  end
end
