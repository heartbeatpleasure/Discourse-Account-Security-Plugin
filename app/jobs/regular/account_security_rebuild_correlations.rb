# frozen_string_literal: true

module Jobs
  class AccountSecurityRebuildCorrelations < ::Jobs::Base
    def execute(args)
      ::AccountSecurity::AccountCorrelationScanner.run!(
        requested_by_id: args[:requested_by_id] || args["requested_by_id"],
      )
    end
  end
end
