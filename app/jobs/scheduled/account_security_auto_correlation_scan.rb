# frozen_string_literal: true

module Jobs
  class AccountSecurityAutoCorrelationScan < ::Jobs::Scheduled
    every 15.minutes

    def execute(_args)
      ::AccountSecurity::AccountCorrelationScheduler.run_if_due!
    end
  end
end
