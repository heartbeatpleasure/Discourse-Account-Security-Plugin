# frozen_string_literal: true

module Jobs
  class AccountSecurityExpireTemporaryIpBlocks < ::Jobs::Scheduled
    every 15.minutes

    def execute(_args)
      ::AccountSecurity::TemporaryIpBlockManager.expire_due!
    end
  end
end
