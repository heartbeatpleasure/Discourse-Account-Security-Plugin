# frozen_string_literal: true
module Jobs
  class AccountSecuritySyncTorExitList < ::Jobs::Scheduled
    every 1.hour
    def execute(_args)
      return unless SiteSetting.account_security_enabled && SiteSetting.account_security_ip_reputation_enabled && SiteSetting.account_security_tor_feed_enabled
      ::AccountSecurity::Feeds::TorExitList.sync!
    end
  end
end
