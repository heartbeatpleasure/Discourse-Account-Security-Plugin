# frozen_string_literal: true
module Jobs
  class AccountSecuritySyncAbuseipdbBlacklist < ::Jobs::Scheduled
    every 6.hours
    def execute(_args)
      return unless SiteSetting.account_security_enabled && SiteSetting.account_security_ip_reputation_enabled && SiteSetting.account_security_blacklist_sync_enabled
      ::AccountSecurity::Feeds::AbuseIpDbBlacklist.sync!
    end
  end
end
