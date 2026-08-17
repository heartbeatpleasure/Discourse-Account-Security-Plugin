# frozen_string_literal: true
module Jobs
  class AccountSecurityCheckIp < ::Jobs::Base
    def execute(args)
      return unless SiteSetting.account_security_enabled && SiteSetting.account_security_ip_reputation_enabled
      ip = ::AccountSecurity::IpNormalizer.normalize_public(args[:ip])
      return if ip.blank?
      user = User.find_by(id: args[:user_id]) if args[:user_id]
      trigger = args[:trigger].to_s
      return unless %w[registration login staff_login].include?(trigger)
      ::AccountSecurity::AssessmentService.call(ip: ip, user: user, trigger: trigger)
    end
  end
end
