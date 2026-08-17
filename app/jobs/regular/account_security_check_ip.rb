# frozen_string_literal: true

module Jobs
  class AccountSecurityCheckIp < ::Jobs::Base
    def execute(args)
      return unless SiteSetting.account_security_enabled

      normalized_ip = ::AccountSecurity::IpNormalizer.normalize(args[:ip] || args["ip"])
      return if normalized_ip.blank?
      public_ip = ::AccountSecurity::IpNormalizer.normalize_public(normalized_ip)

      user_id = args[:user_id] || args["user_id"]
      user = User.find_by(id: user_id) if user_id
      trigger = (args[:trigger] || args["trigger"]).to_s
      return unless %w[registration login staff_login].include?(trigger)

      correlation_enabled =
        SiteSetting.account_security_account_correlation_enabled && user.present? && user.human?
      assessment_enabled = public_ip.present? && assessment_enabled_for?(trigger)
      return unless correlation_enabled || assessment_enabled

      familiarity = nil
      signature = nil
      if correlation_enabled && public_ip.present?
        familiarity = ::AccountSecurity::NetworkFamiliarity.observe!(
          user: user,
          ip: public_ip,
          registration: trigger == "registration",
        )
        signature = ::AccountSecurity::SessionSignatureRecorder.record_from_token!(
          user: user,
          token_id: args[:auth_token_id] || args["auth_token_id"],
          ip: public_ip,
        )
      end

      if correlation_enabled
        ::AccountSecurity::AccountCorrelationService.observe!(
          user: user,
          ip: normalized_ip,
          trigger: trigger,
          network: familiarity&.dig(:network),
          session_signature: signature,
        )
      end

      return unless assessment_enabled

      ::AccountSecurity::AssessmentService.call(
        ip: public_ip,
        user: user,
        trigger: trigger,
        familiarity: familiarity,
      )
    end

    private

    def assessment_enabled_for?(trigger)
      return false unless SiteSetting.account_security_ip_reputation_enabled

      case trigger
      when "registration"
        SiteSetting.account_security_registration_checks_enabled
      when "login", "staff_login"
        SiteSetting.account_security_login_checks_enabled
      else
        false
      end
    end
  end
end
