# frozen_string_literal: true

module Jobs
  class AccountSecurityProcessAuthAbuseCluster < ::Jobs::Base
    def execute(args)
      return unless SiteSetting.account_security_enabled
      return unless SiteSetting.account_security_ip_reputation_enabled
      return unless SiteSetting.account_security_auth_abuse_detection_enabled

      ip = ::AccountSecurity::IpNormalizer.normalize_public(args[:ip] || args["ip"])
      return if ip.blank?

      family = (args[:family] || args["family"]).to_s
      return unless ::AccountSecurity::AuthenticationAbuseTracker::FAMILY_CONFIG.key?(family)

      context = {
        "abuse_family" => family,
        "failure_count" => positive_integer(args[:failure_count] || args["failure_count"]),
        "target_failure_count" => positive_integer(args[:target_failure_count] || args["target_failure_count"]),
        "distinct_targets" => positive_integer(args[:distinct_targets] || args["distinct_targets"]),
        "staff_targeted" => boolean_value(args[:staff_targeted] || args["staff_targeted"]),
        "threshold" => positive_integer(args[:threshold] || args["threshold"]),
        "single_account_threshold" => positive_integer(args[:single_account_threshold] || args["single_account_threshold"]),
        "window_minutes" => positive_integer(args[:window_minutes] || args["window_minutes"]),
        "threshold_exceeded" => true,
        "local_abuse_confirmed" => boolean_value(args[:escalation] || args["escalation"]),
      }.compact

      escalation = boolean_value(args[:escalation] || args["escalation"])
      trigger = family == "registration_rejected" ? "registration_abuse" : "auth_failure"
      result = ::AccountSecurity::AssessmentService.call(
        ip: ip,
        user: nil,
        trigger: trigger,
        force_remote: false,
        allow_remote: !escalation,
        event_context: context,
      )

      if result.event.nil?
        ::AccountSecurity::EventRecorder.record_local_cluster!(
          ip: ip,
          intelligence: result.intelligence,
          trigger: trigger,
          local_context: context,
        )
      end
      ::AccountSecurity::Statistics.increment!(auth_abuse_clusters: 1) unless escalation
    rescue StandardError => e
      Rails.logger.warn("[account_security] authentication-abuse cluster job failed class=#{e.class}")
    end

    private

    def positive_integer(value)
      number = Integer(value, exception: false)
      number&.positive? ? number : nil
    end

    def boolean_value(value)
      value == true || value.to_s == "true" || value.to_s == "1"
    end
  end
end
