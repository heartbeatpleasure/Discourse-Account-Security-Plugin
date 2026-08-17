# frozen_string_literal: true
class ProblemCheck::AccountSecurityOperationalHealth < ProblemCheck
  self.priority = "high"
  self.perform_every = 15.minutes
  self.max_retries = 0
  self.max_blips = 1

  def call
    return no_problem unless SiteSetting.account_security_enabled
    status = ::AccountSecurity::Health.payload[:overall].to_s
    return no_problem if %w[healthy disabled local_only initializing].include?(status)
    problem(
      override_data: { status: ERB::Util.html_escape(status.humanize), reason: ERB::Util.html_escape(reason_for(status)) },
      details: { status: status, reason: reason_for(status) },
    )
  rescue StandardError => e
    Rails.logger.warn("[account_security] problem check failed class=#{e.class}")
    no_problem
  end

  private
  def reason_for(status)
    {
      "misconfigured" => "Provider configuration is incomplete",
      "circuit_open" => "Provider circuit breaker is open",
      "invalid_credentials" => "Provider credentials were rejected",
      "quota_exhausted" => "Provider quota is exhausted",
      "degraded" => "A provider or local intelligence feed is stale",
    }[status] || "Operational health requires attention"
  end
end
