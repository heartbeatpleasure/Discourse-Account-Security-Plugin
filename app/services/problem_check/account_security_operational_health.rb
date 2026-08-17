# frozen_string_literal: true

class ProblemCheck::AccountSecurityOperationalHealth < ProblemCheck
  self.priority = "high"
  self.perform_every = 15.minutes
  self.max_retries = 0
  self.max_blips = 1

  def call
    return no_problem unless SiteSetting.account_security_enabled

    payload = ::AccountSecurity::Health.payload
    status = payload[:overall].to_s
    return no_problem if %w[healthy disabled local_only initializing].include?(status)

    reason = human_reason(payload[:overall_reason].to_s, status)
    problem(
      override_data: {
        status: ERB::Util.html_escape(status.humanize),
        reason: ERB::Util.html_escape(reason),
      },
      details: { status: status, reason: payload[:overall_reason].to_s },
    )
  rescue StandardError => e
    Rails.logger.warn("[account_security] problem check failed class=#{e.class}")
    no_problem
  end

  private

  def human_reason(reason, status)
    {
      "api_key_missing" => "Provider API key is missing",
      "circuit_open" => "Provider circuit breaker is open",
      "invalid_credentials" => "Provider credentials were rejected",
      "quota_exhausted" => "Provider quota is exhausted",
      "tor_never_synced" => "Tor exit feed has not synchronized yet",
      "tor_error" => "Tor exit feed reported an error",
      "tor_stale" => "Tor exit feed is stale",
      "abuseipdb_blacklist_never_synced" => "AbuseIPDB blacklist has not synchronized yet",
      "abuseipdb_blacklist_error" => "AbuseIPDB blacklist reported an error",
      "abuseipdb_blacklist_stale" => "AbuseIPDB blacklist is stale",
      "notification_groups_missing" => "Staff notifications are enabled without a recipient group",
    }[reason] || (status == "degraded" ? "A local intelligence feed requires attention" : "Operational health requires attention")
  end
end
