# frozen_string_literal: true
module ::AccountSecurity
  module AbuseReporter
    module_function

    REPORTABLE_EVENT_TYPES = %w[auth_failure_cluster].freeze
    REPORTABLE_SEVERITIES = %w[high critical].freeze

    def report_event!(event_id:, actor:)
      raise Discourse::InvalidAccess unless actor&.admin?
      raise Discourse::InvalidAccess unless SiteSetting.account_security_enabled
      raise Discourse::InvalidAccess unless SiteSetting.account_security_ip_reputation_enabled
      raise Discourse::InvalidAccess unless SiteSetting.account_security_abuse_reporting_enabled
      raise Discourse::InvalidAccess if SiteSetting.account_security_abuseipdb_api_key.blank?

      id = Integer(event_id, exception: false)
      raise Discourse::InvalidParameters.new(:event_id) unless id&.positive?

      event = RiskEvent.find_by(id: id)
      raise Discourse::InvalidParameters.new(:event_id) unless reportable_event?(event)

      normalized = IpNormalizer.normalize_public(event.ip_address)
      raise Discourse::InvalidParameters.new(:event_id) if normalized.blank?

      mutex_key = "account-security-provider-report-event-#{event.id}"
      DistributedMutex.synchronize(mutex_key, validity: 20) do
        recent_other_report =
          ProviderReport
            .where(ip_address: normalized, provider: "abuseipdb", status: %w[pending reported])
            .where("created_at >= ?", 15.minutes.ago)
            .where.not(risk_event_id: event.id)
            .exists?
        raise Discourse::InvalidParameters.new(:event_id) if recent_other_report

        record = ProviderReport.find_or_initialize_by(risk_event_id: event.id)
        raise Discourse::InvalidParameters.new(:event_id) if record.persisted? && record.status == "reported"

        record.assign_attributes(
          ip_address: normalized,
          provider: "abuseipdb",
          category: "brute_force",
          reported_by_id: actor.id,
          status: "pending",
          provider_status: nil,
          reported_at: nil,
        )
        record.save!

        result = Providers::AbuseIpDb.new.report_bruteforce(normalized, observed_at: event.created_at)
        record.update!(
          status: result.success ? "reported" : "failed",
          provider_status: result.status,
          reported_at: result.success ? Time.zone.now : nil,
        )
        RiskEventAuditTrail.record!(
          event: event,
          action: result.success ? "abuse_reported" : "abuse_report_attempted",
          actor: actor,
          details: {
            provider_report_id: record.id,
            provider_status: result.status.to_i,
            result: result.success ? "reported" : "failed",
          },
        )

        {
          success: result.success,
          status: result.status,
          error_code: result.error_code&.to_s,
          report_id: record.id,
          risk_event_id: event.id,
        }
      end
    rescue ActiveRecord::RecordInvalid, ActiveRecord::RecordNotUnique
      raise Discourse::InvalidParameters.new(:event_id)
    end

    def reportable_event?(event)
      return false unless event
      return false unless REPORTABLE_EVENT_TYPES.include?(event.event_type)
      return false unless REPORTABLE_SEVERITIES.include?(event.severity)
      return false unless event.evidence_strength == "corroborated"
      return false if event.status.in?(%w[benign auto_resolved])

      context = event.context.is_a?(Hash) ? event.context : {}
      context["local_abuse_confirmed"] == true && context["threshold_exceeded"] == true
    end
  end
end
