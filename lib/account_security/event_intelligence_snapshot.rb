# frozen_string_literal: true

module ::AccountSecurity
  module EventIntelligenceSnapshot
    module_function

    VERSION = 1

    def capture(intelligence, captured_at: Time.zone.now, risk_level: nil, evidence_strength: nil)
      snapshot = {
        "version" => VERSION,
        "captured_at" => captured_at.iso8601,
        "provider_data_available" => provider_data_available?(intelligence),
        "risk_level" => (risk_level.presence || intelligence&.risk_level).to_s.presence,
        "evidence_strength" => (evidence_strength.presence || intelligence&.evidence_strength).to_s.presence,
      }.compact
      return snapshot unless intelligence

      snapshot.merge(
        "primary_score" => intelligence.primary_score,
        "total_reports" => intelligence.total_reports,
        "distinct_reporters" => intelligence.distinct_reporters,
        "last_reported_at" => intelligence.last_reported_at&.iso8601,
        "usage_type" => safe_text(intelligence.usage_type, 120),
        "isp" => safe_text(intelligence.isp, 160),
        "domain" => safe_text(intelligence.domain, 160),
        "country_code" => safe_text(intelligence.country_code, 2),
        "is_tor" => intelligence.is_tor == true,
        "local_blacklist_match" => intelligence.local_blacklist_match == true,
        "provider_checked_at" => intelligence.provider_checked_at&.iso8601,
      ).compact
    rescue StandardError => e
      Rails.logger.warn("[account_security] event intelligence snapshot failed class=#{e.class}")
      {
        "version" => VERSION,
        "captured_at" => captured_at.iso8601,
        "provider_data_available" => false,
        "risk_level" => risk_level.to_s.presence,
        "evidence_strength" => evidence_strength.to_s.presence,
      }.compact
    end

    def provider_data_available?(intelligence)
      return false unless intelligence

      summary = intelligence.source_summary.is_a?(Hash) ? intelligence.source_summary : {}
      intelligence.provider_checked_at.present? || summary["provider"].to_s == "abuseipdb"
    end

    def safe_text(value, max)
      value.to_s.gsub(/[[:cntrl:]]+/, " ").squish.byteslice(0, max).presence
    end
  end
end
