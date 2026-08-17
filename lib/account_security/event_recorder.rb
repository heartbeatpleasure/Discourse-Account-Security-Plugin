# frozen_string_literal: true
require "digest"

module ::AccountSecurity
  module EventRecorder
    module_function

    def record!(user:, ip:, intelligence:, trigger:, new_network:, familiarity_network:)
      staff = user&.staff? == true
      return nil unless RiskPolicy.event_required?(
        trigger: trigger,
        risk_level: intelligence.risk_level,
        new_network: new_network,
        staff: staff,
      )

      event_type = event_type_for(trigger, new_network, staff)
      incident_key = Digest::SHA256.hexdigest([user&.id || 0, ip, event_type, intelligence.risk_level].join("|"))[0, 64]
      existing = RiskEvent.where(incident_key: incident_key, status: %w[open acknowledged monitor])
                          .where("created_at >= ?", 30.minutes.ago).order(id: :desc).first
      return existing if existing

      context = {
        "new_network" => new_network == true,
        "staff" => staff,
        "familiarity_network" => familiarity_network,
        "is_tor" => intelligence.is_tor == true,
        "local_blacklist_match" => intelligence.local_blacklist_match == true,
        "usage_type" => intelligence.usage_type.to_s.first(120).presence,
      }.compact

      event = RiskEvent.create!(
        user_id: user&.id,
        ip_address: ip,
        event_type: event_type,
        severity: severity_for(intelligence.risk_level),
        risk_level: intelligence.risk_level,
        evidence_strength: intelligence.evidence_strength,
        ip_intelligence_id: intelligence.id,
        context: context,
        incident_key: incident_key,
        status: "open",
      )
      Statistics.increment!(events_created: 1)
      event
    end

    def event_type_for(trigger, new_network, staff)
      return "registration" if trigger == "registration"
      return "staff_login_new_network" if staff && new_network
      new_network ? "login_new_network" : "login_familiar"
    end

    def severity_for(risk_level)
      %w[elevated high critical].include?(risk_level.to_s) ? risk_level.to_s : "elevated"
    end
  end
end
