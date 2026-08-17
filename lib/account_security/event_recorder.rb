# frozen_string_literal: true

require "digest"

module ::AccountSecurity
  module EventRecorder
    module_function

    INCIDENT_WINDOW = 30.minutes

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
      context = event_context(
        intelligence: intelligence,
        new_network: new_network,
        staff: staff,
        familiarity_network: familiarity_network,
      )

      event = DistributedMutex.synchronize("account-security-event-#{incident_key}", validity: 10) do
        now = Time.zone.now
        existing = RiskEvent.where(incident_key: incident_key, status: %w[open acknowledged monitor])
                            .where("last_seen_at >= ?", INCIDENT_WINDOW.ago)
                            .order(id: :desc)
                            .first

        if existing
          existing.update!(
            occurrence_count: existing.occurrence_count.to_i + 1,
            last_seen_at: now,
            evidence_strength: stronger_evidence(existing.evidence_strength, intelligence.evidence_strength),
            ip_intelligence_id: intelligence.id,
            context: (existing.context || {}).merge(context),
          )
          existing
        else
          created = RiskEvent.create!(
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
            occurrence_count: 1,
            last_seen_at: now,
          )
          Statistics.increment!(events_created: 1)
          created
        end
      end

      UserNoteWriter.record!(event: event, automatic: true) if event
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

    def event_context(intelligence:, new_network:, staff:, familiarity_network:)
      {
        "new_network" => new_network == true,
        "staff" => staff,
        "familiarity_network" => familiarity_network,
        "is_tor" => intelligence.is_tor == true,
        "local_blacklist_match" => intelligence.local_blacklist_match == true,
        "usage_type" => intelligence.usage_type.to_s.first(120).presence,
      }.compact
    end

    def stronger_evidence(current, candidate)
      levels = IpIntelligence::EVIDENCE_LEVELS
      current_rank = levels.index(current.to_s) || 0
      candidate_rank = levels.index(candidate.to_s) || 0
      candidate_rank > current_rank ? candidate.to_s : current.to_s
    end
  end
end
