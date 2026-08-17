# frozen_string_literal: true

require "digest"

module ::AccountSecurity
  module EventRecorder
    module_function

    INCIDENT_WINDOW = 30.minutes
    LOCAL_CONTEXT_KEYS = %w[
      abuse_family
      failure_count
      target_failure_count
      distinct_targets
      staff_targeted
      threshold
      single_account_threshold
      window_minutes
      threshold_exceeded
      local_abuse_confirmed
    ].freeze

    def record!(user:, ip:, intelligence:, trigger:, new_network:, familiarity_network:, local_context: {})
      staff = user&.staff? == true
      return nil unless RiskPolicy.event_required?(
        trigger: trigger,
        risk_level: intelligence.risk_level,
        new_network: new_network,
        staff: staff,
      )

      context = event_context(
        intelligence: intelligence,
        new_network: new_network,
        staff: staff,
        familiarity_network: familiarity_network,
      ).merge(sanitize_local_context(local_context))

      record_internal!(
        user: user,
        ip: ip,
        intelligence: intelligence,
        trigger: trigger,
        context: context,
        risk_level: intelligence.risk_level,
        evidence_strength: event_evidence_strength(intelligence, trigger, context),
        new_network: new_network,
        staff: staff,
      )
    end

    def record_local_cluster!(ip:, intelligence:, trigger:, local_context: {})
      return nil unless trigger.to_s.in?(%w[auth_failure registration_abuse])

      context = sanitize_local_context(local_context)
      if intelligence
        context = event_context(
          intelligence: intelligence,
          new_network: true,
          staff: false,
          familiarity_network: nil,
        ).merge(context)
      end

      risk_level = intelligence&.risk_level.presence || "low"
      evidence = event_evidence_strength(intelligence, trigger, context)
      record_internal!(
        user: nil,
        ip: ip,
        intelligence: intelligence,
        trigger: trigger,
        context: context,
        risk_level: risk_level,
        evidence_strength: evidence,
        new_network: true,
        staff: false,
      )
    end

    def event_type_for(trigger, new_network, staff)
      return "registration" if trigger == "registration"
      return "auth_failure_cluster" if trigger == "auth_failure"
      return "registration_abuse_cluster" if trigger == "registration_abuse"
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

    def event_evidence_strength(intelligence, trigger, context)
      current = intelligence&.evidence_strength.presence || "weak"
      return current unless trigger.to_s.in?(%w[auth_failure registration_abuse])
      return current unless context["threshold_exceeded"] == true

      risk = intelligence&.risk_level.to_s
      return "corroborated" if risk.in?(%w[high critical])

      stronger_evidence(current, "strong")
    end

    def sanitize_local_context(value)
      source = value.is_a?(Hash) ? value : {}
      source.each_with_object({}) do |(key, raw), safe|
        name = key.to_s
        next unless LOCAL_CONTEXT_KEYS.include?(name)

        case name
        when "abuse_family"
          token = raw.to_s
          safe[name] = token if AuthenticationAbuseTracker::FAMILY_CONFIG.key?(token)
        when "staff_targeted", "threshold_exceeded", "local_abuse_confirmed"
          safe[name] = raw == true
        else
          number = Integer(raw, exception: false)
          safe[name] = number if number && number >= 0
        end
      end
    end

    def record_internal!(user:, ip:, intelligence:, trigger:, context:, risk_level:, evidence_strength:, new_network:, staff:)
      event_type = event_type_for(trigger, new_network, staff)
      incident_key = Digest::SHA256.hexdigest([user&.id || 0, ip, event_type, risk_level].join("|"))[0, 64]

      event = DistributedMutex.synchronize("account-security-event-#{incident_key}", validity: 10) do
        now = Time.zone.now
        existing =
          RiskEvent
            .where(incident_key: incident_key, status: %w[open acknowledged monitor])
            .where("last_seen_at >= ?", INCIDENT_WINDOW.ago)
            .order(id: :desc)
            .first

        if existing
          existing_context = existing.context.is_a?(Hash) ? existing.context : {}
          escalation_update =
            event_type.in?(%w[auth_failure_cluster registration_abuse_cluster]) &&
              context["local_abuse_confirmed"] == true &&
              existing_context["local_abuse_confirmed"] != true
          existing.update!(
            occurrence_count: existing.occurrence_count.to_i + (escalation_update ? 0 : 1),
            last_seen_at: now,
            evidence_strength: stronger_evidence(existing.evidence_strength, evidence_strength),
            ip_intelligence_id: intelligence&.id || existing.ip_intelligence_id,
            context: existing_context.merge(context),
          )
          existing
        else
          created = RiskEvent.create!(
            user_id: user&.id,
            ip_address: ip,
            event_type: event_type,
            severity: severity_for(risk_level),
            risk_level: risk_level,
            evidence_strength: evidence_strength,
            ip_intelligence_id: intelligence&.id,
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

      if event
        UserNoteWriter.record!(event: event, automatic: true)
        IncidentNotifier.notify_if_needed!(event)
      end
      event
    end
  end
end
