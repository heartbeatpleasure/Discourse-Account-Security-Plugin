# frozen_string_literal: true

require "digest"

module ::AccountSecurity
  module EventRecorder
    module_function

    INCIDENT_WINDOW = 30.minutes
    RISK_RANK = %w[low observed elevated high critical].each_with_index.to_h.freeze
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

      risk_level =
        intelligence&.risk_level.presence ||
          (context["local_abuse_confirmed"] == true ? "high" : "elevated")
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

    def stronger_risk(current, candidate)
      current_value = current.to_s.presence || "low"
      candidate_value = candidate.to_s.presence || "low"
      candidate_rank = RISK_RANK.fetch(candidate_value, 0)
      current_rank = RISK_RANK.fetch(current_value, 0)
      candidate_rank > current_rank ? candidate_value : current_value
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
      # Risk level deliberately is not part of the incident identity. The same
      # user/network/event can therefore escalate from elevated to high or
      # critical without being split into a second incident.
      incident_key = Digest::SHA256.hexdigest([user&.id || 0, ip, event_type].join("|"))[0, 64]
      audit = nil

      event = DistributedMutex.synchronize("account-security-event-#{incident_key}", validity: 10) do
        now = Time.zone.now
        existing = matching_open_incident(
          incident_key: incident_key,
          user_id: user&.id,
          ip: ip,
          event_type: event_type,
        )

        if existing
          existing_context = existing.context.is_a?(Hash) ? existing.context : {}
          escalation_update =
            event_type.in?(%w[auth_failure_cluster registration_abuse_cluster]) &&
              context["local_abuse_confirmed"] == true &&
              existing_context["local_abuse_confirmed"] != true

          previous_risk = existing.risk_level.to_s
          previous_severity = existing.severity.to_s
          previous_evidence = existing.evidence_strength.to_s
          next_risk = stronger_risk(previous_risk, risk_level)
          next_evidence = stronger_evidence(previous_evidence, evidence_strength)
          next_severity = severity_for(next_risk)

          existing.update!(
            incident_key: incident_key,
            occurrence_count: existing.occurrence_count.to_i + (escalation_update ? 0 : 1),
            last_seen_at: now,
            risk_level: next_risk,
            severity: next_severity,
            evidence_strength: next_evidence,
            ip_intelligence_id: intelligence&.id || existing.ip_intelligence_id,
            context: existing_context.merge(context),
          )

          if previous_risk != next_risk || previous_severity != next_severity || previous_evidence != next_evidence
            audit = {
              action: "incident_escalated",
              details: {
                risk_level_from: previous_risk,
                risk_level_to: next_risk,
                severity_from: previous_severity,
                severity_to: next_severity,
                evidence_from: previous_evidence,
                evidence_to: next_evidence,
              },
            }
          end
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
            intelligence_snapshot: EventIntelligenceSnapshot.capture(
              intelligence,
              captured_at: now,
              risk_level: risk_level,
              evidence_strength: evidence_strength,
            ),
            context: context,
            incident_key: incident_key,
            status: "open",
            occurrence_count: 1,
            last_seen_at: now,
          )
          Statistics.increment!(events_created: 1)
          audit = {
            action: "event_created",
            details: {
              risk_level_to: created.risk_level,
              severity_to: created.severity,
              evidence_to: created.evidence_strength,
            },
          }
          created
        end
      end

      if event
        RiskEventAuditTrail.record!(event: event, **audit) if audit
        UserNoteWriter.record!(event: event, automatic: true)
        IncidentNotifier.notify_if_needed!(event)
      end
      event
    end

    def matching_open_incident(incident_key:, user_id:, ip:, event_type:)
      scope =
        RiskEvent
          .where(status: %w[open acknowledged monitor])
          .where("last_seen_at >= ?", INCIDENT_WINDOW.ago)

      current = scope.where(incident_key: incident_key).order(id: :desc).first
      return current if current

      # Compatibility with pre-v0.21 incident keys, which included risk_level.
      scope
        .where(user_id: user_id, ip_address: ip, event_type: event_type)
        .order(last_seen_at: :desc, id: :desc)
        .first
    end
  end
end
