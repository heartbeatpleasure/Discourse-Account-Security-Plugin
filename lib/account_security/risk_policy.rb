# frozen_string_literal: true
module ::AccountSecurity
  module RiskPolicy
    module_function

    def risk_level(score)
      value = score.to_i.clamp(0, 100)
      case value
      when 0..24 then "low"
      when 25..49 then "observed"
      when 50..74 then "elevated"
      when 75..89 then "high"
      else "critical"
      end
    end

    def evidence_strength(score:, last_reported_at:, distinct_reporters:, local_blacklist_match: false, local_abuse: false)
      return "corroborated" if local_abuse && score.to_i >= 75
      return "strong" if local_blacklist_match

      age_days = last_reported_at ? ((Time.zone.now - last_reported_at) / 1.day).floor : nil
      reporters = distinct_reporters.to_i
      if score.to_i >= 75 && age_days && age_days <= 7 && reporters >= 3
        "strong"
      elsif score.to_i >= 50 && age_days && age_days <= 21 && reporters >= 2
        "moderate"
      else
        "weak"
      end
    end

    def event_required?(trigger:, risk_level:, new_network:, staff:)
      rank = ::AccountSecurity::IpIntelligence::RISK_LEVELS.index(risk_level.to_s) || 0
      return rank >= 2 if trigger == "registration"
      return rank >= 2 if staff && new_network
      return rank >= 3 if trigger.in?(%w[login staff_login]) && new_network
      false
    end
  end
end
