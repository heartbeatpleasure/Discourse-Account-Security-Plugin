# frozen_string_literal: true

module ::AccountSecurity
  module AccountCorrelationPolicy
    module_function

    def score(evidence)
      data = evidence.is_a?(Hash) ? evidence : {}
      score = 0

      score += 45 if truthy?(data["shared_registration_ip"])
      score += 15 if truthy?(data["same_current_ip"])

      shared_networks = nonnegative_integer(data["shared_network_count"])
      score += if shared_networks >= 3
                 60
               elsif shared_networks == 2
                 40
               elsif shared_networks == 1
                 10
               else
                 0
               end

      signatures = nonnegative_integer(data["shared_session_signature_count"])
      score += signatures >= 2 ? 35 : 25 if signatures.positive?

      if data.key?("registration_delta_minutes")
        registration_delta = nonnegative_integer(data["registration_delta_minutes"])
        if registration_delta <= 60
          score += 20
        elsif registration_delta <= 1_440
          score += 15
        elsif registration_delta <= 10_080
          score += 8
        end
      end

      score += 10 if truthy?(data["shared_registration_ip"]) && signatures.positive?
      score += 10 if shared_networks >= 2 && signatures.positive?

      popularity = nonnegative_integer(data["max_shared_network_users"])
      score -= if popularity >= 20
                 30
               elsif popularity >= 10
                 20
               elsif popularity >= 5
                 10
               else
                 0
               end

      score.clamp(0, 100)
    end

    def confidence(score)
      value = score.to_i
      return "very_strong" if value >= 80
      return "strong" if value >= 60
      return "moderate" if value >= 40
      "weak"
    end

    def candidate?(score)
      score.to_i >= SiteSetting.account_security_correlation_min_score.to_i.clamp(30, 90)
    end

    def truthy?(value)
      value == true
    end

    def nonnegative_integer(value)
      number = Integer(value, exception: false)
      number && number >= 0 ? number : 0
    end
  end
end
