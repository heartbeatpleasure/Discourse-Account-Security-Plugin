# frozen_string_literal: true

module ::AccountSecurity
  module AccountCorrelationPolicy
    module_function

    def score(evidence)
      score_with_breakdown(evidence)[:score]
    end

    def score_with_breakdown(evidence)
      data = evidence.is_a?(Hash) ? evidence : {}
      breakdown = []
      total = 0

      public_exact = nonnegative_integer(data["untrusted_public_ip_count"])
      public_points =
        case public_exact
        when 0 then 0
        when 1 then 28
        when 2 then 48
        when 3 then 62
        else 72
        end
      if public_points.positive?
        total += add_breakdown!(breakdown, "shared_public_exact_ips", public_points, public_exact)
      end

      nonpublic_exact = nonnegative_integer(data["shared_nonpublic_ip_count"])
      nonpublic_points =
        case nonpublic_exact
        when 0 then 0
        when 1 then 14
        when 2 then 24
        when 3 then 32
        else 38
        end
      if nonpublic_points.positive?
        total += add_breakdown!(breakdown, "shared_nonpublic_ips", nonpublic_points, nonpublic_exact)
      end

      if truthy?(data["shared_registration_ip_public"])
        total += add_breakdown!(breakdown, "shared_registration_ip", 20, 1)
      elsif truthy?(data["shared_registration_ip_nonpublic"])
        total += add_breakdown!(breakdown, "shared_nonpublic_registration_ip", 18, 1)
      end

      if truthy?(data["same_current_ip_public"])
        total += add_breakdown!(breakdown, "same_current_ip", 8, 1)
      elsif truthy?(data["same_current_ip_nonpublic"])
        total += add_breakdown!(breakdown, "same_nonpublic_current_ip", 4, 1)
      end

      core_history_count = nonnegative_integer(data["shared_core_history_ip_count"])
      core_history_points = [core_history_count * 5, 15].min
      if core_history_points.positive?
        total += add_breakdown!(
          breakdown,
          "shared_core_history_ips",
          core_history_points,
          core_history_count,
        )
      end

      auth_count = nonnegative_integer(data["shared_auth_ip_count"])
      auth_points = [auth_count * 6, 18].min
      if auth_points.positive?
        total += add_breakdown!(breakdown, "shared_auth_ips", auth_points, auth_count)
      end

      browser_count = nonnegative_integer(data["browser_continuity_count"])
      if browser_count.positive?
        browser_users = nonnegative_integer(data["max_browser_continuity_users"])
        browser_points =
          if browser_users >= 10
            5
          elsif browser_users >= 5
            10
          elsif browser_users >= 3
            18
          else
            browser_count >= 2 ? 35 : 25
          end
        total += add_breakdown!(breakdown, "browser_continuity", browser_points, browser_count)
      end

      signatures = nonnegative_integer(data["shared_session_signature_count"])
      if signatures.positive?
        signature_points = signatures >= 2 ? 15 : 10
        total += add_breakdown!(breakdown, "shared_session_signatures", signature_points, signatures)
      end

      shared_networks = nonnegative_integer(data["shared_network_count"])
      network_points =
        if shared_networks >= 3
          12
        elsif shared_networks == 2
          8
        elsif shared_networks == 1
          4
        else
          0
        end
      if network_points.positive?
        total += add_breakdown!(breakdown, "shared_networks", network_points, shared_networks)
      end

      if supporting_identity_signal?(data) && data.key?("registration_delta_minutes")
        registration_delta = nonnegative_integer(data["registration_delta_minutes"])
        delta_points =
          if registration_delta <= 60
            12
          elsif registration_delta <= 1_440
            9
          elsif registration_delta <= 10_080
            7
          elsif registration_delta <= 43_200
            5
          elsif registration_delta <= 129_600
            3
          elsif registration_delta <= 525_600
            1
          else
            0
          end
        if delta_points.positive?
          total += add_breakdown!(breakdown, "registration_timing", delta_points, registration_delta)
        end
      end

      popularity = nonnegative_integer(data["max_shared_exact_ip_users"])
      popularity_penalty =
        if popularity >= 20
          -20
        elsif popularity >= 15
          -14
        elsif popularity >= 10
          -9
        elsif popularity >= 5
          -3
        else
          0
        end
      if popularity_penalty.negative?
        total += add_breakdown!(breakdown, "shared_ip_popularity", popularity_penalty, popularity)
      end

      tor_count = nonnegative_integer(data["tor_shared_ip_count"])
      tor_penalty = -[tor_count * 8, 16].min
      total += add_breakdown!(breakdown, "tor_context", tor_penalty, tor_count) if tor_penalty.negative?

      hosting_count = nonnegative_integer(data["hosting_shared_ip_count"])
      hosting_penalty = -[hosting_count * 4, 8].min
      if hosting_penalty.negative?
        total += add_breakdown!(breakdown, "hosting_context", hosting_penalty, hosting_count)
      end

      mobile_count = nonnegative_integer(data["mobile_shared_ip_count"])
      mobile_penalty = -[mobile_count * 2, 4].min
      if mobile_penalty.negative?
        total += add_breakdown!(breakdown, "mobile_context", mobile_penalty, mobile_count)
      end

      trusted_count = nonnegative_integer(data["trusted_shared_ip_count"])
      if trusted_count.positive?
        total += add_breakdown!(breakdown, "trusted_network_context", -[trusted_count * 20, 40].min, trusted_count)
      end

      { score: total.clamp(0, 100), breakdown: breakdown }
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

    def store_candidate?(score, evidence)
      data = evidence.is_a?(Hash) ? evidence : {}
      return true if nonnegative_integer(data["shared_exact_ip_count"]).positive?
      candidate?(score) && primary_candidate_signal?(data)
    end

    def primary_candidate_signal?(data)
      nonnegative_integer(data["shared_exact_ip_count"]).positive? ||
        nonnegative_integer(data["shared_session_signature_count"]).positive? ||
        nonnegative_integer(data["shared_network_count"]).positive?
    end

    def supporting_identity_signal?(data)
      nonnegative_integer(data["shared_exact_ip_count"]).positive? ||
        nonnegative_integer(data["shared_session_signature_count"]).positive?
    end

    def add_breakdown!(breakdown, key, points, count)
      breakdown << { "key" => key, "points" => points.to_i, "count" => count.to_i }
      points.to_i
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
