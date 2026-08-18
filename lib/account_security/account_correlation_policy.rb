# frozen_string_literal: true

module ::AccountSecurity
  module AccountCorrelationPolicy
    module_function

    SCORING_VERSION = 2

    def score(evidence)
      score_with_breakdown(evidence)[:score]
    end

    def score_with_breakdown(evidence)
      data = evidence.is_a?(Hash) ? evidence : {}
      breakdown = []
      total = 0
      details = Array(data["shared_ip_details"]).select { |detail| detail.is_a?(Hash) }

      if !details.empty?
        total += score_exact_ip_details!(breakdown, details)
      else
        total += score_aggregate_ip_evidence!(breakdown, data)
      end

      browser_count = nonnegative_integer(data["browser_continuity_count"])
      if browser_count.positive?
        browser_users = nonnegative_integer(data["max_browser_continuity_users"])
        browser_points =
          if browser_users >= 10
            4
          elsif browser_users >= 5
            8
          elsif browser_users >= 3
            14
          else
            browser_count >= 2 ? 28 : 20
          end
        total += add_breakdown!(breakdown, "browser_continuity", browser_points, browser_count)
      end

      signatures = nonnegative_integer(data["shared_session_signature_count"])
      if signatures.positive?
        signature_points = signatures >= 2 ? 12 : 8
        total += add_breakdown!(breakdown, "shared_session_signatures", signature_points, signatures)
      end

      shared_networks = nonnegative_integer(data["shared_network_count"])
      network_points =
        if shared_networks >= 3
          9
        elsif shared_networks == 2
          6
        elsif shared_networks == 1
          3
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
            10
          elsif registration_delta <= 1_440
            8
          elsif registration_delta <= 10_080
            6
          elsif registration_delta <= 43_200
            4
          elsif registration_delta <= 129_600
            2
          elsif registration_delta <= 525_600
            1
          else
            0
          end
        if delta_points.positive?
          total += add_breakdown!(breakdown, "registration_timing", delta_points, registration_delta)
        end
      end

      { score: total.clamp(0, 100), breakdown: breakdown }
    end

    def confidence(score)
      value = score.to_i
      return "very_strong" if value >= 75
      return "strong" if value >= 50
      return "moderate" if value >= 25
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
      details = Array(data["shared_ip_details"]).select { |detail| detail.is_a?(Hash) }
      usable_exact =
        if details.empty?
          nonnegative_integer(data["shared_exact_ip_count"]) >
            nonnegative_integer(data["trusted_shared_ip_count"])
        else
          details.any? { |detail| !truthy?(detail["trusted"]) }
        end

      usable_exact || nonnegative_integer(data["shared_session_signature_count"]).positive?
    end

    def score_exact_ip_details!(breakdown, details)
      public_base = 0
      nonpublic_base = 0
      registration_points = 0
      auth_points = 0
      current_points = 0
      history_points = 0
      popularity_penalty = 0
      tor_penalty = 0
      hosting_penalty = 0
      mobile_penalty = 0
      trusted_count = 0

      details.each do |detail|
        public_ip = truthy?(detail["public"])
        trusted = truthy?(detail["trusted"])
        tor = truthy?(detail["tor"])
        hosting = truthy?(detail["hosting"])
        mobile = truthy?(detail["mobile"])
        users = [nonnegative_integer(detail["user_count"]), 1].max
        sources_a = source_set(detail["sources_a"])
        sources_b = source_set(detail["sources_b"])

        if trusted
          trusted_count += 1
          next
        end

        if public_ip
          public_base += 30
          popularity_penalty += public_popularity_penalty(users)
          tor_penalty -= 16 if tor
          hosting_penalty -= 8 if hosting && !tor
          mobile_penalty -= 5 if mobile && !tor && !hosting
        else
          # RFC1918 and other non-public addresses are useful local context, but
          # they are not globally unique and therefore carry deliberately modest weight.
          nonpublic_base += 5
        end

        registration_points += source_points(
          sources_a,
          sources_b,
          "registration",
          public_ip ? 16 : 5,
          public_ip ? 8 : 2,
        )
        auth_points += grouped_source_points(
          sources_a,
          sources_b,
          %w[auth_session active_session],
          public_ip ? 8 : 2,
          public_ip ? 4 : 1,
        )
        current_points += source_points(
          sources_a,
          sources_b,
          "current",
          public_ip ? 5 : 1,
          public_ip ? 2 : 0,
        )
        history_points += source_points(
          sources_a,
          sources_b,
          "history",
          public_ip ? 5 : 1,
          public_ip ? 2 : 0,
        )
      end

      total = 0
      if public_base.positive?
        total += add_breakdown!(breakdown, "shared_public_exact_ips", [public_base, 75].min, details.count { |d| truthy?(d["public"]) && !truthy?(d["trusted"]) })
      end
      if nonpublic_base.positive?
        total += add_breakdown!(breakdown, "shared_nonpublic_ips", [nonpublic_base, 15].min, details.count { |d| !truthy?(d["public"]) && !truthy?(d["trusted"]) })
      end
      if registration_points.positive?
        total += add_breakdown!(breakdown, "shared_registration_links", [registration_points, 30].min, 1)
      end
      if auth_points.positive?
        total += add_breakdown!(breakdown, "shared_auth_links", [auth_points, 20].min, 1)
      end
      if current_points.positive?
        total += add_breakdown!(breakdown, "shared_current_links", [current_points, 12].min, 1)
      end
      if history_points.positive?
        total += add_breakdown!(breakdown, "shared_core_history_links", [history_points, 12].min, 1)
      end

      if popularity_penalty.negative?
        total += add_breakdown!(breakdown, "shared_ip_popularity", [popularity_penalty, -24].max, 1)
      end
      total += add_breakdown!(breakdown, "tor_context", [tor_penalty, -24].max, 1) if tor_penalty.negative?
      if hosting_penalty.negative?
        total += add_breakdown!(breakdown, "hosting_context", [hosting_penalty, -16].max, 1)
      end
      if mobile_penalty.negative?
        total += add_breakdown!(breakdown, "mobile_context", [mobile_penalty, -10].max, 1)
      end
      if trusted_count.positive?
        # Trusted/shared networks are intentionally excluded from identity weight.
        add_breakdown!(breakdown, "trusted_network_context", 0, trusted_count)
      end

      total
    end

    def score_aggregate_ip_evidence!(breakdown, data)
      total = 0
      public_exact = nonnegative_integer(data["untrusted_public_ip_count"])
      nonpublic_exact = nonnegative_integer(data["shared_nonpublic_ip_count"])

      public_points = [public_exact * 30, 75].min
      nonpublic_points = [nonpublic_exact * 5, 15].min
      total += add_breakdown!(breakdown, "shared_public_exact_ips", public_points, public_exact) if public_points.positive?
      total += add_breakdown!(breakdown, "shared_nonpublic_ips", nonpublic_points, nonpublic_exact) if nonpublic_points.positive?

      if truthy?(data["shared_registration_ip_public"])
        total += add_breakdown!(breakdown, "shared_registration_links", 16, 1)
      elsif truthy?(data["shared_registration_ip_nonpublic"])
        total += add_breakdown!(breakdown, "shared_registration_links", 5, 1)
      end

      if truthy?(data["same_current_ip_public"])
        total += add_breakdown!(breakdown, "shared_current_links", 5, 1)
      elsif truthy?(data["same_current_ip_nonpublic"])
        total += add_breakdown!(breakdown, "shared_current_links", 1, 1)
      end

      auth_count = nonnegative_integer(data["shared_auth_ip_count"])
      if auth_count.positive?
        total += add_breakdown!(breakdown, "shared_auth_links", [auth_count * 6, 16].min, auth_count)
      end

      core_history_count = nonnegative_integer(data["shared_core_history_ip_count"])
      if core_history_count.positive?
        total += add_breakdown!(breakdown, "shared_core_history_links", [core_history_count * 4, 12].min, core_history_count)
      end

      popularity = nonnegative_integer(data["max_shared_exact_ip_users"])
      popularity_penalty = public_exact.positive? ? public_popularity_penalty(popularity) : 0
      if popularity_penalty.negative?
        total += add_breakdown!(breakdown, "shared_ip_popularity", popularity_penalty, popularity)
      end

      tor_penalty = -[nonnegative_integer(data["tor_shared_ip_count"]) * 16, 24].min
      total += add_breakdown!(breakdown, "tor_context", tor_penalty, 1) if tor_penalty.negative?
      hosting_penalty = -[nonnegative_integer(data["hosting_shared_ip_count"]) * 8, 16].min
      total += add_breakdown!(breakdown, "hosting_context", hosting_penalty, 1) if hosting_penalty.negative?
      mobile_penalty = -[nonnegative_integer(data["mobile_shared_ip_count"]) * 5, 10].min
      total += add_breakdown!(breakdown, "mobile_context", mobile_penalty, 1) if mobile_penalty.negative?

      total
    end

    def public_popularity_penalty(user_count)
      return 0 if user_count <= 2
      return -4 if user_count == 3
      return -6 if user_count == 4
      return -10 if user_count <= 9
      return -16 if user_count <= 19
      -24
    end

    def source_points(sources_a, sources_b, source, both_points, one_points)
      a = sources_a.include?(source)
      b = sources_b.include?(source)
      return both_points if a && b
      return one_points if a || b
      0
    end

    def grouped_source_points(sources_a, sources_b, sources, both_points, one_points)
      a = (sources_a & sources).any?
      b = (sources_b & sources).any?
      return both_points if a && b
      return one_points if a || b
      0
    end

    def source_set(value)
      Array(value).map(&:to_s).uniq
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
