# frozen_string_literal: true

module ::AccountSecurity
  module AccountCorrelationPolicy
    module_function

    SCORING_VERSION = 3

    GROUP_CAPS = {
      exact_public_ip: 45,
      temporal_proximity: 12,
      public_ip_transition: 25,
      browser_continuity: 27,
      client_signature: 10,
      independent_ipv6_network: 6,
      registration_timing: 5,
    }.freeze

    IP_WEIGHTS = [1.0, 0.80, 0.40].freeze
    EXTRA_IP_WEIGHT = 0.25
    TRANSITION_WEIGHTS = [1.0, 0.60, 0.35].freeze
    EXTRA_TRANSITION_WEIGHT = 0.20
    TRANSITION_BASE_POINTS = 20.0
    INCOMPLETE_POPULATION_RARITY_CAP = 1.0 / Math.sqrt(2.0)
    UNKNOWN_POPULATION_USERS = 5

    def score(evidence)
      score_with_breakdown(evidence)[:score]
    end

    def score_with_breakdown(evidence)
      data = evidence.is_a?(Hash) ? evidence : {}
      breakdown = []

      exact_ip = exact_public_ip_score(data)
      temporal = temporal_proximity_score(data)
      transition = public_ip_transition_score(data)
      browser = browser_continuity_score(data)
      client = client_signature_score(data)
      ipv6 = independent_ipv6_network_score(data)
      registration = registration_timing_score(data)

      add_breakdown!(breakdown, "v3_exact_public_ip", exact_ip[:points], exact_ip[:count]) if exact_ip[:points].positive?
      add_breakdown!(breakdown, "v3_temporal_proximity", temporal[:points], temporal[:count]) if temporal[:points].positive?
      add_breakdown!(breakdown, "v3_public_ip_transitions", transition[:points], transition[:count]) if transition[:points].positive?
      add_breakdown!(breakdown, "v3_browser_continuity", browser[:points], browser[:count]) if browser[:points].positive?
      add_breakdown!(breakdown, "v3_client_signatures", client[:points], client[:count]) if client[:points].positive?
      add_breakdown!(breakdown, "v3_independent_ipv6_networks", ipv6[:points], ipv6[:count]) if ipv6[:points].positive?
      add_breakdown!(breakdown, "v3_registration_timing", registration[:points], registration[:count]) if registration[:points].positive?

      trusted_count = Array(data["shared_ip_details"]).count do |detail|
        detail.is_a?(Hash) && truthy?(detail["trusted"])
      end
      add_breakdown!(breakdown, "trusted_network_context", 0, trusted_count) if trusted_count.positive?

      total = exact_ip[:points] + temporal[:points] + transition[:points] + browser[:points] +
        client[:points] + ipv6[:points] + registration[:points]

      if total >= 70 && !very_strong_eligible?(
        exact_ip: exact_ip,
        temporal: temporal,
        transition: transition,
        browser: browser,
        client: client,
        ipv6: ipv6,
      )
        correction = 69 - total
        add_breakdown!(breakdown, "v3_very_strong_guardrail", correction, 1)
        total = 69
      end

      { score: total.clamp(0, 100), breakdown: breakdown }
    end

    def confidence(score)
      value = score.to_i
      return "very_strong" if value >= 70
      return "strong" if value >= 45
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

    # Browser continuity remains supplemental positive-only evidence. It can
    # strengthen a pair that was found through another local signal but cannot
    # create a new candidate by itself.
    def primary_candidate_signal?(data)
      nonnegative_integer(data["shared_exact_ip_count"]).positive? ||
        nonnegative_integer(data["client_signature_group_count"]).positive? ||
        nonnegative_integer(data["shared_independent_network_count"]).positive? ||
        nonnegative_integer(data["shared_session_signature_count"]).positive? ||
        nonnegative_integer(data["shared_network_count"]).positive?
    end

    def supporting_identity_signal?(data)
      exact_public_ip_candidates(data).any? ||
        nonnegative_integer(data["client_signature_group_count"]).positive? ||
        independent_ipv6_networks(data).any?
    end

    def exact_public_ip_score(data)
      candidates = exact_public_ip_candidates(data)
      return score_result(0, 0) if candidates.empty?

      ordered = candidates.sort_by { |item| [-item[:specificity], item[:ip_address].to_s] }
      weighted = ordered.each_with_index.sum do |item, index|
        24.0 * item[:specificity] * diminishing_weight(index, IP_WEIGHTS, EXTRA_IP_WEIGHT)
      end
      reliability_bonus = shared_ip_source_reliability_bonus(ordered)
      points = [weighted.round + reliability_bonus, GROUP_CAPS[:exact_public_ip]].min

      score_result(points, ordered.length, specificity: ordered.first[:specificity])
    end

    def temporal_proximity_score(data)
      detail_by_ip = exact_public_ip_candidates(data).index_by { |item| item[:ip_address] }
      auth_details = Array(data["auth_proximity_details"]).select { |raw| raw.is_a?(Hash) && truthy?(raw["public"]) }
      scored = auth_details.filter_map do |raw|
        ip = raw["ip_address"].to_s
        ip_context = detail_by_ip[ip]
        next if ip_context.blank?

        gap = nonnegative_integer_or_nil(raw["closest_gap_seconds"])
        next if gap.nil?

        base = login_gap_points(gap)
        next if base.zero?

        { points: base.to_f * ip_context[:specificity], specificity: ip_context[:specificity] }
      end
      return score_result(0, 0) if scored.empty?

      best = scored.max_by { |item| item[:points] }
      repeat_count = nonnegative_integer(data["auth_proximity_public_ip_within_24h_count"])
      repeat_bonus =
        if repeat_count >= 8
          3
        elsif repeat_count >= 4
          2
        elsif repeat_count >= 2
          1
        else
          0
        end
      points = [best[:points].round + (repeat_bonus * best[:specificity]).round, GROUP_CAPS[:temporal_proximity]].min
      score_result(points, scored.length)
    end

    def public_ip_transition_score(data)
      # The transition rarity already measures how distinctive the exact A -> B
      # sequence is. Do not multiply individual endpoint rarity into this group
      # a second time: endpoint commonness is already represented by the exact-IP
      # group. Only network context (Tor/hosting/mobile/trusted) carries across.
      ip_context = transition_endpoint_contexts(data)
      transition_details = Array(data["public_ip_transition_details"]).select { |raw| raw.is_a?(Hash) }
      scored = transition_details.filter_map do |raw|
        from_ip = raw["from_ip"].to_s
        to_ip = raw["to_ip"].to_s
        next if from_ip.blank? || to_ip.blank? || from_ip == to_ip

        gap = nonnegative_integer_or_nil(raw["closest_transition_gap_seconds"])
        next if gap.nil?
        decay = transition_time_decay(gap)
        next if decay.zero?

        from_context = ip_context[from_ip] || transition_endpoint_context(from_ip, data)
        to_context = ip_context[to_ip] || transition_endpoint_context(to_ip, data)
        next if from_context.blank? || to_context.blank?

        population_complete = truthy?(raw["transition_population_complete"]) || truthy?(data["public_ip_transition_population_complete"])
        transition_users = transition_population_for_gap(raw, gap)
        transition_rarity = rarity_factor(transition_users, complete: population_complete)
        endpoint_factor = Math.sqrt(from_context[:context_factor] * to_context[:context_factor])
        value = TRANSITION_BASE_POINTS * transition_rarity * endpoint_factor * decay
        next unless value.positive?

        {
          points: value,
          gap: gap,
          transition_rarity: transition_rarity,
          endpoint_factor: endpoint_factor,
        }
      end
      return score_result(0, 0) if scored.empty?

      ordered = scored.sort_by { |item| [-item[:points], item[:gap]] }
      weighted = ordered.each_with_index.sum do |item, index|
        item[:points] * diminishing_weight(index, TRANSITION_WEIGHTS, EXTRA_TRANSITION_WEIGHT)
      end
      points = [weighted.round, GROUP_CAPS[:public_ip_transition]].min
      score_result(
        points,
        ordered.length,
        best_gap: ordered.first[:gap],
        best_strength: ordered.first[:points],
      )
    end

    def browser_continuity_score(data)
      count = nonnegative_integer(data["browser_continuity_count"])
      return score_result(0, 0) if count.zero?

      users = positive_integer_or_nil(data["max_browser_continuity_users"])
      rarity = rarity_factor(users, complete: users.present?)
      base = 25
      base += 1 if nonnegative_integer(data["repeated_browser_continuity_count"]).positive?
      base += 1 if nonnegative_integer(data["browser_continuity_paired_observations"]) >= 4 ||
        nonnegative_integer(data["browser_continuity_span_days"]) >= 7
      points = [(base * rarity).round, GROUP_CAPS[:browser_continuity]].min
      score_result(points, count, rarity: rarity)
    end

    def client_signature_score(data)
      count = nonnegative_integer(data["client_signature_group_count"])
      return score_result(0, 0) if count.zero?

      repeated = nonnegative_integer(data["repeated_client_signature_group_count"])
      paired_observations = [
        nonnegative_integer(data["client_signature_group_paired_observations"]),
        nonnegative_integer(data["shared_session_signature_paired_observations"]),
        nonnegative_integer(data["shared_auth_client_signature_paired_observations"]),
      ].max
      users = positive_integer_or_nil(data["max_client_signature_group_users"])
      complete = truthy?(data["client_signature_population_complete"])
      rarity = rarity_factor(users, complete: complete)

      base = count >= 2 ? 8 : 6
      base += 1 if repeated.positive?
      base += 1 if paired_observations >= 4
      points = [(base * rarity).round, GROUP_CAPS[:client_signature]].min
      score_result(points, count, rarity: rarity)
    end

    def independent_ipv6_network_score(data)
      networks = independent_ipv6_networks(data)
      return score_result(0, 0) if networks.empty?

      users = positive_integer_or_nil(data["max_independent_shared_network_users"])
      rarity = rarity_factor(users, complete: users.present?)
      base = networks.length >= 3 ? 6 : networks.length == 2 ? 5 : 4
      points = [(base * rarity).round, GROUP_CAPS[:independent_ipv6_network]].min
      score_result(points, networks.length, rarity: rarity)
    end

    def registration_timing_score(data)
      return score_result(0, 0) unless supporting_identity_signal?(data)
      return score_result(0, 0) unless data.key?("registration_delta_minutes")

      minutes = nonnegative_integer(data["registration_delta_minutes"])
      points =
        if minutes <= 60
          5
        elsif minutes <= 1_440
          4
        elsif minutes <= 10_080
          2
        elsif minutes <= 43_200
          1
        else
          0
        end
      score_result(points, points.positive? ? 1 : 0)
    end

    def exact_public_ip_candidates(data)
      details = Array(data["shared_ip_details"]).select do |detail|
        detail.is_a?(Hash) && truthy?(detail["public"]) && !truthy?(detail["trusted"])
      end
      return aggregate_public_ip_candidates(data) if details.empty?

      temporal = Array(data["temporal_ip_details"]).select { |row| row.is_a?(Hash) }.index_by { |row| row["ip_address"].to_s }
      population_complete = truthy?(data["exact_ip_population_complete"])

      details.map do |detail|
        ip = detail["ip_address"].to_s
        temporal_detail = temporal[ip]
        users = effective_ip_population(detail, temporal_detail)
        rarity_complete = population_complete && (temporal_detail.blank? || !temporal_detail.key?("temporal_population_complete") || truthy?(temporal_detail["temporal_population_complete"]))
        context = ip_context_factor(detail)

        {
          ip_address: ip,
          specificity: rarity_factor(users, complete: rarity_complete) * context,
          users: users,
          sources_a: source_set(detail["sources_a"]),
          sources_b: source_set(detail["sources_b"]),
          context_factor: context,
        }
      end.select { |item| item[:specificity].positive? }
    end

    def aggregate_public_ip_candidates(data)
      count = nonnegative_integer(data["untrusted_public_ip_count"])
      count = nonnegative_integer(data["shared_public_ip_count"]) if count.zero?
      return [] if count.zero?

      users = positive_integer_or_nil(data["max_shared_exact_ip_users"])
      specificity = rarity_factor(users, complete: truthy?(data["exact_ip_population_complete"]))
      Array.new(count) do |index|
        {
          ip_address: "aggregate-#{index}",
          specificity: specificity,
          users: users || UNKNOWN_POPULATION_USERS,
          sources_a: [],
          sources_b: [],
          context_factor: 1.0,
        }
      end
    end

    def transition_endpoint_contexts(data)
      Array(data["shared_ip_details"]).each_with_object({}) do |detail, memo|
        next unless detail.is_a?(Hash) && truthy?(detail["public"]) && !truthy?(detail["trusted"])

        ip = detail["ip_address"].to_s
        next if ip.blank?

        context = ip_context_factor(detail)
        memo[ip] = { ip_address: ip, context_factor: context }
      end
    end

    def transition_endpoint_context(ip, data)
      # A transition endpoint may no longer be part of the current exact-IP
      # intersection. In that case use a conservative neutral-public estimate
      # rather than discarding a legitimate historical A -> B pattern.
      {
        ip_address: ip,
        # A capped-out historical endpoint has no safe per-IP context available
        # in the persisted payload. Use a conservative half-weight rather than
        # assuming an ordinary residential address.
        context_factor: 0.50,
      }
    end

    def effective_ip_population(detail, temporal_detail)
      historical = [positive_integer_or_nil(detail["user_count"]) || UNKNOWN_POPULATION_USERS, 2].max
      return historical unless temporal_detail.is_a?(Hash)

      gap = nonnegative_integer_or_nil(temporal_detail["closest_gap_seconds"])
      temporal_users =
        if gap && gap <= 1.day.to_i
          positive_integer_or_nil(temporal_detail["temporal_population_users_24h"])
        elsif gap && gap <= 7.days.to_i
          positive_integer_or_nil(temporal_detail["temporal_population_users_7d"])
        elsif gap && gap <= 30.days.to_i
          positive_integer_or_nil(temporal_detail["temporal_population_users_30d"])
        end
      [temporal_users || historical, 2].max
    end

    def transition_population_for_gap(detail, gap)
      if gap <= 1.day.to_i
        positive_integer_or_nil(detail["transition_user_count_24h"]) ||
          positive_integer_or_nil(detail["transition_user_count"])
      elsif gap <= 7.days.to_i
        positive_integer_or_nil(detail["transition_user_count_7d"]) ||
          positive_integer_or_nil(detail["transition_user_count"])
      else
        positive_integer_or_nil(detail["transition_user_count"])
      end
    end

    def shared_ip_source_reliability_bonus(details)
      return 0 if details.empty?

      bonuses = details.map do |detail|
        a = detail[:sources_a]
        b = detail[:sources_b]
        score = 0
        score += source_reliability(a, b, ["registration"], both: 4, one: 2)
        score += source_reliability(a, b, %w[auth_session active_session], both: 2, one: 1)
        score += source_reliability(a, b, ["current"], both: 1, one: 0)
        score += source_reliability(a, b, ["history"], both: 1, one: 0)
        score
      end
      [bonuses.max.to_i, 6].min
    end

    def source_reliability(sources_a, sources_b, sources, both:, one:)
      a = (sources_a & sources).any?
      b = (sources_b & sources).any?
      return both if a && b
      return one if a || b
      0
    end

    def login_gap_points(seconds)
      return 10 if seconds <= 5.minutes.to_i
      return 9 if seconds <= 30.minutes.to_i
      return 8 if seconds <= 1.hour.to_i
      return 7 if seconds <= 6.hours.to_i
      return 5 if seconds <= 1.day.to_i
      return 3 if seconds <= 3.days.to_i
      return 2 if seconds <= 7.days.to_i
      0
    end

    def transition_time_decay(seconds)
      return 1.00 if seconds <= 1.hour.to_i
      return 0.95 if seconds <= 6.hours.to_i
      return 0.90 if seconds <= 1.day.to_i
      return 0.75 if seconds <= 3.days.to_i
      return 0.60 if seconds <= 7.days.to_i
      return 0.35 if seconds <= 30.days.to_i
      return 0.15 if seconds <= 90.days.to_i
      return 0.05 if seconds <= 180.days.to_i
      0.0
    end

    def rarity_factor(user_count, complete:)
      users = [positive_integer_or_nil(user_count) || UNKNOWN_POPULATION_USERS, 2].max
      raw = 1.0 / Math.sqrt([users - 1, 1].max.to_f)
      complete ? raw : [raw, INCOMPLETE_POPULATION_RARITY_CAP].min
    end

    def ip_context_factor(detail)
      return 0.0 if truthy?(detail["trusted"])
      return 0.25 if truthy?(detail["tor"])
      return 0.50 if truthy?(detail["hosting"])
      return 0.60 if truthy?(detail["mobile"])
      1.0
    end

    def independent_ipv6_networks(data)
      Array(data["shared_independent_networks"]).map(&:to_s).select do |network|
        network.include?(":")
      end.uniq
    end

    def very_strong_eligible?(exact_ip:, temporal:, transition:, browser:, client:, ipv6:)
      network_strength = exact_ip[:points] + temporal[:points] + transition[:points] + ipv6[:points]
      multiple_families =
        (browser[:points] >= 15 && network_strength >= 25) ||
        (client[:points] >= 7 && exact_ip[:points] >= 35 &&
          (temporal[:points] >= 5 || transition[:points] >= 8))
      exceptional_network_sequence =
        exact_ip[:points] >= 30 && transition[:points] >= 14 && transition[:best_gap].to_i <= 7.days.to_i

      multiple_families || exceptional_network_sequence
    end

    def diminishing_weight(index, weights, fallback)
      weights[index] || fallback
    end

    def score_result(points, count, **extra)
      { points: points.to_i, count: count.to_i }.merge(extra)
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

    def positive_integer_or_nil(value)
      number = Integer(value, exception: false)
      number && number.positive? ? number : nil
    end

    def nonnegative_integer_or_nil(value)
      number = Integer(value, exception: false)
      number && number >= 0 ? number : nil
    end

    def nonnegative_integer(value)
      nonnegative_integer_or_nil(value) || 0
    end
  end
end
