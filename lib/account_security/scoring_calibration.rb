# frozen_string_literal: true

module ::AccountSecurity
  module ScoringCalibration
    module_function

    STORE_KEY = "scoring_calibration_draft_v1"
    PROFILE_SCHEMA_VERSION = 1
    MAX_PREVIEW_ROWS = 5_000
    DEFAULT_PREVIEW_ROWS = 2_000

    DEFAULT_PROFILE = {
      "moderate_threshold" => 25,
      "strong_threshold" => 45,
      "very_strong_threshold" => 70,
      "exact_ip_base_points" => 24.0,
      "exact_ip_cap" => 45,
      "rarity_exponent" => 0.50,
      "tor_context_factor" => 0.25,
      "hosting_context_factor" => 0.50,
      "mobile_context_factor" => 0.60,
      "temporal_cap" => 12,
      "login_5m_points" => 10,
      "login_30m_points" => 9,
      "login_1h_points" => 8,
      "login_6h_points" => 7,
      "login_24h_points" => 5,
      "login_72h_points" => 3,
      "login_7d_points" => 2,
      "transition_base_points" => 20.0,
      "transition_cap" => 25,
      "transition_decay_24h" => 0.90,
      "transition_decay_7d" => 0.60,
      "transition_decay_30d" => 0.35,
      "transition_decay_90d" => 0.15,
      "transition_decay_180d" => 0.05,
      "browser_base_points" => 25,
      "browser_repeated_bonus" => 3,
      "browser_sustained_bonus" => 3,
      "browser_switch_1h_bonus" => 6,
      "browser_switch_6h_bonus" => 5,
      "browser_switch_24h_bonus" => 4,
      "browser_switch_7d_bonus" => 2,
      "browser_repeated_switch_bonus" => 2,
      "browser_cap" => 36,
      "client_single_points" => 6,
      "client_multiple_points" => 8,
      "client_cap" => 10,
    }.freeze

    def descriptor(group, min, max, step, kind)
      { group: group, min: min, max: max, step: step, kind: kind.to_s }.freeze
    end

    DESCRIPTORS = {
      "moderate_threshold" => descriptor("confidence", 10, 40, 1, :integer),
      "strong_threshold" => descriptor("confidence", 30, 70, 1, :integer),
      "very_strong_threshold" => descriptor("confidence", 55, 95, 1, :integer),
      "exact_ip_base_points" => descriptor("ip", 5, 40, 0.5, :float),
      "exact_ip_cap" => descriptor("ip", 20, 70, 1, :integer),
      "rarity_exponent" => descriptor("ip", 0.20, 1.20, 0.05, :float),
      "tor_context_factor" => descriptor("ip", 0.0, 1.0, 0.05, :float),
      "hosting_context_factor" => descriptor("ip", 0.0, 1.0, 0.05, :float),
      "mobile_context_factor" => descriptor("ip", 0.0, 1.0, 0.05, :float),
      "temporal_cap" => descriptor("timing", 0, 25, 1, :integer),
      "login_5m_points" => descriptor("timing", 0, 20, 1, :integer),
      "login_30m_points" => descriptor("timing", 0, 20, 1, :integer),
      "login_1h_points" => descriptor("timing", 0, 20, 1, :integer),
      "login_6h_points" => descriptor("timing", 0, 20, 1, :integer),
      "login_24h_points" => descriptor("timing", 0, 20, 1, :integer),
      "login_72h_points" => descriptor("timing", 0, 20, 1, :integer),
      "login_7d_points" => descriptor("timing", 0, 20, 1, :integer),
      "transition_base_points" => descriptor("transition", 0, 40, 0.5, :float),
      "transition_cap" => descriptor("transition", 0, 50, 1, :integer),
      "transition_decay_24h" => descriptor("transition", 0.0, 1.0, 0.05, :float),
      "transition_decay_7d" => descriptor("transition", 0.0, 1.0, 0.05, :float),
      "transition_decay_30d" => descriptor("transition", 0.0, 1.0, 0.05, :float),
      "transition_decay_90d" => descriptor("transition", 0.0, 1.0, 0.05, :float),
      "transition_decay_180d" => descriptor("transition", 0.0, 1.0, 0.05, :float),
      "browser_base_points" => descriptor("browser", 0, 40, 1, :integer),
      "browser_repeated_bonus" => descriptor("browser", 0, 15, 1, :integer),
      "browser_sustained_bonus" => descriptor("browser", 0, 15, 1, :integer),
      "browser_switch_1h_bonus" => descriptor("browser", 0, 20, 1, :integer),
      "browser_switch_6h_bonus" => descriptor("browser", 0, 20, 1, :integer),
      "browser_switch_24h_bonus" => descriptor("browser", 0, 20, 1, :integer),
      "browser_switch_7d_bonus" => descriptor("browser", 0, 20, 1, :integer),
      "browser_repeated_switch_bonus" => descriptor("browser", 0, 15, 1, :integer),
      "browser_cap" => descriptor("browser", 10, 60, 1, :integer),
      "client_single_points" => descriptor("client", 0, 20, 1, :integer),
      "client_multiple_points" => descriptor("client", 0, 20, 1, :integer),
      "client_cap" => descriptor("client", 0, 25, 1, :integer),
    }.freeze

    def profile(overrides = nil)
      DEFAULT_PROFILE.merge(normalize_overrides(overrides || {}))
    end

    def draft
      raw = PluginStore.get(AccountSecurity::STORE_NAMESPACE, STORE_KEY)
      return DEFAULT_PROFILE.dup unless raw.is_a?(Hash)

      profile(raw)
    rescue StandardError => e
      Rails.logger.warn("[account_security] scoring calibration draft load failed class=#{e.class}")
      DEFAULT_PROFILE.dup
    end

    def validated_profile(values)
      normalized = profile(values)
      validate_relationships!(normalized)
      normalized
    end

    def save_draft!(values)
      normalized = validated_profile(values)
      PluginStore.set(AccountSecurity::STORE_NAMESPACE, STORE_KEY, normalized)
      normalized
    end

    def reset_draft!
      PluginStore.remove(AccountSecurity::STORE_NAMESPACE, STORE_KEY)
      DEFAULT_PROFILE.dup
    end

    def descriptors
      DESCRIPTORS.map do |key, value|
        value.merge(key: key, default: DEFAULT_PROFILE.fetch(key))
      end
    end

    def normalize_overrides(values)
      hash = values.respond_to?(:to_h) ? values.to_h : {}
      unknown = hash.keys.map(&:to_s) - DESCRIPTORS.keys
      raise Discourse::InvalidParameters.new(:profile) if unknown.any?

      hash.each_with_object({}) do |(raw_key, raw_value), result|
        key = raw_key.to_s
        descriptor = DESCRIPTORS[key]
        next if descriptor.blank?

        value = numeric_value(raw_value, descriptor[:kind])
        raise Discourse::InvalidParameters.new(key) if value.nil?
        raise Discourse::InvalidParameters.new(key) if value < descriptor[:min] || value > descriptor[:max]
        result[key] = value
      end
    end

    def validate_relationships!(value)
      unless value["moderate_threshold"] < value["strong_threshold"] &&
          value["strong_threshold"] < value["very_strong_threshold"]
        raise Discourse::InvalidParameters.new(:confidence_thresholds)
      end

      timing = %w[
        login_5m_points login_30m_points login_1h_points login_6h_points
        login_24h_points login_72h_points login_7d_points
      ].map { |key| value[key].to_f }
      raise Discourse::InvalidParameters.new(:login_timing) unless timing.each_cons(2).all? { |a, b| a >= b }

      transition = %w[
        transition_decay_24h transition_decay_7d transition_decay_30d
        transition_decay_90d transition_decay_180d
      ].map { |key| value[key].to_f }
      raise Discourse::InvalidParameters.new(:transition_decay) unless transition.each_cons(2).all? { |a, b| a >= b }

      switches = %w[
        browser_switch_1h_bonus browser_switch_6h_bonus browser_switch_24h_bonus
        browser_switch_7d_bonus
      ].map { |key| value[key].to_f }
      raise Discourse::InvalidParameters.new(:browser_switch_timing) unless switches.each_cons(2).all? { |a, b| a >= b }

      value
    end

    def numeric_value(raw, kind)
      if kind == "integer"
        Integer(raw, exception: false)
      else
        Float(raw, exception: false)&.round(4)
      end
    rescue TypeError, ArgumentError
      nil
    end
  end
end
