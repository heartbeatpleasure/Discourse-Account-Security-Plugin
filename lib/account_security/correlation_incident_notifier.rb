# frozen_string_literal: true

module ::AccountSecurity
  module CorrelationIncidentNotifier
    module_function

    CONFIDENCE_RANK = { "weak" => 0, "moderate" => 1, "strong" => 2, "very_strong" => 3 }.freeze
    REALTIME_SOURCES = %w[registration login staff_login browser_continuity].freeze

    def notify_if_needed!(correlation, source:)
      return false unless SiteSetting.account_security_staff_notifications_enabled
      return false unless SiteSetting.account_security_correlation_notifications_enabled
      return false unless correlation&.persisted?
      return false unless REALTIME_SOURCES.include?(source.to_s)
      return false unless correlation.status.in?(%w[open monitor])
      return false unless confidence_rank(correlation.confidence) >= confidence_rank("strong")
      return false unless notification_due?(correlation)

      groups = IncidentNotifier.notification_group_names
      return false if groups.empty?

      DistributedMutex.synchronize("account-security-notify-correlation-#{correlation.id}", validity: 30) do
        correlation.reload
        return false unless correlation.status.in?(%w[open monitor])
        return false unless confidence_rank(correlation.confidence) >= confidence_rank("strong")
        return false unless notification_due?(correlation)

        create_private_message!(correlation, groups)
        evidence = correlation.evidence.is_a?(Hash) ? correlation.evidence : {}
        now = Time.zone.now
        correlation.update_columns(
          notified_at: now,
          notified_score: correlation.score.to_i,
          notified_confidence: correlation.confidence.to_s,
          notified_public_ip_count: evidence["untrusted_public_ip_count"].to_i,
          updated_at: now,
        )
        Statistics.increment!(notifications_sent: 1)
        true
      end
    rescue StandardError => e
      Rails.logger.warn(
        "[account_security] correlation notification failed correlation_id=#{correlation&.id} class=#{e.class}",
      )
      false
    end

    def notification_due?(correlation)
      return true if correlation.notified_at.blank?

      current_rank = confidence_rank(correlation.confidence)
      previous_rank = confidence_rank(correlation.notified_confidence)
      return true if current_rank > previous_rank

      return true if correlation.score.to_i >= correlation.notified_score.to_i + 15

      evidence = correlation.evidence.is_a?(Hash) ? correlation.evidence : {}
      current_public_ips = evidence["untrusted_public_ip_count"].to_i
      current_public_ips > correlation.notified_public_ip_count.to_i
    end

    def confidence_rank(value)
      CONFIDENCE_RANK[value.to_s] || 0
    end

    def create_private_message!(correlation, group_names)
      locale = SiteSetting.default_locale.presence || I18n.default_locale
      title = nil
      raw = nil
      evidence = correlation.evidence.is_a?(Hash) ? correlation.evidence : {}

      I18n.with_locale(locale) do
        title = I18n.t(
          "account_security.correlation_notification.title",
          confidence: I18n.t(
            "account_security.correlation_notification.confidences.#{correlation.confidence}",
            default: correlation.confidence.to_s.humanize,
          ),
        )
        raw = I18n.t(
          "account_security.correlation_notification.body",
          user_a: correlation.user_a&.username || I18n.t("account_security.correlation_notification.unknown_user"),
          user_b: correlation.user_b&.username || I18n.t("account_security.correlation_notification.unknown_user"),
          score: correlation.score.to_i,
          confidence: I18n.t(
            "account_security.correlation_notification.confidences.#{correlation.confidence}",
            default: correlation.confidence.to_s.humanize,
          ),
          shared_ips: evidence["shared_exact_ip_count"].to_i,
          public_ips: evidence["untrusted_public_ip_count"].to_i,
          auth_ips: evidence["shared_auth_ip_count"].to_i,
          correlation_url: "#{Discourse.base_url}/admin/plugins/account-security-correlations?pair_id=#{correlation.id}",
        )
      end

      PostCreator.create!(
        Discourse.system_user,
        title: title,
        raw: raw,
        archetype: Archetype.private_message,
        target_group_names: group_names.join(","),
      )
    end
  end
end
