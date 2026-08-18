# frozen_string_literal: true

module ::AccountSecurity
  module IncidentNotifier
    module_function

    EVIDENCE_RANK = { "weak" => 0, "moderate" => 1, "strong" => 2, "corroborated" => 3 }.freeze
    HIGH_SEVERITIES = %w[high critical].freeze

    def notify_if_needed!(event)
      return false unless SiteSetting.account_security_staff_notifications_enabled
      return false unless event&.persisted?
      return false if event.notified_at.present?
      return false if event.status.in?(%w[benign auto_resolved])
      return false if NotificationSuppressionManager.active_for(event)

      kind = notification_kind(event)
      return false unless kind

      groups = notification_group_names
      return false if groups.empty?

      mutex = "account-security-notify-event-#{event.id}"
      DistributedMutex.synchronize(mutex, validity: 30) do
        event.reload
        return false if event.notified_at.present?
        return false if event.status.in?(%w[benign auto_resolved])
        return false if NotificationSuppressionManager.active_for(event)

        kind = notification_kind(event)
        return false unless kind

        create_private_message!(event, kind, groups)
        now = Time.zone.now
        event.update_columns(notified_at: now, notification_kind: kind, updated_at: now)
        Statistics.increment!(notifications_sent: 1)
        RiskEventAuditTrail.record!(
          event: event,
          action: "staff_notified",
          details: { notification_kind: kind },
        )
        true
      end
    rescue StandardError => e
      Rails.logger.warn("[account_security] incident notification failed event_id=#{event&.id} class=#{e.class}")
      false
    end

    def notification_kind(event)
      evidence = EVIDENCE_RANK[event.evidence_strength.to_s] || 0
      context = event.context.is_a?(Hash) ? event.context : {}

      if event.event_type == "registration" && event.severity == "critical" && evidence >= EVIDENCE_RANK["strong"]
        return "critical_registration"
      end

      if event.event_type == "staff_login_new_network" && HIGH_SEVERITIES.include?(event.severity) && evidence >= EVIDENCE_RANK["moderate"]
        return "staff_new_network"
      end

      if event.event_type == "auth_failure_cluster" &&
           evidence >= EVIDENCE_RANK["strong"] &&
           (context["local_abuse_confirmed"] == true || context["staff_targeted"] == true)
        return "auth_abuse_cluster"
      end

      return "repeated_high_networks" if repeated_high_network_pattern?(event)

      nil
    end

    def repeated_high_network_pattern?(event)
      return false unless event.user_id.present? && HIGH_SEVERITIES.include?(event.severity)
      return false unless event.event_type.in?(%w[login_new_network staff_login_new_network])

      events =
        RiskEvent
          .where(user_id: event.user_id, severity: HIGH_SEVERITIES)
          .where(event_type: %w[login_new_network staff_login_new_network])
          .where.not(status: %w[benign auto_resolved])
          .where("last_seen_at >= ?", 24.hours.ago)
          .order(last_seen_at: :desc)
          .limit(100)
          .to_a

      networks = events.filter_map do |item|
        context = item.context.is_a?(Hash) ? item.context : {}
        context["familiarity_network"].to_s.presence
      end
      networks.uniq.length >= 3
    end

    def notification_group_names
      ids = notification_group_ids
      return [] if ids.empty?

      Group.where(id: ids).order(:id).pluck(:name).compact
    end

    def notification_group_ids
      if SiteSetting.respond_to?(:account_security_notification_groups_map)
        return Array(SiteSetting.account_security_notification_groups_map).map(&:to_i).select(&:positive?).uniq
      end

      SiteSetting.account_security_notification_groups.to_s.split(/[|,]/).filter_map do |value|
        id = Integer(value, exception: false)
        id if id&.positive?
      end.uniq
    end

    def create_private_message!(event, kind, group_names)
      locale = SiteSetting.default_locale.presence || I18n.default_locale
      title = nil
      raw = nil
      I18n.with_locale(locale) do
        severity = I18n.t("account_security.notification.severities.#{event.severity}", default: event.severity.to_s.humanize)
        event_type = I18n.t("account_security.notification.event_types.#{event.event_type}", default: event.event_type.to_s.humanize)
        title = I18n.t("account_security.notification.title", severity: severity)
        raw = I18n.t(
          "account_security.notification.body",
          kind: I18n.t("account_security.notification.kinds.#{kind}"),
          severity: severity,
          event_type: event_type,
          user: SafeText.markdown_plain(
            event.user&.username || I18n.t("account_security.notification.no_user"),
            max_chars: 80,
          ),
          network_context: coarse_context(event),
          ip_line: ip_line(event),
          event_url: "#{Discourse.base_url}/admin/plugins/account-security-events/#{event.id}",
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

    def coarse_context(event)
      context = event.context.is_a?(Hash) ? event.context : {}
      parts = []
      usage_type = SafeText.markdown_plain(context["usage_type"], max_chars: 120)
      parts << usage_type if usage_type.present?
      parts << I18n.t("account_security.notification.context.tor") if context["is_tor"] == true
      if context["local_blacklist_match"] == true
        parts << I18n.t("account_security.notification.context.local_blacklist")
      end
      if context["staff_targeted"] == true
        parts << I18n.t("account_security.notification.context.staff_targeted")
      end
      country = event.ip_intelligence&.country_code.to_s
      parts << country if country.match?(/\A[A-Z]{2}\z/)
      parts = [I18n.t("account_security.notification.context.unavailable")] if parts.empty?
      SafeText.plain(parts.join(" / "), max_chars: 180)
    end

    def ip_line(event)
      return "" unless SiteSetting.account_security_notification_include_ip
      "\n- IP: `#{event.ip_address}`"
    end
  end
end
