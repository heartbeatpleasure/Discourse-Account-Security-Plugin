# frozen_string_literal: true

module ::AccountSecurity
  class AdminController < ::Admin::AdminController
    requires_plugin ::AccountSecurity::PLUGIN_NAME
    before_action :disable_response_caching

    ADMIN_LIMIT = 30

    def overview
      health = Health.payload
      render_json_dump(
        enabled: SiteSetting.account_security_enabled,
        health: health,
        today: Statistics.today_payload,
        open_events: RiskEvent.where(status: "open").count,
        high_critical_events: RiskEvent.where(status: "open", severity: %w[high critical]).count,
        cached_addresses: IpIntelligence.count,
        trusted_networks: TrustedNetwork.active.count,
        active_temporary_ip_blocks: TemporaryIpBlock.active.count,
        reporting_enabled: SiteSetting.account_security_abuse_reporting_enabled,
      )
    end

    def events
      page = positive_integer_value(params[:page]) || 1
      per_page = 50
      status = params[:status].to_s
      severity = params[:severity].to_s
      raise Discourse::InvalidParameters.new(:status) if status.present? && !RiskEvent::STATUSES.include?(status)
      raise Discourse::InvalidParameters.new(:severity) if severity.present? && !RiskEvent::SEVERITIES.include?(severity)

      scope = RiskEvent.includes(:user, :reviewed_by).order(last_seen_at: :desc, id: :desc)
      scope = scope.where(status: status) if status.present?
      scope = scope.where(severity: severity) if severity.present?
      total = scope.count
      max_page = [(total.to_f / per_page).ceil, 1].max
      page = [page, max_page].min
      items = scope.offset((page - 1) * per_page).limit(per_page)
      render_json_dump(page: page, per_page: per_page, total: total, items: items.map { |event| serialize_event(event) })
    end

    def show_event
      event = find_event!
      render_json_dump(event_detail_payload(event))
    end

    def update_event
      rate_limit!("event-update")
      event = find_event!
      status = params.require(:status).to_s
      raise Discourse::InvalidParameters.new(:status) unless RiskEvent::STATUSES.include?(status)
      reason = clean_optional(params[:resolution_reason], 240)
      event.update!(
        status: status,
        reviewed_by_id: current_user.id,
        reviewed_at: Time.zone.now,
        resolution_reason: reason,
      )
      StaffAudit.log!(actor: current_user, action: "event_review_changed", details: { event_id: event.id, status: status })
      render_json_dump(success: true, event: serialize_event(event.reload, detail: true))
    end

    def refresh_event
      rate_limit!("event-refresh", 10)
      event = find_event!
      result = AssessmentService.call(
        ip: event.ip_address.to_s,
        user: nil,
        trigger: "manual",
        force_remote: true,
        allow_remote: true,
      )

      if result.intelligence
        refreshed_evidence =
          if event.event_type.in?(%w[auth_failure_cluster registration_abuse_cluster])
            trigger = event.event_type == "registration_abuse_cluster" ? "registration_abuse" : "auth_failure"
            EventRecorder.event_evidence_strength(result.intelligence, trigger, event.context || {})
          else
            result.intelligence.evidence_strength
          end
        event.update!(
          risk_level: result.intelligence.risk_level,
          severity: EventRecorder.severity_for(result.intelligence.risk_level),
          evidence_strength: refreshed_evidence,
          ip_intelligence_id: result.intelligence.id,
          last_seen_at: Time.zone.now,
        )
        IncidentNotifier.notify_if_needed!(event)
      end

      StaffAudit.log!(actor: current_user, action: "event_refreshed", details: { event_id: event.id, result: result.source || result.reason })
      render_json_dump(
        success: result.success,
        reason: result.reason,
        source: result.source,
        event: serialize_event(event.reload, detail: true),
      )
    end

    def add_user_note
      rate_limit!("event-user-note", 10)
      require_confirmation!
      event = find_event!
      unless UserNoteWriter.record!(event: event, actor: current_user)
        return render_json_error(I18n.t("admin.account_security.events.user_note_unavailable"), status: :unprocessable_entity)
      end

      render_json_dump(success: true, event: serialize_event(event.reload, detail: true))
    end

    def create_temporary_block
      rate_limit!("event-temp-block", 10)
      require_confirmation!
      event = find_event!
      block = TemporaryIpBlockManager.create!(
        event: event,
        actor: current_user,
        duration_minutes: params.require(:duration_minutes),
      )
      render_json_dump(success: true, temporary_block: serialize_temporary_block(block))
    rescue TemporaryIpBlockManager::ExistingScreening
      render_json_error(I18n.t("admin.account_security.events.existing_ip_screening"), status: :unprocessable_entity)
    rescue TemporaryIpBlockManager::NotEligible
      render_json_error(I18n.t("admin.account_security.events.temporary_block_not_eligible"), status: :unprocessable_entity)
    end

    def release_temporary_block
      rate_limit!("event-temp-block-release", 10)
      event = find_event!
      block = TemporaryIpBlockManager.release_for_event!(event: event, actor: current_user)
      render_json_dump(success: true, temporary_block: serialize_temporary_block(block.reload))
    end

    def create_notification_suppression
      rate_limit!("notification-suppression-create", 10)
      require_confirmation!
      event = find_event!
      suppression = NotificationSuppressionManager.create!(
        event: event,
        actor: current_user,
        duration_hours: params.require(:duration_hours),
      )
      render_json_dump(success: true, notification_suppression: serialize_notification_suppression(suppression))
    rescue NotificationSuppressionManager::NotEligible
      render_json_error(I18n.t("admin.account_security.events.notification_suppression_not_eligible"), status: :unprocessable_entity)
    end

    def release_notification_suppression
      rate_limit!("notification-suppression-release", 10)
      event = find_event!
      suppression = NotificationSuppressionManager.release!(event: event, actor: current_user)
      render_json_dump(success: true, notification_suppression: serialize_notification_suppression(suppression))
    rescue NotificationSuppressionManager::NotEligible
      render_json_error(I18n.t("admin.account_security.events.notification_suppression_not_eligible"), status: :unprocessable_entity)
    end

    def lookup
      rate_limit!("lookup", 20)
      ip = params.require(:account_security_ip).to_s
      normalized = IpNormalizer.normalize_public(ip)
      raise Discourse::InvalidParameters.new(:account_security_ip) if normalized.blank?
      force = params[:refresh] == true || params[:refresh].to_s == "true"
      result = AssessmentService.call(ip: normalized, user: nil, trigger: "manual", force_remote: force, allow_remote: force)
      render_json_dump(
        success: result.success,
        reason: result.reason,
        source: result.source,
        intelligence: serialize_intelligence(result.intelligence),
        recent_users: recent_users_for(normalized),
      )
    end

    def trusted_networks
      items = TrustedNetwork.includes(:created_by).order(id: :desc).limit(500)
      render_json_dump(items: items.map { |item| serialize_trusted_network(item) })
    end

    def create_trusted_network
      rate_limit!("trusted-create", 20)
      network = IpNormalizer.parse_network(params.require(:account_security_network))
      raise Discourse::InvalidParameters.new(:account_security_network) if network.blank? || network.in?(["0.0.0.0/0", "::/0"])
      if IpNormalizer.broad_network?(network) && !(params[:confirm_broad] == true || params[:confirm_broad].to_s == "true")
        return render_json_error(I18n.t("admin.account_security.trusted.broad_confirmation_required"), status: :unprocessable_entity)
      end
      label = clean_required(params.require(:label), 120, :label)
      reason = clean_required(params.require(:reason), 240, :reason)
      scope = params[:scope].presence || "bypass_lookup_and_enforcement"
      raise Discourse::InvalidParameters.new(:scope) unless TrustedNetwork::SCOPES.include?(scope)
      expires_at = parse_optional_time(params[:expires_at])
      item = TrustedNetwork.create!(network: network, label: label, reason: reason, scope: scope, created_by_id: current_user.id, expires_at: expires_at)
      StaffAudit.log!(actor: current_user, action: "trusted_network_created", details: { trusted_network_id: item.id })
      render_json_dump(success: true, item: serialize_trusted_network(item))
    rescue ActiveRecord::RecordNotUnique
      render_json_error(I18n.t("admin.account_security.trusted.duplicate"), status: :unprocessable_entity)
    end

    def delete_trusted_network
      rate_limit!("trusted-delete", 20)
      item = TrustedNetwork.find(positive_integer_param!(:id))
      item_id = item.id
      item.destroy!
      StaffAudit.log!(actor: current_user, action: "trusted_network_deleted", details: { trusted_network_id: item_id })
      render_json_dump(success: true)
    end

    def health
      render_json_dump(Health.payload)
    end

    def health_test
      rate_limit!("health-test", 2, 10.minutes)
      render_json_dump(Health.test!)
    end

    def reset_circuit
      rate_limit!("reset-circuit", 5)
      CircuitBreaker.reset!
      StaffAudit.log!(actor: current_user, action: "circuit_reset")
      render_json_dump(success: true, circuit_breaker: CircuitBreaker.state)
    end

    def sync_feed
      source = params.require(:source).to_s
      case source
      when "tor"
        rate_limit!("sync-tor-feed", 4, 1.hour)
      when "abuseipdb_blacklist"
        rate_limit!("sync-blacklist-feed", 2, 1.day)
      else
        raise Discourse::InvalidParameters.new(:source)
      end

      result = Health.sync_feed!(source)
      StaffAudit.log!(
        actor: current_user,
        action: "feed_synced",
        details: { feed: source, result: result.dig(:feed_sync, :success) == true ? "success" : "failed" },
      )
      render_json_dump(result)
    end

    def statistics
      period = params[:period].to_i
      period = 30 unless [7, 30, 90, 365].include?(period)
      render_json_dump(Statistics.period_payload(period))
    end

    def report_abuse
      rate_limit!("report-abuse", 5)
      require_confirmation!
      result = AbuseReporter.report_event!(event_id: params.require(:event_id), actor: current_user)
      if result[:success]
        StaffAudit.log!(
          actor: current_user,
          action: "abuse_reported",
          details: { event_id: result[:risk_event_id], report_id: result[:report_id] },
        )
      end
      render_json_dump(result)
    end

    private

    def disable_response_caching
      response.headers["Cache-Control"] = "no-store, private"
      response.headers["Pragma"] = "no-cache"
    end

    def rate_limit!(suffix, limit = ADMIN_LIMIT, period = 1.minute)
      RateLimiter.new(current_user, "account-security-admin-#{suffix}", limit, period).performed!
    end

    def require_confirmation!
      confirmed = params[:confirmed] == true || params[:confirmed].to_s == "true"
      raise Discourse::InvalidParameters.new(:confirmed) unless confirmed
    end

    def find_event!
      RiskEvent.includes(:user, :reviewed_by, :ip_intelligence).find(positive_integer_param!(:id))
    end

    def positive_integer_param!(name)
      positive_integer_value(params[name]) || raise(Discourse::InvalidParameters.new(name))
    end

    def positive_integer_value(value)
      number = Integer(value, exception: false)
      number&.positive? ? number : nil
    end

    def clean_required(value, max, name)
      cleaned = clean_optional(value, max)
      raise Discourse::InvalidParameters.new(name) if cleaned.blank?
      cleaned
    end

    def clean_optional(value, max)
      value.to_s.gsub(/[[:cntrl:]]+/, " ").squish.byteslice(0, max).presence
    end

    def parse_optional_time(value)
      return nil if value.blank?
      parsed = Time.zone.parse(value.to_s)
      raise Discourse::InvalidParameters.new(:expires_at) if parsed <= Time.zone.now
      parsed
    rescue ArgumentError, TypeError
      raise Discourse::InvalidParameters.new(:expires_at)
    end

    def event_detail_payload(event)
      report = ProviderReport.find_by(risk_event_id: event.id)
      temporary_block = TemporaryIpBlock.unreleased.where(risk_event_id: event.id).order(id: :desc).first
      notification_suppression = NotificationSuppressionManager.active_for(event)
      {
        event: serialize_event(event, detail: true),
        intelligence: serialize_intelligence(event.ip_intelligence),
        temporary_block: serialize_temporary_block(temporary_block),
        notification_suppression: serialize_notification_suppression(notification_suppression),
        provider_report: report && {
          id: report.id,
          status: report.status,
          provider_status: report.provider_status,
          reported_at: report.reported_at&.iso8601,
        },
        capabilities: {
          user_notes_enabled: SiteSetting.account_security_user_notes_enabled,
          user_note_available: UserNoteWriter.eligible?(event),
          temporary_ip_blocks_enabled: SiteSetting.account_security_temporary_ip_blocks_enabled,
          temporary_block_eligible: TemporaryIpBlockManager.eligible_event?(event),
          staff_notifications_enabled: SiteSetting.account_security_staff_notifications_enabled,
          notification_suppression_eligible:
            SiteSetting.account_security_staff_notifications_enabled &&
              event.user_id.present? &&
              NotificationSuppressionManager.network_key(event).present?,
          abuse_reporting_enabled: SiteSetting.account_security_abuse_reporting_enabled,
          abuse_reportable: AbuseReporter.reportable_event?(event),
        },
        temporary_block_durations: TemporaryIpBlockManager::ALLOWED_DURATIONS,
        notification_suppression_durations: NotificationSuppressionManager::ALLOWED_HOURS,
      }
    end

    def serialize_event(event, detail: false)
      payload = {
        id: event.id,
        event_type: event.event_type,
        severity: event.severity,
        risk_level: event.risk_level,
        evidence_strength: event.evidence_strength,
        ip_address: event.ip_address.to_s,
        status: event.status,
        occurrence_count: event.occurrence_count.to_i,
        created_at: event.created_at&.iso8601,
        last_seen_at: event.last_seen_at&.iso8601,
        reviewed_at: event.reviewed_at&.iso8601,
        resolution_reason: event.resolution_reason,
        user_note_created_at: event.user_note_created_at&.iso8601,
        notified_at: event.notified_at&.iso8601,
        notification_kind: event.notification_kind,
        context: event.context,
        user: event.user && { id: event.user.id, username: event.user.username },
        reviewed_by: event.reviewed_by && { id: event.reviewed_by.id, username: event.reviewed_by.username },
      }
      payload
    end

    def serialize_intelligence(record)
      return nil unless record
      {
        ip_address: record.ip_address.to_s,
        risk_level: record.risk_level,
        evidence_strength: record.evidence_strength,
        primary_score: record.primary_score,
        total_reports: record.total_reports,
        distinct_reporters: record.distinct_reporters,
        last_reported_at: record.last_reported_at&.iso8601,
        usage_type: record.usage_type,
        isp: record.isp,
        domain: record.domain,
        country_code: record.country_code,
        is_tor: record.is_tor,
        local_blacklist_match: record.local_blacklist_match,
        provider_checked_at: record.provider_checked_at&.iso8601,
        next_check_after: record.next_check_after&.iso8601,
        last_seen_at: record.last_seen_at&.iso8601,
      }
    end

    def serialize_temporary_block(block)
      return nil unless block
      {
        id: block.id,
        ip_address: block.ip_address.to_s,
        expires_at: block.expires_at&.iso8601,
        released_at: block.released_at&.iso8601,
        release_reason: block.release_reason,
        active: block.released_at.blank? && block.expires_at.present? && block.expires_at > Time.zone.now,
      }
    end

    def serialize_notification_suppression(record)
      return nil unless record
      {
        id: record.id,
        network_key: record.network_key,
        expires_at: record.expires_at&.iso8601,
        active: record.expires_at.present? && record.expires_at > Time.zone.now,
      }
    end

    def serialize_trusted_network(item)
      {
        id: item.id,
        network: item.network.to_s,
        label: item.label,
        reason: item.reason,
        scope: item.scope,
        expires_at: item.expires_at&.iso8601,
        created_at: item.created_at&.iso8601,
        active: item.expires_at.blank? || item.expires_at > Time.zone.now,
        created_by: item.created_by && { id: item.created_by.id, username: item.created_by.username },
      }
    end

    def recent_users_for(ip)
      key = IpNormalizer.familiarity_network(ip)
      return [] if key.blank?
      UserNetwork.includes(:user).where(network_key: key).order(last_seen_at: :desc).limit(20).filter_map do |row|
        next unless row.user
        { id: row.user.id, username: row.user.username, last_seen_at: row.last_seen_at&.iso8601 }
      end
    end
  end
end
