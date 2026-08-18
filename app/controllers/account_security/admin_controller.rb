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
        open_correlations: AccountCorrelation.unresolved.count,
        strong_correlations: AccountCorrelation.unresolved.where(confidence: %w[strong very_strong]).count,
        correlation_enabled: SiteSetting.account_security_account_correlation_enabled,
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

    def correlations
      page = positive_integer_value(params[:page]) || 1
      per_page = 50
      status = params[:status].to_s
      confidence = params[:confidence].to_s
      search = clean_optional(params[:search], 60)

      raise Discourse::InvalidParameters.new(:status) if status.present? && !AccountCorrelation::STATUSES.include?(status)
      if confidence.present? && !AccountCorrelation::CONFIDENCES.include?(confidence)
        raise Discourse::InvalidParameters.new(:confidence)
      end

      scope = AccountCorrelation.includes(:user_a, :user_b, :reviewed_by).order(score: :desc, last_seen_at: :desc, id: :desc)
      scope = scope.where(status: status) if status.present?
      scope = scope.where(confidence: confidence) if confidence.present?
      if search.present?
        pattern = "%#{ActiveRecord::Base.sanitize_sql_like(search.downcase)}%"
        ids = User.where("username_lower LIKE ?", pattern).limit(100).pluck(:id)
        scope = scope.where("user_a_id IN (:ids) OR user_b_id IN (:ids)", ids: ids.presence || [-1])
      end

      total = scope.count
      scoring_refresh_required = AccountCorrelation.where(
        "COALESCE((evidence ->> 'scoring_version')::integer, 0) < ?",
        AccountCorrelationPolicy::SCORING_VERSION,
      ).exists?
      max_page = [(total.to_f / per_page).ceil, 1].max
      page = [page, max_page].min
      items = scope.offset((page - 1) * per_page).limit(per_page)

      render_json_dump(
        enabled: SiteSetting.account_security_account_correlation_enabled,
        page: page,
        per_page: per_page,
        total: total,
        open_count: AccountCorrelation.where(status: "open").count,
        strong_open_count: AccountCorrelation.where(status: %w[open monitor], confidence: %w[strong very_strong]).count,
        scoring_refresh_required: scoring_refresh_required,
        scan: AccountCorrelationScanner.status,
        schedule: AccountCorrelationScheduler.schedule_status.slice(:enabled, :next_run_at),
        items: items.map { |item| serialize_correlation(item) },
      )
    end


    def update_correlation
      rate_limit!("correlation-update", 20)
      correlation = find_correlation!
      status = params.require(:status).to_s
      raise Discourse::InvalidParameters.new(:status) unless AccountCorrelation::STATUSES.include?(status)
      require_confirmation! if status == "confirmed_duplicate"

      reason = clean_optional(params[:resolution_reason], 240)
      correlation.update!(
        status: status,
        reviewed_by_id: current_user.id,
        reviewed_at: Time.zone.now,
        resolution_reason: reason,
      )
      StaffAudit.log!(
        actor: current_user,
        action: "account_correlation_review_changed",
        details: { correlation_id: correlation.id, status: status },
      )
      render_json_dump(success: true, item: serialize_correlation(correlation.reload))
    end

    def rebuild_correlations
      rate_limit!("correlation-rebuild", 1, 30.minutes)
      unless SiteSetting.account_security_account_correlation_enabled
        return render_json_error(I18n.t("admin.account_security.correlations.disabled"), status: :unprocessable_entity)
      end

      result = AccountCorrelationScanner.enqueue!(requested_by_id: current_user.id, source: "manual")
      if result[:success]
        StaffAudit.log!(actor: current_user, action: "account_correlation_scan_started")
        render_json_dump(result)
      else
        render json: result, status: :unprocessable_entity
      end
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
    def find_correlation!
      AccountCorrelation.includes(:user_a, :user_b, :reviewed_by).find(positive_integer_param!(:id))
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

    def serialize_correlation(item)
      evidence = item.evidence.is_a?(Hash) ? item.evidence : {}
      {
        id: item.id,
        score: item.score.to_i,
        confidence: item.confidence,
        status: item.status,
        first_seen_at: item.first_seen_at&.iso8601,
        last_seen_at: item.last_seen_at&.iso8601,
        reviewed_at: item.reviewed_at&.iso8601,
        resolution_reason: item.resolution_reason,
        user_a: serialize_correlation_user(item.user_a),
        user_b: serialize_correlation_user(item.user_b),
        reviewed_by: item.reviewed_by && { id: item.reviewed_by.id, username: item.reviewed_by.username },
        evidence: {
          scoring_version: evidence["scoring_version"].to_i,
          shared_registration_ip: evidence["shared_registration_ip"] == true,
          shared_registration_ip_public: evidence["shared_registration_ip_public"] == true,
          shared_registration_ip_nonpublic: evidence["shared_registration_ip_nonpublic"] == true,
          same_current_ip: evidence["same_current_ip"] == true,
          same_current_ip_public: evidence["same_current_ip_public"] == true,
          same_current_ip_nonpublic: evidence["same_current_ip_nonpublic"] == true,
          shared_exact_ip_count: evidence["shared_exact_ip_count"].to_i,
          shared_public_ip_count: evidence["shared_public_ip_count"].to_i,
          untrusted_public_ip_count: evidence["untrusted_public_ip_count"].to_i,
          shared_nonpublic_ip_count: evidence["shared_nonpublic_ip_count"].to_i,
          shared_history_ip_count: evidence["shared_history_ip_count"].to_i,
          shared_core_history_ip_count: evidence["shared_core_history_ip_count"].to_i,
          shared_auth_ip_count: evidence["shared_auth_ip_count"].to_i,
          trusted_shared_ip_count: evidence["trusted_shared_ip_count"].to_i,
          tor_shared_ip_count: evidence["tor_shared_ip_count"].to_i,
          hosting_shared_ip_count: evidence["hosting_shared_ip_count"].to_i,
          mobile_shared_ip_count: evidence["mobile_shared_ip_count"].to_i,
          local_blacklist_shared_ip_count: evidence["local_blacklist_shared_ip_count"].to_i,
          shared_ip_details: serialize_shared_ip_details(evidence["shared_ip_details"]),
          shared_network_count: evidence["shared_network_count"].to_i,
          shared_networks: Array(evidence["shared_networks"]).map(&:to_s).first(AccountCorrelationService::MAX_SHARED_NETWORKS_IN_PAYLOAD),
          shared_session_signature_count: evidence["shared_session_signature_count"].to_i,
          browser_continuity_count: evidence["browser_continuity_count"].to_i,
          max_browser_continuity_users: evidence["max_browser_continuity_users"].to_i,
          browser_continuity_positive_only: evidence["browser_continuity_positive_only"] == true,
          registration_delta_minutes: evidence["registration_delta_minutes"].to_i,
          max_shared_network_users: evidence["max_shared_network_users"].to_i,
          max_shared_exact_ip_users: evidence["max_shared_exact_ip_users"].to_i,
          large_shared_network: evidence["large_shared_network"] == true,
          score_breakdown: serialize_score_breakdown(evidence["score_breakdown"]),
          raw_user_agent_stored: false,
        },
      }
    end

    def serialize_correlation_user(user)
      return nil if user.blank?
      {
        id: user.id,
        username: user.username,
        created_at: user.created_at&.iso8601,
        last_seen_at: user.last_seen_at&.iso8601,
        active: user.active? == true,
        suspended: user.suspended? == true,
      }
    end

    def serialize_shared_ip_details(value)
      Array(value).first(AccountCorrelationService::MAX_SHARED_IPS_IN_PAYLOAD).filter_map do |raw|
        next unless raw.is_a?(Hash)
        ip = IpNormalizer.normalize(raw["ip_address"])
        next if ip.blank?

        {
          ip_address: ip,
          sources_a: Array(raw["sources_a"]).map(&:to_s) & CoreIpEvidence::SOURCES,
          sources_b: Array(raw["sources_b"]).map(&:to_s) & CoreIpEvidence::SOURCES,
          user_count: raw["user_count"].to_i,
          public: raw["public"] == true,
          trusted: raw["trusted"] == true,
          tor: raw["tor"] == true,
          local_blacklist: raw["local_blacklist"] == true,
          usage_type: clean_optional(raw["usage_type"], 80),
          isp: clean_optional(raw["isp"], 160),
          hosting: raw["hosting"] == true,
          mobile: raw["mobile"] == true,
        }
      end
    end

    def serialize_score_breakdown(value)
      Array(value).first(20).filter_map do |raw|
        next unless raw.is_a?(Hash)
        key = raw["key"].to_s
        next unless key.match?(/\A[a-z0-9_]{1,40}\z/)
        { key: key, points: raw["points"].to_i, count: raw["count"].to_i }
      end
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
