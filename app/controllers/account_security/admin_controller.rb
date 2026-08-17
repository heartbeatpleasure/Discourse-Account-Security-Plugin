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

      scope = RiskEvent.includes(:user, :reviewed_by).order(id: :desc)
      scope = scope.where(status: status) if status.present?
      scope = scope.where(severity: severity) if severity.present?
      total = scope.count
      max_page = [(total.to_f / per_page).ceil, 1].max
      page = [page, max_page].min
      items = scope.offset((page - 1) * per_page).limit(per_page)
      render_json_dump(page: page, per_page: per_page, total: total, items: items.map { |event| serialize_event(event) })
    end

    def update_event
      rate_limit!("event-update")
      event = RiskEvent.find(positive_integer_param!(:id))
      status = params.require(:status).to_s
      raise Discourse::InvalidParameters.new(:status) unless RiskEvent::STATUSES.include?(status)
      reason = params[:resolution_reason].to_s.gsub(/[[:cntrl:]]+/, " ").squish.byteslice(0, 240).presence
      event.update!(status: status, reviewed_by_id: current_user.id, reviewed_at: Time.zone.now, resolution_reason: reason)
      render_json_dump(success: true, event: serialize_event(event.reload))
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
      render_json_dump(success: true, item: serialize_trusted_network(item))
    rescue ActiveRecord::RecordNotUnique
      render_json_error(I18n.t("admin.account_security.trusted.duplicate"), status: :unprocessable_entity)
    end

    def delete_trusted_network
      rate_limit!("trusted-delete", 20)
      TrustedNetwork.find(positive_integer_param!(:id)).destroy!
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
      render_json_dump(success: true, circuit_breaker: CircuitBreaker.state)
    end

    def statistics
      period = params[:period].to_i
      period = 30 unless [7, 30, 90, 365].include?(period)
      render_json_dump(Statistics.period_payload(period))
    end

    def report_abuse
      rate_limit!("report-abuse", 5)
      unless params[:confirmed] == true || params[:confirmed].to_s == "true"
        raise Discourse::InvalidParameters.new(:confirmed)
      end
      render_json_dump(AbuseReporter.report_event!(event_id: params.require(:event_id), actor: current_user))
    end

    private

    def disable_response_caching
      response.headers["Cache-Control"] = "no-store, private"
      response.headers["Pragma"] = "no-cache"
    end

    def rate_limit!(suffix, limit = ADMIN_LIMIT, period = 1.minute)
      RateLimiter.new(current_user, "account-security-admin-#{suffix}", limit, period).performed!
    end

    def positive_integer_param!(name)
      positive_integer_value(params[name]) || raise(Discourse::InvalidParameters.new(name))
    end

    def positive_integer_value(value)
      number = Integer(value, exception: false)
      number&.positive? ? number : nil
    end

    def clean_required(value, max, name)
      cleaned = value.to_s.gsub(/[[:cntrl:]]+/, " ").squish.byteslice(0, max)
      raise Discourse::InvalidParameters.new(name) if cleaned.blank?
      cleaned
    end

    def parse_optional_time(value)
      return nil if value.blank?
      parsed = Time.zone.parse(value.to_s)
      raise Discourse::InvalidParameters.new(:expires_at) if parsed <= Time.zone.now
      parsed
    rescue ArgumentError, TypeError
      raise Discourse::InvalidParameters.new(:expires_at)
    end

    def serialize_event(event)
      {
        id: event.id,
        event_type: event.event_type,
        severity: event.severity,
        risk_level: event.risk_level,
        evidence_strength: event.evidence_strength,
        ip_address: event.ip_address.to_s,
        status: event.status,
        context: event.context,
        created_at: event.created_at&.iso8601,
        reviewed_at: event.reviewed_at&.iso8601,
        resolution_reason: event.resolution_reason,
        user: event.user && { id: event.user.id, username: event.user.username },
        reviewed_by: event.reviewed_by && { id: event.reviewed_by.id, username: event.reviewed_by.username },
      }
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
