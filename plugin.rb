# frozen_string_literal: true

# name: Discourse-Account-Security-Plugin
# about: Adds provider-neutral account security intelligence and abuse-risk monitoring to Discourse.
# version: 0.10.0
# authors: Chris

add_admin_route "admin.account_security.title", "accountSecurity"
enabled_site_setting :account_security_enabled

module ::AccountSecurity
  PLUGIN_NAME = "Discourse-Account-Security-Plugin"
  PLUGIN_VERSION = "0.10.0"
  STORE_NAMESPACE = "account_security"
end

after_initialize do
  begin
    Rails.application.config.filter_parameters |= [
      :account_security_abuseipdb_api_key,
      :account_security_ip,
      :account_security_network,
    ]
  rescue StandardError
    # Do not make plugin boot depend on filter-parameter availability.
  end

  %w[
    app/models/account_security/ip_intelligence.rb
    app/models/account_security/risk_event.rb
    app/models/account_security/user_network.rb
    app/models/account_security/trusted_network.rb
    app/models/account_security/provider_usage.rb
    app/models/account_security/feed_entry.rb
    app/models/account_security/feed_snapshot.rb
    app/models/account_security/provider_report.rb
    app/models/account_security/daily_stat.rb
    app/models/account_security/temporary_ip_block.rb
    app/models/account_security/notification_suppression.rb
    app/models/account_security/session_signature.rb
    app/models/account_security/browser_continuity.rb
    app/models/account_security/account_correlation.rb
    app/models/account_security/correlation_review.rb
    app/controllers/account_security/admin_controller.rb
  ].each { |path| require_dependency File.expand_path(path, __dir__) }

  %w[
    lib/account_security/ip_normalizer.rb
    lib/account_security/risk_policy.rb
    lib/account_security/cache_policy.rb
    lib/account_security/statistics.rb
    lib/account_security/circuit_breaker.rb
    lib/account_security/quota_manager.rb
    lib/account_security/providers/abuse_ip_db.rb
    lib/account_security/feeds/tor_exit_list.rb
    lib/account_security/feeds/abuse_ip_db_blacklist.rb
    lib/account_security/network_familiarity.rb
    lib/account_security/session_signature_recorder.rb
    lib/account_security/browser_continuity_recorder.rb
    lib/account_security/core_ip_evidence.rb
    lib/account_security/temporal_correlation_evidence.rb
    lib/account_security/account_correlation_policy.rb
    lib/account_security/account_correlation_service.rb
    lib/account_security/correlation_investigation_service.rb
    lib/account_security/account_correlation_scan_context.rb
    lib/account_security/account_correlation_scanner.rb
    lib/account_security/account_correlation_scheduler.rb
    lib/account_security/authentication_abuse_tracker.rb
    lib/account_security/authentication_tracking_hooks.rb
    lib/account_security/staff_audit.rb
    lib/account_security/user_note_writer.rb
    lib/account_security/temporary_ip_block_manager.rb
    lib/account_security/notification_suppression_manager.rb
    lib/account_security/incident_notifier.rb
    lib/account_security/correlation_incident_notifier.rb
    lib/account_security/event_recorder.rb
    lib/account_security/assessment_service.rb
    lib/account_security/health.rb
    lib/account_security/abuse_reporter.rb
    app/jobs/regular/account_security_check_ip.rb
    app/jobs/regular/account_security_process_auth_abuse_cluster.rb
    app/jobs/regular/account_security_rebuild_correlations.rb
    app/jobs/regular/account_security_record_browser_continuity.rb
    app/jobs/scheduled/account_security_auto_correlation_scan.rb
    app/jobs/scheduled/account_security_sync_tor_exit_list.rb
    app/jobs/scheduled/account_security_sync_abuseipdb_blacklist.rb
    app/jobs/scheduled/account_security_expire_temporary_ip_blocks.rb
    app/jobs/scheduled/account_security_cleanup.rb
    app/services/problem_check/account_security_operational_health.rb
  ].each { |path| require_relative path }

  register_problem_check ProblemCheck::AccountSecurityOperationalHealth

  require_dependency "session_controller"
  require_dependency "users_controller"
  require_dependency "user_ip_address_history"
  require_dependency "user_auth_token_log"
  SessionController.prepend(::AccountSecurity::SessionControllerTracking) unless SessionController < ::AccountSecurity::SessionControllerTracking
  UsersController.prepend(::AccountSecurity::UsersControllerRegistrationTracking) unless UsersController < ::AccountSecurity::UsersControllerRegistrationTracking

  on(:user_created) do |user|
    next unless SiteSetting.account_security_enabled
    next if user.blank? || user.staged?

    reputation_enabled =
      SiteSetting.account_security_ip_reputation_enabled &&
        SiteSetting.account_security_registration_checks_enabled
    correlation_enabled = SiteSetting.account_security_account_correlation_enabled
    next unless reputation_enabled || correlation_enabled

    ip = user.registration_ip_address || user.ip_address
    normalized = ::AccountSecurity::IpNormalizer.normalize(ip)
    public_ip = ::AccountSecurity::IpNormalizer.normalize_public(normalized)
    next if normalized.blank? || (!correlation_enabled && public_ip.blank?)

    token = UserAuthToken.where(user_id: user.id).order(id: :desc).first if correlation_enabled
    Jobs.enqueue(
      :account_security_check_ip,
      ip: normalized,
      user_id: user.id,
      trigger: "registration",
      auth_token_id: token&.id,
    )
  end

  on(:user_logged_in) do |user|
    next unless SiteSetting.account_security_enabled
    next if user.blank? || user.staged?

    reputation_enabled =
      SiteSetting.account_security_ip_reputation_enabled &&
        SiteSetting.account_security_login_checks_enabled
    correlation_enabled = SiteSetting.account_security_account_correlation_enabled
    next unless reputation_enabled || correlation_enabled

    token = UserAuthToken.where(user_id: user.id).order(id: :desc).first
    ip = token&.client_ip || user.ip_address
    normalized = ::AccountSecurity::IpNormalizer.normalize(ip)
    public_ip = ::AccountSecurity::IpNormalizer.normalize_public(normalized)
    next if normalized.blank? || (!correlation_enabled && public_ip.blank?)

    Jobs.enqueue(
      :account_security_check_ip,
      ip: normalized,
      user_id: user.id,
      trigger: user.staff? ? "staff_login" : "login",
      auth_token_id: token&.id,
    )
  end

  on(:user_destroyed) do |user|
    next if user.blank?

    ::AccountSecurity::UserNetwork.where(user_id: user.id).delete_all
    ::AccountSecurity::RiskEvent.where(user_id: user.id).update_all(user_id: nil)
    ::AccountSecurity::RiskEvent.where(reviewed_by_id: user.id).update_all(reviewed_by_id: nil)
    ::AccountSecurity::TemporaryIpBlock.where(created_by_id: user.id).update_all(created_by_id: nil)
    ::AccountSecurity::NotificationSuppression.where(user_id: user.id).delete_all
    ::AccountSecurity::NotificationSuppression.where(created_by_id: user.id).update_all(created_by_id: nil)
    ::AccountSecurity::SessionSignature.where(user_id: user.id).delete_all
    ::AccountSecurity::BrowserContinuity.where(user_id: user.id).delete_all
    correlation_ids = ::AccountSecurity::AccountCorrelation.where(user_a_id: user.id).or(::AccountSecurity::AccountCorrelation.where(user_b_id: user.id)).pluck(:id)
    ::AccountSecurity::CorrelationReview.where(account_correlation_id: correlation_ids).delete_all if correlation_ids.any?
    ::AccountSecurity::CorrelationReview.where(actor_user_id: user.id).update_all(actor_user_id: nil)
    ::AccountSecurity::CorrelationReview.where(primary_user_id: user.id).update_all(primary_user_id: nil)
    ::AccountSecurity::AccountCorrelation.where(id: correlation_ids).delete_all if correlation_ids.any?
    ::AccountSecurity::AccountCorrelation.where(reviewed_by_id: user.id).update_all(reviewed_by_id: nil)
    ::AccountSecurity::AccountCorrelation.where(primary_user_id: user.id).update_all(primary_user_id: nil)
  end

  on(:user_anonymized) do |args|
    user = args.is_a?(Hash) ? args[:user] : nil
    opts = args.is_a?(Hash) ? args[:opts] : nil
    next unless user

    # Correlation identifiers no longer serve a legitimate purpose once the
    # account itself is anonymized, regardless of whether core IP anonymization
    # was requested as part of the same operation.
    ::AccountSecurity::BrowserContinuity.where(user_id: user.id).delete_all
    correlation_ids = ::AccountSecurity::AccountCorrelation.where(user_a_id: user.id).or(::AccountSecurity::AccountCorrelation.where(user_b_id: user.id)).pluck(:id)
    ::AccountSecurity::CorrelationReview.where(account_correlation_id: correlation_ids).delete_all if correlation_ids.any?
    ::AccountSecurity::CorrelationReview.where(actor_user_id: user.id).update_all(actor_user_id: nil)
    ::AccountSecurity::CorrelationReview.where(primary_user_id: user.id).update_all(primary_user_id: nil)
    ::AccountSecurity::AccountCorrelation.where(id: correlation_ids).delete_all if correlation_ids.any?
    ::AccountSecurity::AccountCorrelation.where(reviewed_by_id: user.id).update_all(reviewed_by_id: nil)
    ::AccountSecurity::AccountCorrelation.where(primary_user_id: user.id).update_all(primary_user_id: nil)

    next unless opts&.key?(:anonymize_ip)

    ::AccountSecurity::UserNetwork.where(user_id: user.id).delete_all
    ::AccountSecurity::NotificationSuppression.where(user_id: user.id).delete_all
    ::AccountSecurity::SessionSignature.where(user_id: user.id).delete_all
  end

  Discourse::Application.routes.append do
    %w[
      account-security
      account-security-events
      account-security-intelligence
      account-security-correlations
      account-security-trusted-networks
      account-security-health
      account-security-statistics
    ].each do |path|
      get "/admin/plugins/#{path}" => "admin/plugins#index", constraints: AdminConstraint.new
    end
    get "/admin/plugins/account-security-events/:id" => "admin/plugins#index",
        constraints: AdminConstraint.new

    get "/admin/plugins/account-security/overview.json" => "account_security/admin#overview",
        defaults: { format: :json }, constraints: AdminConstraint.new
    get "/admin/plugins/account-security/events.json" => "account_security/admin#events",
        defaults: { format: :json }, constraints: AdminConstraint.new
    get "/admin/plugins/account-security/events/:id.json" => "account_security/admin#show_event",
        defaults: { format: :json }, constraints: AdminConstraint.new
    put "/admin/plugins/account-security/events/:id.json" => "account_security/admin#update_event",
        defaults: { format: :json }, constraints: AdminConstraint.new
    post "/admin/plugins/account-security/events/:id/refresh.json" => "account_security/admin#refresh_event",
         defaults: { format: :json }, constraints: AdminConstraint.new
    post "/admin/plugins/account-security/events/:id/user-note.json" => "account_security/admin#add_user_note",
         defaults: { format: :json }, constraints: AdminConstraint.new
    post "/admin/plugins/account-security/events/:id/temporary-block.json" => "account_security/admin#create_temporary_block",
         defaults: { format: :json }, constraints: AdminConstraint.new
    delete "/admin/plugins/account-security/events/:id/temporary-block.json" => "account_security/admin#release_temporary_block",
           defaults: { format: :json }, constraints: AdminConstraint.new
    post "/admin/plugins/account-security/events/:id/notification-suppression.json" => "account_security/admin#create_notification_suppression",
         defaults: { format: :json }, constraints: AdminConstraint.new
    delete "/admin/plugins/account-security/events/:id/notification-suppression.json" => "account_security/admin#release_notification_suppression",
           defaults: { format: :json }, constraints: AdminConstraint.new
    post "/admin/plugins/account-security/lookup.json" => "account_security/admin#lookup",
         defaults: { format: :json }, constraints: AdminConstraint.new
    get "/admin/plugins/account-security/correlations.json" => "account_security/admin#correlations",
        defaults: { format: :json }, constraints: AdminConstraint.new
    put "/admin/plugins/account-security/correlations/:id.json" => "account_security/admin#update_correlation",
        defaults: { format: :json }, constraints: AdminConstraint.new
    post "/admin/plugins/account-security/correlations/rebuild.json" => "account_security/admin#rebuild_correlations",
         defaults: { format: :json }, constraints: AdminConstraint.new
    get "/admin/plugins/account-security/trusted-networks.json" => "account_security/admin#trusted_networks",
        defaults: { format: :json }, constraints: AdminConstraint.new
    post "/admin/plugins/account-security/trusted-networks.json" => "account_security/admin#create_trusted_network",
         defaults: { format: :json }, constraints: AdminConstraint.new
    delete "/admin/plugins/account-security/trusted-networks/:id.json" => "account_security/admin#delete_trusted_network",
           defaults: { format: :json }, constraints: AdminConstraint.new
    get "/admin/plugins/account-security/health.json" => "account_security/admin#health",
        defaults: { format: :json }, constraints: AdminConstraint.new
    post "/admin/plugins/account-security/health/test.json" => "account_security/admin#health_test",
         defaults: { format: :json }, constraints: AdminConstraint.new
    post "/admin/plugins/account-security/health/reset-circuit.json" => "account_security/admin#reset_circuit",
         defaults: { format: :json }, constraints: AdminConstraint.new
    post "/admin/plugins/account-security/health/sync-feed.json" => "account_security/admin#sync_feed",
         defaults: { format: :json }, constraints: AdminConstraint.new
    get "/admin/plugins/account-security/statistics.json" => "account_security/admin#statistics",
        defaults: { format: :json }, constraints: AdminConstraint.new
    post "/admin/plugins/account-security/report.json" => "account_security/admin#report_abuse",
         defaults: { format: :json }, constraints: AdminConstraint.new
  end
end
