# frozen_string_literal: true

# name: Discourse-Account-Security-Plugin
# about: Adds provider-neutral account security intelligence and abuse-risk monitoring to Discourse.
# version: 0.2.1
# authors: Chris

add_admin_route "admin.account_security.title", "accountSecurity"
enabled_site_setting :account_security_enabled

module ::AccountSecurity
  PLUGIN_NAME = "Discourse-Account-Security-Plugin"
  PLUGIN_VERSION = "0.2.1"
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
    lib/account_security/staff_audit.rb
    lib/account_security/user_note_writer.rb
    lib/account_security/temporary_ip_block_manager.rb
    lib/account_security/event_recorder.rb
    lib/account_security/assessment_service.rb
    lib/account_security/health.rb
    lib/account_security/abuse_reporter.rb
    app/jobs/regular/account_security_check_ip.rb
    app/jobs/scheduled/account_security_sync_tor_exit_list.rb
    app/jobs/scheduled/account_security_sync_abuseipdb_blacklist.rb
    app/jobs/scheduled/account_security_expire_temporary_ip_blocks.rb
    app/jobs/scheduled/account_security_cleanup.rb
    app/services/problem_check/account_security_operational_health.rb
  ].each { |path| require_relative path }

  register_problem_check ProblemCheck::AccountSecurityOperationalHealth

  on(:user_created) do |user|
    next unless SiteSetting.account_security_enabled
    next unless SiteSetting.account_security_ip_reputation_enabled
    next unless SiteSetting.account_security_registration_checks_enabled
    next if user.blank? || user.staged?

    ip = user.registration_ip_address || user.ip_address
    normalized = ::AccountSecurity::IpNormalizer.normalize_public(ip)
    next if normalized.blank?

    Jobs.enqueue(
      :account_security_check_ip,
      ip: normalized,
      user_id: user.id,
      trigger: "registration",
    )
  end

  on(:user_logged_in) do |user|
    next unless SiteSetting.account_security_enabled
    next unless SiteSetting.account_security_ip_reputation_enabled
    next unless SiteSetting.account_security_login_checks_enabled
    next if user.blank? || user.staged?

    token = UserAuthToken.where(user_id: user.id).order(id: :desc).first
    ip = token&.client_ip || user.ip_address
    normalized = ::AccountSecurity::IpNormalizer.normalize_public(ip)
    next if normalized.blank?

    Jobs.enqueue(
      :account_security_check_ip,
      ip: normalized,
      user_id: user.id,
      trigger: user.staff? ? "staff_login" : "login",
    )
  end

  on(:user_destroyed) do |user|
    next if user.blank?

    ::AccountSecurity::UserNetwork.where(user_id: user.id).delete_all
    ::AccountSecurity::RiskEvent.where(user_id: user.id).update_all(user_id: nil)
    ::AccountSecurity::RiskEvent.where(reviewed_by_id: user.id).update_all(reviewed_by_id: nil)
    ::AccountSecurity::TemporaryIpBlock.where(created_by_id: user.id).update_all(created_by_id: nil)
  end

  on(:user_anonymized) do |args|
    user = args.is_a?(Hash) ? args[:user] : nil
    opts = args.is_a?(Hash) ? args[:opts] : nil
    next unless user && opts&.key?(:anonymize_ip)

    ::AccountSecurity::UserNetwork.where(user_id: user.id).delete_all
  end

  Discourse::Application.routes.append do
    %w[
      account-security
      account-security-events
      account-security-intelligence
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
    post "/admin/plugins/account-security/lookup.json" => "account_security/admin#lookup",
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
    get "/admin/plugins/account-security/statistics.json" => "account_security/admin#statistics",
        defaults: { format: :json }, constraints: AdminConstraint.new
    post "/admin/plugins/account-security/report.json" => "account_security/admin#report_abuse",
         defaults: { format: :json }, constraints: AdminConstraint.new
  end
end
