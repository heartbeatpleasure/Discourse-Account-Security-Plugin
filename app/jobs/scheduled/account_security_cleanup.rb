# frozen_string_literal: true
module Jobs
  class AccountSecurityCleanup < ::Jobs::Scheduled
    every 1.day
    BATCH_SIZE = 1000

    def execute(_args)
      now = Time.zone.now
      delete_in_batches(::AccountSecurity::UserNetwork.where("last_seen_at < ?", SiteSetting.account_security_user_network_retention_days.to_i.days.ago))
      delete_in_batches(::AccountSecurity::ProviderReport.where("created_at < ?", 180.days.ago))
      protected_event_ids = ::AccountSecurity::TemporaryIpBlock.unreleased.select(:risk_event_id)
      delete_in_batches(
        ::AccountSecurity::RiskEvent
          .where("created_at < ?", SiteSetting.account_security_event_retention_days.to_i.days.ago)
          .where.not(id: protected_event_ids),
      )
      delete_in_batches(::AccountSecurity::IpIntelligence.where(risk_level: %w[low observed]).where("last_seen_at < ?", SiteSetting.account_security_low_risk_cache_retention_days.to_i.days.ago))
      delete_in_batches(::AccountSecurity::DailyStat.where("stat_date < ?", Date.current - SiteSetting.account_security_stats_retention_days.to_i.days))
      delete_in_batches(::AccountSecurity::TrustedNetwork.where("expires_at IS NOT NULL AND expires_at < ?", now - 180.days))
      delete_in_batches(::AccountSecurity::TemporaryIpBlock.where.not(released_at: nil).where("released_at < ?", now - 180.days))
      delete_in_batches(::AccountSecurity::NotificationSuppression.where("expires_at < ?", now - 180.days))
      session_signature_cutoff =
        SiteSetting.account_security_user_network_retention_days.to_i.clamp(30, 365).days.ago
      delete_in_batches(
        ::AccountSecurity::SessionSignature.where("last_seen_at < ?", session_signature_cutoff),
      )
      correlation_cutoff = SiteSetting.account_security_correlation_retention_days.to_i.clamp(30, 730).days.ago
      delete_in_batches(
        ::AccountSecurity::BrowserContinuity.where("last_seen_at < ?", correlation_cutoff),
      )
      delete_in_batches(
        ::AccountSecurity::AccountCorrelation
          .where.not(status: "confirmed_duplicate")
          .where("last_seen_at < ?", correlation_cutoff),
      )
      delete_in_batches(
        ::AccountSecurity::CorrelationReview.where.not(
          account_correlation_id: ::AccountSecurity::AccountCorrelation.select(:id),
        ),
      )
    end

    private
    def delete_in_batches(scope)
      scope.in_batches(of: BATCH_SIZE).delete_all
    end
  end
end
