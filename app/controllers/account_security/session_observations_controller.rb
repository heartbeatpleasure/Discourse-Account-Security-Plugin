# frozen_string_literal: true

module ::AccountSecurity
  class SessionObservationsController < ::ApplicationController
    requires_plugin AccountSecurity::PLUGIN_NAME
    requires_login

    def create
      RateLimiter.new(current_user, "account-security-session-observation", 12, 1.hour).performed!

      unless SessionObservationRecorder.enabled?
        head :no_content
        return
      end

      normalized_ip = IpNormalizer.normalize(request.remote_ip)
      if normalized_ip.blank?
        head :no_content
        return
      end

      browser_token_hash =
        if SiteSetting.account_security_browser_continuity_enabled
          BrowserContinuityRecorder.ensure_token_hash!(cookies: cookies)
        end
      client_signature_hash = SessionSignatureRecorder.signature_for(request.user_agent)

      Jobs.enqueue(
        :account_security_record_session_observation,
        user_id: current_user.id,
        ip: normalized_ip,
        browser_token_hash: browser_token_hash,
        client_signature_hash: client_signature_hash,
        observed_at: Time.zone.now.iso8601,
      )

      head :no_content
    rescue RateLimiter::LimitExceeded
      head :too_many_requests
    rescue StandardError => e
      Rails.logger.warn("[account_security] session observation endpoint failed class=#{e.class}")
      head :no_content
    end
  end
end
