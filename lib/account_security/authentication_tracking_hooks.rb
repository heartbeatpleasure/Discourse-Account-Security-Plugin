# frozen_string_literal: true

module ::AccountSecurity
  module SessionControllerTracking
    def log_on_user(user, *args, **kwargs)
      result = super
      safely_track do
        BrowserContinuityRecorder.capture_login!(cookies: cookies, user: user)
      end
      result
    end

    protected :log_on_user

    def forgot_password
      safely_track do
        AuthenticationAbuseTracker.password_reset(ip: request.remote_ip, login: params[:login])
      end
      super
    end

    private

    def invalid_credentials
      safely_track do
        AuthenticationAbuseTracker.failed_login(ip: request.remote_ip, login: params[:login])
      end
      super
    end

    def invalid_login_code
      safely_track do
        AuthenticationAbuseTracker.login_code_failure(ip: request.remote_ip)
      end
      super
    end

    def safely_track
      yield
    rescue StandardError => e
      Rails.logger.warn("[account_security] authentication tracking hook failed class=#{e.class}")
      nil
    end
  end

  module UsersControllerRegistrationTracking
    def create
      result = super
      track_rejected_registration if account_security_rejected_registration_response?
      result
    end

    private

    def account_security_rejected_registration_response?
      return false unless AuthenticationAbuseTracker.enabled?
      return false if current_user&.admin? && is_api?
      return false if response.status.to_i >= 500

      body = response.body.to_s
      return false if body.blank? || body.bytesize > 65_536
      parsed = JSON.parse(body)
      parsed.is_a?(Hash) && parsed["success"] == false
    rescue JSON::ParserError, TypeError
      false
    end

    def track_rejected_registration
      AuthenticationAbuseTracker.registration_rejected(ip: request.remote_ip)
    rescue StandardError => e
      Rails.logger.warn("[account_security] rejected-registration tracking hook failed class=#{e.class}")
      nil
    end
  end
end
