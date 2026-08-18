# frozen_string_literal: true

require "rails_helper"

RSpec.describe AccountSecurity::SessionControllerTracking do
  let(:base_controller) do
    Class.new do
      attr_accessor :request, :params, :cookies

      def log_on_user(_user, **_kwargs)
        :core_login
      end

      def forgot_password
        :core_forgot_password
      end

      private

      def invalid_credentials
        :core_invalid_credentials
      end

      def invalid_login_code
        :core_invalid_login_code
      end
    end
  end

  let(:controller_class) do
    klass = base_controller
    klass.prepend(described_class)
    klass
  end

  let(:controller) do
    instance = controller_class.new
    instance.request = Struct.new(:remote_ip).new("8.8.8.8")
    instance.params = { login: "user@example.com" }
    instance.cookies = Object.new
    instance
  end

  it "tracks invalid credentials without replacing the core response path" do
    expect(AccountSecurity::AuthenticationAbuseTracker).to receive(:failed_login).with(
      ip: "8.8.8.8",
      login: "user@example.com",
    )

    expect(controller.send(:invalid_credentials)).to eq(:core_invalid_credentials)
  end

  it "tracks invalid login codes without replacing the core response path" do
    expect(AccountSecurity::AuthenticationAbuseTracker).to receive(:login_code_failure).with(
      ip: "8.8.8.8",
    )

    expect(controller.send(:invalid_login_code)).to eq(:core_invalid_login_code)
  end

  it "tracks password reset requests and then preserves core handling" do
    expect(AccountSecurity::AuthenticationAbuseTracker).to receive(:password_reset).with(
      ip: "8.8.8.8",
      login: "user@example.com",
    )

    expect(controller.forgot_password).to eq(:core_forgot_password)
  end

  it "records browser continuity only after the core login succeeds" do
    user = Fabricate(:user)
    expect(AccountSecurity::BrowserContinuityRecorder).to receive(:capture_login!).with(
      cookies: controller.cookies,
      user: user,
    )

    expect(controller.send(:log_on_user, user, replay_anonymous_action: true)).to eq(:core_login)
  end
end
