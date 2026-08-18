# frozen_string_literal: true
require "rails_helper"

RSpec.describe AccountSecurity::AdminController do
  fab!(:admin)
  fab!(:user)

  it "keeps all JSON administration endpoints administrator-only" do
    sign_in(user)
    [
      [:get, "/admin/plugins/account-security/overview.json", {}],
      [:get, "/admin/plugins/account-security/events.json", {}],
      [:get, "/admin/plugins/account-security/events/1.json", {}],
      [:post, "/admin/plugins/account-security/events/1/refresh.json", {}],
      [:post, "/admin/plugins/account-security/events/1/user-note.json", { confirmed: true }],
      [:post, "/admin/plugins/account-security/events/1/temporary-block.json", { confirmed: true, duration_minutes: 60 }],
      [:delete, "/admin/plugins/account-security/events/1/temporary-block.json", {}],
      [:post, "/admin/plugins/account-security/events/1/notification-suppression.json", { duration_hours: 24 }],
      [:delete, "/admin/plugins/account-security/events/1/notification-suppression.json", {}],
      [:post, "/admin/plugins/account-security/lookup.json", { account_security_ip: "8.8.8.8" }],
      [:get, "/admin/plugins/account-security/correlations.json", {}],
      [:put, "/admin/plugins/account-security/correlations/1.json", { status: "monitor" }],
      [:post, "/admin/plugins/account-security/correlations/rebuild.json", {}],
      [:get, "/admin/plugins/account-security/trusted-networks.json", {}],
      [:get, "/admin/plugins/account-security/health.json", {}],
      [:post, "/admin/plugins/account-security/health/sync-feed.json", { source: "tor" }],
      [:get, "/admin/plugins/account-security/statistics.json", {}],
      [:post, "/admin/plugins/account-security/report.json", { event_id: 1, confirmed: true }],
    ].each do |method, path, params|
      public_send(method, path, params: params)
      expect(response.status).to eq(404).or eq(403), "expected #{method.upcase} #{path} to be admin-only"
    end
  end

  it "does not serialize the AbuseIPDB API key from Health" do
    SiteSetting.account_security_abuseipdb_api_key = "super-secret-test-key"
    sign_in(admin)
    get "/admin/plugins/account-security/health.json"
    expect(response.status).to eq(200)
    expect(response.headers["Cache-Control"]).to include("no-store")
    expect(response.body).not_to include("super-secret-test-key")
  end

  it "does not permit provider abuse reporting while the setting is disabled" do
    SiteSetting.account_security_abuse_reporting_enabled = false
    sign_in(admin)
    post "/admin/plugins/account-security/report.json", params: { event_id: 1, confirmed: true }
    expect(response.status).to eq(403).or eq(400)
    expect(AccountSecurity::ProviderReport.count).to eq(0)
  end

  it "does not expose a second account-correlation schedule mutation endpoint" do
    sign_in(admin)

    put "/admin/plugins/account-security/correlations/schedule.json",
        params: { frequency: "weekly", time: "11:00", weekday: "monday" }

    expect(response.status).to eq(404)
  end

  it "requires explicit confirmation before classifying a correlation as a confirmed duplicate" do
    SiteSetting.account_security_enabled = true
    SiteSetting.account_security_account_correlation_enabled = true
    first = Fabricate(:user)
    second = Fabricate(:user)
    correlation = AccountSecurity::AccountCorrelation.create!(
      user_a_id: [first.id, second.id].min,
      user_b_id: [first.id, second.id].max,
      score: 80,
      confidence: "very_strong",
      status: "open",
      evidence: {},
      first_seen_at: Time.zone.now,
      last_seen_at: Time.zone.now,
    )

    sign_in(admin)
    put "/admin/plugins/account-security/correlations/#{correlation.id}.json",
        params: { status: "confirmed_duplicate", review_note: "Independent duplicate review." }

    expect(response.status).to eq(400)
    expect(correlation.reload.status).to eq("open")
  end

  it "stores correlation investigation history and an optional account to keep" do
    SiteSetting.account_security_enabled = true
    SiteSetting.account_security_account_correlation_enabled = true
    first = Fabricate(:user)
    second = Fabricate(:user)
    user_a_id, user_b_id = [first.id, second.id].sort
    correlation = AccountSecurity::AccountCorrelation.create!(
      user_a_id: user_a_id,
      user_b_id: user_b_id,
      score: 80,
      confidence: "very_strong",
      status: "open",
      evidence: {},
      first_seen_at: Time.zone.now,
      last_seen_at: Time.zone.now,
    )

    sign_in(admin)
    put "/admin/plugins/account-security/correlations/#{correlation.id}.json",
        params: {
          status: "confirmed_duplicate",
          review_note: "Staff independently confirmed both accounts belong to the same member.",
          primary_user_id: user_a_id,
          confirmed: true,
        }

    expect(response.status).to eq(200)
    correlation.reload
    expect(correlation.status).to eq("confirmed_duplicate")
    expect(correlation.primary_user_id).to eq(user_a_id)
    expect(correlation.reviewed_by_id).to eq(admin.id)
    expect(AccountSecurity::CorrelationReview.where(account_correlation_id: correlation.id).count).to eq(1)
    payload = response.parsed_body["item"]
    expect(payload["review_history"].length).to eq(1)
    expect(payload["primary_user"]["id"]).to eq(user_a_id)
  end


  it "serializes local network context without MaxMind coordinates" do
    sign_in(admin)
    allow(AccountSecurity::AssessmentService).to receive(:call).and_return(
      AccountSecurity::AssessmentService::Result.new(
        success: true,
        reason: "local_context",
        source: "local",
      ),
    )
    allow(AccountSecurity::NetworkContext).to receive(:for_ip).and_return(
      ip_address: "8.8.8.8",
      public: true,
      maxmind: {
        source: "discourse_geolite2",
        asn: 15_169,
        organization: "Example Network",
        country_code: "US",
        location: "United States",
        latitude: 37.4,
        longitude: -122.1,
        geoname_ids: [1, 2, 3],
      },
    )

    post "/admin/plugins/account-security/lookup.json",
         params: { account_security_ip: "8.8.8.8" }

    expect(response.status).to eq(200)
    maxmind = response.parsed_body.dig("network_context", "maxmind")
    expect(maxmind).to include(
      "source" => "discourse_geolite2",
      "asn" => 15_169,
      "organization" => "Example Network",
    )
    expect(maxmind).not_to have_key("latitude")
    expect(maxmind).not_to have_key("longitude")
    expect(maxmind).not_to have_key("geoname_ids")
  end

end
