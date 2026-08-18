# frozen_string_literal: true

require "rails_helper"

RSpec.describe AccountSecurity::NetworkContext do
  describe ".maxmind_for_ip" do
    it "uses Discourse local GeoLite data without exposing coordinates" do
      allow(DiscourseIpInfo).to receive(:get).with(
        "8.8.8.8",
        locale: I18n.locale,
        resolve_hostname: false,
      ).and_return(
        asn: 15_169,
        organization: "Example Network",
        country: "United States",
        country_code: "US",
        region: "California",
        city: "Mountain View",
        location: "Mountain View, California, United States",
        latitude: 37.4,
        longitude: -122.1,
        geoname_ids: [1, 2, 3],
      )

      result = described_class.maxmind_for_ip("8.8.8.8")

      expect(result).to include(
        source: "discourse_geolite2",
        asn: 15_169,
        organization: "Example Network",
        country_code: "US",
        location: "Mountain View, California, United States",
        location_is_approximate: true,
      )
      expect(result).not_to have_key(:latitude)
      expect(result).not_to have_key(:longitude)
      expect(result).not_to have_key(:geoname_ids)
    end

    it "does not invoke MaxMind for a non-public address" do
      expect(DiscourseIpInfo).not_to receive(:get)
      expect(described_class.maxmind_for_ip("10.0.3.1")).to eq({})
    end
  end

  describe ".for_ip" do
    it "surfaces country disagreement as context without changing scoring" do
      now = Time.zone.now
      AccountSecurity::IpIntelligence.create!(
        ip_address: "8.8.4.4",
        risk_level: "low",
        evidence_strength: "weak",
        country_code: "US",
        first_seen_at: now,
        last_seen_at: now,
      )
      allow(DiscourseIpInfo).to receive(:get).and_return(
        asn: 64500,
        organization: "Example ASN",
        country: "Netherlands",
        country_code: "NL",
        location: "Amsterdam, North Holland, Netherlands",
      )

      result = described_class.for_ip("8.8.4.4")

      expect(result[:country_mismatch]).to eq(true)
      expect(result[:provider_country_code]).to eq("US")
      expect(result[:maxmind_country_code]).to eq("NL")
      expect(result[:sources]).to contain_exactly("discourse_geolite2", "abuseipdb_cache")
    end
  end
end
