# frozen_string_literal: true
require "rails_helper"

RSpec.describe AccountSecurity::IpNormalizer do
  it "canonicalizes public IPv4 and IPv6 addresses" do
    expect(described_class.normalize_public(" 8.8.8.8 ")).to eq("8.8.8.8")
    expect(described_class.normalize_public("2001:4860:4860::8888")).to eq("2001:4860:4860::8888")
  end

  it "normalizes IPv4-mapped IPv6 to IPv4" do
    expect(described_class.normalize("::ffff:8.8.8.8")).to eq("8.8.8.8")
  end

  it "excludes private, carrier NAT, documentation and multicast addresses" do
    %w[10.0.0.1 100.64.0.1 192.0.2.1 224.0.0.1 2001:db8::1 fe80::1].each do |ip|
      expect(described_class.normalize_public(ip)).to be_nil
    end
  end

  it "uses /64 as the default IPv6 familiarity key" do
    SiteSetting.account_security_ipv6_familiarity_prefix = 64
    expect(described_class.familiarity_network("2001:4860:1234:5678:abcd::1")).to eq("2001:4860:1234:5678::/64")
  end
end
