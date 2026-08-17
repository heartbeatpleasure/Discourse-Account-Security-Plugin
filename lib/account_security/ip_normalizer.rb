# frozen_string_literal: true
require "ipaddr"

module ::AccountSecurity
  module IpNormalizer
    module_function

    NONPUBLIC_RANGES = [
      IPAddr.new("0.0.0.0/8"),
      IPAddr.new("10.0.0.0/8"),
      IPAddr.new("100.64.0.0/10"),
      IPAddr.new("127.0.0.0/8"),
      IPAddr.new("169.254.0.0/16"),
      IPAddr.new("172.16.0.0/12"),
      IPAddr.new("192.0.0.0/24"),
      IPAddr.new("192.0.2.0/24"),
      IPAddr.new("192.88.99.0/24"),
      IPAddr.new("192.168.0.0/16"),
      IPAddr.new("198.18.0.0/15"),
      IPAddr.new("198.51.100.0/24"),
      IPAddr.new("203.0.113.0/24"),
      IPAddr.new("224.0.0.0/4"),
      IPAddr.new("240.0.0.0/4"),
      IPAddr.new("::/128"),
      IPAddr.new("::1/128"),
      IPAddr.new("100::/64"),
      IPAddr.new("2001:db8::/32"),
      IPAddr.new("fc00::/7"),
      IPAddr.new("fe80::/10"),
      IPAddr.new("ff00::/8"),
    ].freeze

    def normalize(value)
      text = value.to_s.strip
      return nil if text.blank? || text.bytesize > 64 || text.include?("/")

      ip = IPAddr.new(text)
      ip = IPAddr.new(ip.native.to_s) if ip.ipv4_mapped?
      ip.to_s
    rescue IPAddr::InvalidAddressError, IPAddr::AddressFamilyError
      nil
    end

    def normalize_public(value)
      normalized = normalize(value)
      return nil if normalized.blank?

      ip = IPAddr.new(normalized)
      public?(ip) ? normalized : nil
    rescue IPAddr::InvalidAddressError
      nil
    end

    def public?(ip)
      !NONPUBLIC_RANGES.any? { |range| range.family == ip.family && range.include?(ip) }
    end

    def family(value)
      ip = IPAddr.new(normalize(value).to_s)
      ip.ipv4? ? "ipv4" : "ipv6"
    rescue IPAddr::InvalidAddressError
      nil
    end

    def familiarity_network(value)
      normalized = normalize(value)
      return nil if normalized.blank?

      ip = IPAddr.new(normalized)
      prefix = ip.ipv4? ? 32 : SiteSetting.account_security_ipv6_familiarity_prefix.to_i.clamp(48, 128)
      IPAddr.new("#{ip}/#{prefix}").to_range.first.to_s + "/#{prefix}"
    rescue IPAddr::InvalidAddressError
      nil
    end

    def parse_network(value)
      text = value.to_s.strip
      return nil if text.blank? || text.bytesize > 80

      ip = IPAddr.new(text)
      prefix = text.include?("/") ? Integer(text.split("/", 2).last, exception: false) : (ip.ipv4? ? 32 : 128)
      return nil if prefix.nil?
      return nil if ip.ipv4? && !prefix.between?(0, 32)
      return nil if ip.ipv6? && !prefix.between?(0, 128)

      canonical = IPAddr.new("#{ip}/#{prefix}").to_range.first.to_s
      "#{canonical}/#{prefix}"
    rescue IPAddr::InvalidAddressError
      nil
    end

    def broad_network?(network)
      parsed = parse_network(network)
      return true if parsed.blank?
      prefix = parsed.split("/", 2).last.to_i
      ip = IPAddr.new(parsed.split("/", 2).first)
      ip.ipv4? ? prefix < 16 : prefix < 48
    end

    def mask(value)
      normalized = normalize(value)
      return "unknown" if normalized.blank?
      ip = IPAddr.new(normalized)
      if ip.ipv4?
        parts = normalized.split(".")
        "#{parts[0]}.#{parts[1]}.#{parts[2]}.x"
      else
        network = IPAddr.new("#{normalized}/64").to_range.first.to_s
        "#{network}/64"
      end
    rescue IPAddr::InvalidAddressError
      "unknown"
    end
  end
end
