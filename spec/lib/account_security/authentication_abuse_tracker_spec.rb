# frozen_string_literal: true

require "rails_helper"
require "set"

RSpec.describe AccountSecurity::AuthenticationAbuseTracker do
  class AccountSecurityFakeRedis
    attr_reader :values

    def initialize
      @values = {}
      @ttls = {}
      @sets = Hash.new { |hash, key| hash[key] = Set.new }
    end

    def set(key, value, nx: false, ex: nil)
      return false if nx && @values.key?(key)

      @values[key] = value.to_s
      @ttls[key] = ex.to_i if ex
      true
    end

    def get(key)
      @values[key]
    end

    def incr(key)
      @values[key] = (@values[key].to_i + 1).to_s
      @values[key].to_i
    end

    def expire(key, ttl)
      @ttls[key] = ttl.to_i
      true
    end

    def ttl(key)
      return -2 unless @values.key?(key) || @sets.key?(key)

      @ttls.fetch(key, -1)
    end

    def sadd(key, value)
      @sets[key] << value.to_s
      @values[key] ||= "set"
      true
    end

    def scard(key)
      @sets[key].length
    end

    def flattened_content
      (@values.keys + @values.values + @sets.keys + @sets.values.flat_map(&:to_a)).join(" ")
    end
  end

  let(:redis) { AccountSecurityFakeRedis.new }

  before do
    SiteSetting.account_security_enabled = true
    SiteSetting.account_security_ip_reputation_enabled = true
    SiteSetting.account_security_auth_abuse_detection_enabled = true
    SiteSetting.account_security_failed_login_threshold = 10
    SiteSetting.account_security_failed_login_single_account_threshold = 6
    allow(Discourse).to receive(:redis).and_return(redis)
    allow(Jobs).to receive(:enqueue)
    allow(described_class).to receive(:staff_target?).and_return(false)
  end

  it "enqueues one assessment only after the across-account threshold is reached" do
    9.times { described_class.failed_login(ip: "8.8.8.8") }
    expect(Jobs).not_to have_received(:enqueue)

    described_class.failed_login(ip: "8.8.8.8")
    expect(Jobs).to have_received(:enqueue).once

    3.times { described_class.failed_login(ip: "8.8.8.8") }
    expect(Jobs).to have_received(:enqueue).once
  end

  it "uses the lower single-account threshold without storing the submitted identifier" do
    identifier = "PrivateUser@example.test"
    5.times { described_class.failed_login(ip: "8.8.4.4", login: identifier) }
    expect(Jobs).not_to have_received(:enqueue)

    described_class.failed_login(ip: "8.8.4.4", login: identifier)
    expect(Jobs).to have_received(:enqueue).once
    expect(redis.flattened_content.downcase).not_to include(identifier.downcase)
  end

  it "creates at most one escalation phase within the same counter window" do
    20.times { described_class.failed_login(ip: "1.1.1.1") }
    expect(Jobs).to have_received(:enqueue).twice

    5.times { described_class.failed_login(ip: "1.1.1.1") }
    expect(Jobs).to have_received(:enqueue).twice
  end
end
