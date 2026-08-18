# frozen_string_literal: true

require "rails_helper"

RSpec.describe AccountSecurity::CircuitBreaker do
  before do
    Discourse.redis.del(
      described_class::FAILURE_KEY,
      described_class::OPEN_UNTIL_KEY,
    )
    SiteSetting.account_security_circuit_breaker_failure_count = 2
    SiteSetting.account_security_circuit_breaker_window_minutes = 5
    SiteSetting.account_security_circuit_breaker_open_minutes = 10
  end

  after do
    Discourse.redis.del(
      described_class::FAILURE_KEY,
      described_class::OPEN_UNTIL_KEY,
    )
  end

  it "opens only after the configured number of failures inside the window" do
    expect(described_class.record_failure!).to eq(true)
    expect(described_class.open?).to eq(false)

    expect(described_class.record_failure!).to eq(true)
    expect(described_class.open?).to eq(true)
  end

  it "clears failure history after a successful provider request" do
    described_class.record_failure!
    expect(described_class.failure_entries).not_to be_empty

    expect(described_class.record_success!).to eq(true)
    expect(described_class.failure_entries).to be_empty
  end

  it "does not allow an external reset time to keep the circuit open indefinitely" do
    described_class.open_until!(1.year.from_now)

    open_until = Integer(Discourse.redis.get(described_class::OPEN_UNTIL_KEY), exception: false)
    expect(open_until).to be_present
    expect(open_until).to be <= Time.now.to_i + described_class::MAX_OPEN_SECONDS + 5
  end

  it "recovers safely from malformed Redis failure state" do
    Discourse.redis.set(described_class::FAILURE_KEY, "not-json")

    expect(described_class.failure_entries).to eq([])
    expect { described_class.record_failure! }.not_to raise_error
  end
end
