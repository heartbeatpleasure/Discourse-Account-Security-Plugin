# frozen_string_literal: true
require "rails_helper"

RSpec.describe AccountSecurity::CachePolicy do
  it "refreshes higher-risk addresses more frequently" do
    expect(described_class.ttl_for("low")).to eq(24.hours)
    expect(described_class.ttl_for("observed")).to eq(24.hours)
    expect(described_class.ttl_for("elevated")).to eq(12.hours)
    expect(described_class.ttl_for("high")).to eq(6.hours)
    expect(described_class.ttl_for("critical")).to eq(1.hour)
  end
end
