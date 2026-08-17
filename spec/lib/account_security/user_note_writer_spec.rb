# frozen_string_literal: true

require "rails_helper"

RSpec.describe AccountSecurity::UserNoteWriter do
  EventStub = Struct.new(:event_type, :severity, :evidence_strength, :occurrence_count)

  it "limits automatic notes to escalated incident patterns" do
    expect(
      described_class.automatic_escalation?(EventStub.new("registration", "critical", "strong", 1)),
    ).to eq(true)
    expect(
      described_class.automatic_escalation?(EventStub.new("login_new_network", "high", "corroborated", 3)),
    ).to eq(true)
    expect(
      described_class.automatic_escalation?(EventStub.new("login_new_network", "high", "strong", 1)),
    ).to eq(false)
    expect(
      described_class.automatic_escalation?(EventStub.new("registration", "critical", "weak", 1)),
    ).to eq(false)
  end
end
