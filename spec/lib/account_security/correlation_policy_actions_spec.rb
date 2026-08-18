# frozen_string_literal: true

require "rails_helper"

RSpec.describe AccountSecurity::CorrelationPolicyActions do
  fab!(:admin)
  fab!(:user_a) { Fabricate(:user) }
  fab!(:user_b) { Fabricate(:user) }

  let(:correlation) do
    first_id, second_id = [user_a.id, user_b.id].sort
    AccountSecurity::AccountCorrelation.create!(
      user_a_id: first_id,
      user_b_id: second_id,
      score: 82,
      confidence: "very_strong",
      status: "confirmed_duplicate",
      primary_user_id: first_id,
      evidence: {},
      first_seen_at: Time.zone.now,
      last_seen_at: Time.zone.now,
    )
  end

  before do
    stub_const("DiscourseUserNotes", Class.new)
    allow(DiscourseUserNotes).to receive(:add_note)
    allow(AccountSecurity::UserNoteWriter).to receive(:available?).and_return(true)
  end

  it "targets only the non-primary account and records an append-only policy action" do
    primary = User.find(correlation.primary_user_id)
    additional = User.find([correlation.user_a_id, correlation.user_b_id].find { |id| id != primary.id })

    expect(DiscourseUserNotes).to receive(:add_note) do |user, note, actor_id|
      expect(user.id).to eq(additional.id)
      expect(actor_id).to eq(Discourse::SYSTEM_USER_ID)
      expect(note).to include("@#{primary.username}")
      expect(note).not_to match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/)
    end

    expect(
      described_class.add_duplicate_user_note!(correlation: correlation, actor: admin),
    ).to eq(true)

    review = AccountSecurity::CorrelationReview.last
    expect(review.action).to eq("duplicate_user_note_added")
    expect(review.primary_user_id).to eq(primary.id)
    expect(review.from_status).to eq("confirmed_duplicate")
    expect(review.to_status).to eq("confirmed_duplicate")
  end

  it "requires a confirmed duplicate and an explicit account-to-keep choice" do
    correlation.update!(status: "open", primary_user_id: nil)
    expect(
      described_class.duplicate_user_note_eligible?(correlation),
    ).to eq(false)

    correlation.update!(status: "confirmed_duplicate")
    expect(
      described_class.duplicate_user_note_eligible?(correlation),
    ).to eq(false)
  end

  it "deduplicates the note for the current account-to-keep choice" do
    expect(
      described_class.add_duplicate_user_note!(correlation: correlation, actor: admin),
    ).to eq(true)

    expect do
      described_class.add_duplicate_user_note!(correlation: correlation, actor: admin)
    end.to raise_error(AccountSecurity::CorrelationPolicyActions::NotEligible)

    expect(
      AccountSecurity::CorrelationReview.where(
        account_correlation_id: correlation.id,
        action: "duplicate_user_note_added",
      ).count,
    ).to eq(1)
  end

  it "allows a note for the other target if staff later changes the account-to-keep choice" do
    original_primary = correlation.primary_user_id
    other_primary = [correlation.user_a_id, correlation.user_b_id].find { |id| id != original_primary }

    described_class.add_duplicate_user_note!(correlation: correlation, actor: admin)
    correlation.update!(primary_user_id: other_primary)

    expect(
      described_class.duplicate_user_note_eligible?(correlation.reload),
    ).to eq(true)
  end
end
