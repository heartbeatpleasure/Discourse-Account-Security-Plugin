# frozen_string_literal: true

require "rails_helper"

RSpec.describe AccountSecurity::CorrelationInvestigationService do
  fab!(:admin)
  fab!(:user_a) { Fabricate(:user) }
  fab!(:user_b) { Fabricate(:user) }

  let(:correlation) do
    first_id, second_id = [user_a.id, user_b.id].sort
    AccountSecurity::AccountCorrelation.create!(
      user_a_id: first_id,
      user_b_id: second_id,
      score: 60,
      confidence: "strong",
      status: "open",
      evidence: {},
      first_seen_at: Time.zone.now,
      last_seen_at: Time.zone.now,
    )
  end

  it "keeps an immutable review trail for status decisions" do
    result = described_class.review!(
      correlation: correlation,
      actor: admin,
      status: "monitor",
      note: "Watch for another independent signal.",
    )

    expect(result.status).to eq("monitor")
    expect(result.reviewed_by_id).to eq(admin.id)
    review = AccountSecurity::CorrelationReview.last
    expect(review.action).to eq("status_changed")
    expect(review.from_status).to eq("open")
    expect(review.to_status).to eq("monitor")
    expect(review.note).to eq("Watch for another independent signal.")
  end

  it "requires a note before a duplicate classification" do
    expect do
      described_class.review!(
        correlation: correlation,
        actor: admin,
        status: "confirmed_duplicate",
        confirmed: true,
      )
    end.to raise_error(Discourse::InvalidParameters)

    expect(correlation.reload.status).to eq("open")
    expect(AccountSecurity::CorrelationReview.count).to eq(0)
  end

  it "allows an optional account-to-keep choice only from the correlated pair" do
    kept = User.find(correlation.user_a_id)
    result = described_class.review!(
      correlation: correlation,
      actor: admin,
      status: "confirmed_duplicate",
      note: "Both accounts are controlled by the same member; keep the older account.",
      primary_user_id: kept.id,
      confirmed: true,
    )

    expect(result.status).to eq("confirmed_duplicate")
    expect(result.primary_user_id).to eq(kept.id)
    expect(AccountSecurity::CorrelationReview.last.primary_user_id).to eq(kept.id)

    outsider = Fabricate(:user)
    expect do
      described_class.review!(
        correlation: result,
        actor: admin,
        status: "confirmed_duplicate",
        primary_user_id: outsider.id,
        confirmed: true,
      )
    end.to raise_error(Discourse::InvalidParameters)
  end

  it "requires a note when reversing a resolved decision" do
    dismissed = described_class.review!(
      correlation: correlation,
      actor: admin,
      status: "dismissed",
      note: "Known legitimate shared environment.",
    )

    expect do
      described_class.review!(
        correlation: dismissed,
        actor: admin,
        status: "open",
      )
    end.to raise_error(Discourse::InvalidParameters)

    expect(dismissed.reload.status).to eq("dismissed")
  end

  it "requires a note when changing the account-to-keep choice" do
    kept = User.find(correlation.user_a_id)
    other = User.find(correlation.user_b_id)
    confirmed = described_class.review!(
      correlation: correlation,
      actor: admin,
      status: "confirmed_duplicate",
      note: "Confirmed duplicate during investigation.",
      primary_user_id: kept.id,
      confirmed: true,
    )

    expect do
      described_class.review!(
        correlation: confirmed,
        actor: admin,
        status: "confirmed_duplicate",
        primary_user_id: other.id,
        confirmed: true,
      )
    end.to raise_error(Discourse::InvalidParameters)

    expect(confirmed.reload.primary_user_id).to eq(kept.id)
  end

  it "supports note-only follow-up without changing the classification" do
    described_class.review!(
      correlation: correlation,
      actor: admin,
      status: "open",
      note: "Member contacted; waiting for clarification.",
    )

    expect(correlation.reload.status).to eq("open")
    expect(AccountSecurity::CorrelationReview.last.action).to eq("note_added")
  end

  it "clears a stale account-to-keep choice when a confirmed duplicate is reopened" do
    kept = User.find(correlation.user_a_id)
    confirmed = described_class.review!(
      correlation: correlation,
      actor: admin,
      status: "confirmed_duplicate",
      note: "Initially confirmed during test review.",
      primary_user_id: kept.id,
      confirmed: true,
    )

    reopened = described_class.review!(
      correlation: confirmed,
      actor: admin,
      status: "open",
      note: "Reopened after new information.",
    )

    expect(reopened.primary_user_id).to be_nil
    expect(reopened.status).to eq("open")
  end
end
