import { fn } from "@ember/helper";
import { action } from "@ember/object";
import Component from "@glimmer/component";
import { tracked } from "@glimmer/tracking";
import { on } from "@ember/modifier";
import { eq } from "discourse/truth-helpers";
import dIcon from "discourse/ui-kit/helpers/d-icon";
import { i18n } from "discourse-i18n";

const NOTE_REQUIRED_STATUSES = new Set([
  "expected_shared_network",
  "confirmed_duplicate",
  "dismissed",
]);

export default class AccountSecurityCorrelationPair extends Component {
  @tracked selectedStatus;
  @tracked reviewNote = "";
  @tracked primaryUserId = "";
  @tracked isSaving = false;

  constructor(owner, args) {
    super(owner, args);
    this.selectedStatus = args.item.status;
    this.primaryUserId = args.item.primary_user?.id?.toString() || "";
  }

  get elementId() {
    return `correlation-${this.args.item.id}`;
  }

  get isConfirmedDuplicate() {
    return this.selectedStatus === "confirmed_duplicate";
  }

  get statusChanged() {
    return this.selectedStatus !== this.args.item.status;
  }

  get primaryChanged() {
    const current = this.args.item.primary_user?.id?.toString() || "";
    const requested = this.isConfirmedDuplicate ? this.primaryUserId : "";
    return current !== requested;
  }

  get noteRequired() {
    return (
      (this.statusChanged &&
        (NOTE_REQUIRED_STATUSES.has(this.selectedStatus) ||
          NOTE_REQUIRED_STATUSES.has(this.args.item.status))) ||
      this.primaryChanged
    );
  }

  get saveDisabled() {
    if (this.isSaving) {
      return true;
    }
    if (this.noteRequired && !this.reviewNote.trim()) {
      return true;
    }
    return !this.statusChanged && !this.primaryChanged && !this.reviewNote.trim();
  }

  @action
  selectStatus(status) {
    this.selectedStatus = status;
    if (this.selectedStatus !== "confirmed_duplicate") {
      this.primaryUserId = "";
    }
  }

  @action
  setPrimaryUser(event) {
    this.primaryUserId = event.target.value;
  }

  @action
  setReviewNote(event) {
    this.reviewNote = event.target.value;
  }

  @action
  async saveReview() {
    if (this.saveDisabled) {
      return;
    }

    this.isSaving = true;
    try {
      const saved = await this.args.controller.saveReview(
        this.args.item,
        this.selectedStatus,
        this.reviewNote.trim(),
        this.isConfirmedDuplicate ? this.primaryUserId : ""
      );
      if (saved) {
        this.reviewNote = "";
      }
    } finally {
      this.isSaving = false;
    }
  }

  <template>
    <details class="as-correlation__candidate" id={{this.elementId}}>
      <summary class="as-correlation__candidate-summary-line">
        <div class="as-correlation__summary-main">
          <div class="as-correlation__summary-title">
            {{#if @item.user_a}}
              <a
                class="trigger-user-card as-correlation__user-link"
                data-user-card={{@item.user_a.username}}
                href={{@item.user_a.profile_url}}
              >{{@item.user_a.username}}</a>
            {{else}}
              <strong>—</strong>
            {{/if}}
            <span class="as-correlation__pair-separator">↔</span>
            {{#if @item.user_b}}
              <a
                class="trigger-user-card as-correlation__user-link"
                data-user-card={{@item.user_b.username}}
                href={{@item.user_b.profile_url}}
              >{{@item.user_b.username}}</a>
            {{else}}
              <strong>—</strong>
            {{/if}}
          </div>
        </div>
        <div class="as-correlation__badges">
          <span class="as-correlation__badge as-correlation__score">{{i18n "admin.account_security.correlations.score"}} {{@item.score}}</span>
          <span class="as-correlation__badge">{{@item.confidence_label}}</span>
          <span class="as-correlation__badge">{{@item.status_label}}</span>
        </div>
        <span class="as-correlation__disclosure-icon" aria-hidden="true">{{dIcon "chevron-right"}}</span>
      </summary>

      <div class="as-correlation__candidate-body">
        <div class="as-correlation__accounts-grid">
          {{#if @item.user_a}}
            <div class="as-correlation__account-card">
              <a
                class="trigger-user-card as-correlation__user-link"
                data-user-card={{@item.user_a.username}}
                href={{@item.user_a.profile_url}}
              >{{@item.user_a.username}}</a>
              <div class="as-correlation__account-meta">
                <div><div class="as-correlation__label">{{i18n "admin.account_security.correlations.registered"}}</div><div class="as-correlation__value">{{@item.user_a.created_at_display}}</div></div>
                <div><div class="as-correlation__label">{{i18n "admin.account_security.correlations.account_last_seen"}}</div><div class="as-correlation__value">{{@item.user_a.last_seen_at_display}}</div></div>
                <div><div class="as-correlation__label">{{i18n "admin.account_security.correlations.account_active"}}</div><div class="as-correlation__value">{{if @item.user_a.active (i18n "admin.account_security.correlations.yes") (i18n "admin.account_security.correlations.no")}}</div></div>
                <div><div class="as-correlation__label">{{i18n "admin.account_security.correlations.account_suspended"}}</div><div class="as-correlation__value">{{if @item.user_a.suspended (i18n "admin.account_security.correlations.yes") (i18n "admin.account_security.correlations.no")}}</div></div>
              </div>
              <div class="as-correlation__account-actions">
                <a class="btn btn-small" href={{@item.user_a.profile_url}}>{{i18n "admin.account_security.correlations.open_profile"}}</a>
                <a class="btn btn-small" href={{@item.user_a.admin_url}}>{{i18n "admin.account_security.correlations.open_admin_user"}}</a>
              </div>
            </div>
          {{/if}}
          {{#if @item.user_b}}
            <div class="as-correlation__account-card">
              <a
                class="trigger-user-card as-correlation__user-link"
                data-user-card={{@item.user_b.username}}
                href={{@item.user_b.profile_url}}
              >{{@item.user_b.username}}</a>
              <div class="as-correlation__account-meta">
                <div><div class="as-correlation__label">{{i18n "admin.account_security.correlations.registered"}}</div><div class="as-correlation__value">{{@item.user_b.created_at_display}}</div></div>
                <div><div class="as-correlation__label">{{i18n "admin.account_security.correlations.account_last_seen"}}</div><div class="as-correlation__value">{{@item.user_b.last_seen_at_display}}</div></div>
                <div><div class="as-correlation__label">{{i18n "admin.account_security.correlations.account_active"}}</div><div class="as-correlation__value">{{if @item.user_b.active (i18n "admin.account_security.correlations.yes") (i18n "admin.account_security.correlations.no")}}</div></div>
                <div><div class="as-correlation__label">{{i18n "admin.account_security.correlations.account_suspended"}}</div><div class="as-correlation__value">{{if @item.user_b.suspended (i18n "admin.account_security.correlations.yes") (i18n "admin.account_security.correlations.no")}}</div></div>
              </div>
              <div class="as-correlation__account-actions">
                <a class="btn btn-small" href={{@item.user_b.profile_url}}>{{i18n "admin.account_security.correlations.open_profile"}}</a>
                <a class="btn btn-small" href={{@item.user_b.admin_url}}>{{i18n "admin.account_security.correlations.open_admin_user"}}</a>
              </div>
            </div>
          {{/if}}
        </div>

        <div class="as-correlation__candidate-meta">
          <div class="as-correlation__signal-box">
            <div class="as-correlation__label">{{i18n "admin.account_security.correlations.signals"}}</div>
            <div class="as-correlation__value">{{@item.signal_summary}}</div>
            {{#if @item.evidence.shared_networks.length}}<p class="as-correlation__muted" style="margin-top: .35rem;">{{@item.evidence.shared_networks}}</p>{{/if}}
          </div>
          <div class="as-correlation__time-box">
            <div><div class="as-correlation__label">{{i18n "admin.account_security.correlations.first_seen"}}</div><div class="as-correlation__value">{{@item.first_seen_at_display}}</div></div>
            <div><div class="as-correlation__label">{{i18n "admin.account_security.correlations.last_seen"}}</div><div class="as-correlation__value">{{@item.last_seen_at_display}}</div></div>
          </div>
        </div>

        {{#if @item.shared_ip_details.length}}
          <div class="as-correlation__evidence-title">
            <h4>{{i18n "admin.account_security.correlations.exact_ip_evidence"}}</h4>
            <p class="as-correlation__muted">{{i18n "admin.account_security.correlations.exact_ip_evidence_description"}}</p>
          </div>
          <div class="as-correlation__ip-list">
            {{#each @item.shared_ip_details as |detail|}}
              <div class="as-correlation__ip-card {{if detail.contextual "as-correlation__ip-card--contextual" ""}}">
                <div class="as-correlation__ip-address">{{detail.ip_address}}</div>
                <div class="as-correlation__ip-meta">
                  <div><strong>{{detail.account_a_sources_label}}:</strong> {{detail.sources_a_display}}</div>
                  <div><strong>{{detail.account_b_sources_label}}:</strong> {{detail.sources_b_display}}</div>
                  <div><strong>{{i18n "admin.account_security.correlations.ip_context"}}:</strong> {{detail.context_display}}</div>
                  {{#if detail.network_context.network_display}}<div><strong>{{i18n "admin.account_security.correlations.network_asn"}}:</strong> {{detail.network_context.network_display}}</div>{{/if}}
                  {{#if detail.network_context.location_display}}<div><strong>{{i18n "admin.account_security.correlations.approximate_location"}}:</strong> {{detail.network_context.location_display}}</div>{{/if}}
                  <div>{{detail.seen_by_display}}</div>
                  {{#if detail.network_context.country_mismatch}}<div class="as-correlation__muted">{{i18n "admin.account_security.correlations.country_mismatch"}}</div>{{/if}}
                </div>
              </div>
            {{/each}}
          </div>
        {{/if}}

        {{#if @item.has_network_context}}
          <div class="as-correlation__evidence-title">
            <h4>{{i18n "admin.account_security.correlations.network_context_title"}}</h4>
            <p class="as-correlation__muted">{{i18n "admin.account_security.correlations.network_context_description"}}</p>
          </div>
          <div class="as-correlation__compact-grid">
            <div class="as-correlation__compact-item"><div class="as-correlation__label">{{i18n "admin.account_security.correlations.network_context_enriched_ips"}}</div><div class="as-correlation__value">{{@item.network_context_summary.locally_enriched_ip_count}}</div></div>
            <div class="as-correlation__compact-item"><div class="as-correlation__label">{{i18n "admin.account_security.correlations.network_context_distinct_asns"}}</div><div class="as-correlation__value">{{@item.network_context_summary.distinct_asn_count}}</div></div>
            <div class="as-correlation__compact-item"><div class="as-correlation__label">{{i18n "admin.account_security.correlations.network_context_operators"}}</div><div class="as-correlation__value">{{if @item.network_context_summary.organizations_display @item.network_context_summary.organizations_display "—"}}</div></div>
            <div class="as-correlation__compact-item"><div class="as-correlation__label">{{i18n "admin.account_security.correlations.network_context_countries"}}</div><div class="as-correlation__value">{{if @item.network_context_summary.countries_display @item.network_context_summary.countries_display "—"}}</div></div>
          </div>
        {{/if}}

        {{#if @item.has_temporal_evidence}}
          <div class="as-correlation__evidence-title">
            <h4>{{i18n "admin.account_security.correlations.temporal_title"}}</h4>
            <p class="as-correlation__muted">{{i18n "admin.account_security.correlations.temporal_description"}}</p>
          </div>
          <div class="as-correlation__temporal-summary">
            <div class="as-correlation__compact-item"><div class="as-correlation__label">{{i18n "admin.account_security.correlations.temporal_closest_gap"}}</div><div class="as-correlation__value">{{@item.temporal_closest_gap_display}}</div></div>
            <div class="as-correlation__compact-item"><div class="as-correlation__label">{{i18n "admin.account_security.correlations.temporal_within_1h"}}</div><div class="as-correlation__value">{{@item.evidence.temporal_within_1h_count}}</div></div>
            <div class="as-correlation__compact-item"><div class="as-correlation__label">{{i18n "admin.account_security.correlations.temporal_within_24h"}}</div><div class="as-correlation__value">{{@item.evidence.temporal_within_24h_count}}</div></div>
            <div class="as-correlation__compact-item"><div class="as-correlation__label">{{i18n "admin.account_security.correlations.temporal_public_within_24h"}}</div><div class="as-correlation__value">{{@item.evidence.temporal_public_within_24h_count}}</div></div>
          </div>
          <div class="as-correlation__temporal-list">
            {{#each @item.temporal_ip_details as |detail|}}
              <div class="as-correlation__temporal-card">
                <div class="as-correlation__temporal-card-header"><span class="as-correlation__ip-address">{{detail.ip_address}}</span><span class="as-correlation__badge">{{detail.closest_gap_display}}</span></div>
                <div class="as-correlation__temporal-account-grid">
                  <div><div class="as-correlation__label">{{detail.account_a_label}}</div><div class="as-correlation__value">{{i18n "admin.account_security.correlations.temporal_observations" count=detail.observations_a}}</div></div>
                  <div><div class="as-correlation__label">{{detail.account_b_label}}</div><div class="as-correlation__value">{{i18n "admin.account_security.correlations.temporal_observations" count=detail.observations_b}}</div></div>
                </div>
              </div>
            {{/each}}
          </div>
          {{#if @item.evidence.temporal_ip_details_truncated}}<div class="as-correlation__continuity-note">{{i18n "admin.account_security.correlations.temporal_details_truncated"}}</div>{{/if}}
        {{/if}}

        {{#if @item.has_auth_pattern_evidence}}
          <div class="as-correlation__evidence-title">
            <h4>{{i18n "admin.account_security.correlations.auth_patterns_title"}}</h4>
            <p class="as-correlation__muted">{{i18n "admin.account_security.correlations.auth_patterns_description"}}</p>
          </div>
          <div class="as-correlation__compact-grid">
            <div class="as-correlation__compact-item"><div class="as-correlation__label">{{i18n "admin.account_security.correlations.auth_patterns_very_close_logins"}}</div><div class="as-correlation__value">{{@item.evidence.auth_proximity_within_5m_count}}</div></div>
            <div class="as-correlation__compact-item"><div class="as-correlation__label">{{i18n "admin.account_security.correlations.auth_patterns_close_logins"}}</div><div class="as-correlation__value">{{@item.evidence.auth_proximity_within_30m_count}}</div></div>
            <div class="as-correlation__compact-item"><div class="as-correlation__label">{{i18n "admin.account_security.correlations.auth_patterns_same_client"}}</div><div class="as-correlation__value">{{@item.evidence.auth_proximity_same_client_within_30m_count}}</div></div>
            <div class="as-correlation__compact-item"><div class="as-correlation__label">{{i18n "admin.account_security.correlations.auth_patterns_public_transitions"}}</div><div class="as-correlation__value">{{@item.evidence.aligned_public_ip_transition_7d_count}}</div></div>
            <div class="as-correlation__compact-item"><div class="as-correlation__label">{{i18n "admin.account_security.correlations.auth_patterns_shared_client_signatures"}}</div><div class="as-correlation__value">{{@item.evidence.shared_auth_client_signature_count}}</div></div>
            <div class="as-correlation__compact-item"><div class="as-correlation__label">{{i18n "admin.account_security.correlations.auth_patterns_repeated_browser"}}</div><div class="as-correlation__value">{{@item.evidence.repeated_browser_continuity_count}}</div></div>
            <div class="as-correlation__compact-item"><div class="as-correlation__label">{{i18n "admin.account_security.correlations.auth_patterns_repeated_session"}}</div><div class="as-correlation__value">{{@item.evidence.repeated_shared_session_signature_count}}</div></div>
          </div>

          {{#if @item.evidence.auth_client_signature_population_complete}}
            {{#if @item.evidence.max_shared_auth_client_signature_users}}
              <p class="as-correlation__muted" style="margin-top: .65rem;">{{i18n "admin.account_security.correlations.auth_patterns_signature_seen_by" count=@item.evidence.max_shared_auth_client_signature_users}}</p>
            {{/if}}
          {{/if}}

          {{#if @item.auth_proximity_details.length}}
            <div class="as-correlation__temporal-list">
              {{#each @item.auth_proximity_details as |detail|}}
                <div class="as-correlation__temporal-card">
                  <div class="as-correlation__temporal-card-header"><span class="as-correlation__ip-address">{{detail.ip_address}}</span><span class="as-correlation__badge">{{detail.closest_gap_display}}</span></div>
                  <div class="as-correlation__temporal-account-grid">
                    <div><div class="as-correlation__label">{{i18n "admin.account_security.correlations.auth_patterns_close_logins"}}</div><div class="as-correlation__value">{{detail.within_30m_count}}</div></div>
                    <div><div class="as-correlation__label">{{i18n "admin.account_security.correlations.auth_patterns_same_client"}}</div><div class="as-correlation__value">{{detail.same_client_within_30m_count}}</div></div>
                  </div>
                </div>
              {{/each}}
            </div>
          {{/if}}

          {{#if @item.public_ip_transition_details.length}}
            <div class="as-correlation__temporal-list">
              {{#each @item.public_ip_transition_details as |detail|}}
                <div class="as-correlation__temporal-card">
                  <div class="as-correlation__temporal-card-header"><span class="as-correlation__ip-address">{{detail.from_ip}} → {{detail.to_ip}}</span><span class="as-correlation__badge">{{detail.closest_gap_display}}</span></div>
                  <p class="as-correlation__muted" style="margin-top: .55rem;">{{i18n "admin.account_security.correlations.auth_patterns_transition_detail"}}</p>
                </div>
              {{/each}}
            </div>
          {{/if}}

          <div class="as-correlation__continuity-note">{{i18n "admin.account_security.correlations.auth_patterns_score_note"}}</div>
        {{/if}}

        {{#if @item.score_breakdown.length}}
          <div class="as-correlation__evidence-title">
            <h4>{{i18n "admin.account_security.correlations.score_explanation"}}</h4>
            <p class="as-correlation__muted">{{i18n "admin.account_security.correlations.score_explanation_description"}}</p>
          </div>
          <div class="as-correlation__breakdown">
            {{#each @item.score_breakdown as |entry|}}
              <div class="as-correlation__reason"><span>{{entry.label}}</span><span class="as-correlation__points {{if entry.positive "as-correlation__points--positive" ""}} {{if entry.negative "as-correlation__points--negative" ""}}">{{entry.points_display}}</span></div>
            {{/each}}
          </div>
        {{/if}}

        {{#if @item.evidence.browser_continuity_count}}
          {{#unless @item.has_auth_pattern_evidence}}<div class="as-correlation__continuity-note">{{i18n "admin.account_security.correlations.browser_continuity_note"}}</div>{{/unless}}
        {{/if}}

        <section class="as-correlation__investigation">
          <div class="as-correlation__evidence-title as-correlation__evidence-title--first">
            <h4>{{i18n "admin.account_security.correlations.investigation_title"}}</h4>
            <p class="as-correlation__muted">{{i18n "admin.account_security.correlations.investigation_description"}}</p>
          </div>

          <div class="as-correlation__investigation-summary">
            <div class="as-correlation__compact-item"><div class="as-correlation__label">{{i18n "admin.account_security.correlations.current_status"}}</div><div class="as-correlation__value">{{@item.status_label}}</div></div>
            <div class="as-correlation__compact-item"><div class="as-correlation__label">{{i18n "admin.account_security.correlations.last_reviewed_by"}}</div><div class="as-correlation__value">{{if @item.reviewed_by @item.reviewed_by.username "—"}}</div></div>
            <div class="as-correlation__compact-item"><div class="as-correlation__label">{{i18n "admin.account_security.correlations.last_reviewed_at"}}</div><div class="as-correlation__value">{{if @item.reviewed_at_display @item.reviewed_at_display "—"}}</div></div>
            <div class="as-correlation__compact-item"><div class="as-correlation__label">{{i18n "admin.account_security.correlations.account_to_keep"}}</div><div class="as-correlation__value">{{if @item.primary_user @item.primary_user.username "—"}}</div></div>
          </div>

          <div class="as-correlation__review-form">
            <div class="as-correlation__review-decision">
              <div class="as-correlation__field-label">{{i18n "admin.account_security.correlations.review_status"}}</div>
              <div class="as-correlation__decision-actions" role="group" aria-label={{i18n "admin.account_security.correlations.review_status"}}>
                <button class="btn {{if (eq this.selectedStatus "open") "as-correlation__decision-button--selected" ""}}" type="button" aria-pressed={{eq this.selectedStatus "open"}} {{on "click" (fn this.selectStatus "open")}}>{{i18n "admin.account_security.correlations.status_actions.open"}}</button>
                <button class="btn {{if (eq this.selectedStatus "monitor") "as-correlation__decision-button--selected" ""}}" type="button" aria-pressed={{eq this.selectedStatus "monitor"}} {{on "click" (fn this.selectStatus "monitor")}}>{{i18n "admin.account_security.correlations.status_actions.monitor"}}</button>
                <button class="btn {{if (eq this.selectedStatus "expected_shared_network") "as-correlation__decision-button--selected" ""}}" type="button" aria-pressed={{eq this.selectedStatus "expected_shared_network"}} {{on "click" (fn this.selectStatus "expected_shared_network")}}>{{i18n "admin.account_security.correlations.status_actions.expected_shared_network"}}</button>
                <button class="btn btn-danger {{if (eq this.selectedStatus "confirmed_duplicate") "as-correlation__decision-button--selected-danger" ""}}" type="button" aria-pressed={{eq this.selectedStatus "confirmed_duplicate"}} {{on "click" (fn this.selectStatus "confirmed_duplicate")}}>{{i18n "admin.account_security.correlations.status_actions.confirmed_duplicate"}}</button>
                <button class="btn {{if (eq this.selectedStatus "dismissed") "as-correlation__decision-button--selected" ""}}" type="button" aria-pressed={{eq this.selectedStatus "dismissed"}} {{on "click" (fn this.selectStatus "dismissed")}}>{{i18n "admin.account_security.correlations.status_actions.dismissed"}}</button>
              </div>
            </div>

            {{#if this.isConfirmedDuplicate}}
              <label class="as-correlation__field as-correlation__field--keep">
                <span>{{i18n "admin.account_security.correlations.account_to_keep"}}</span>
                <select value={{this.primaryUserId}} {{on "change" this.setPrimaryUser}}>
                  <option value="">{{i18n "admin.account_security.correlations.not_selected"}}</option>
                  {{#if @item.user_a}}<option value={{@item.user_a.id}}>{{@item.user_a.username}}</option>{{/if}}
                  {{#if @item.user_b}}<option value={{@item.user_b.id}}>{{@item.user_b.username}}</option>{{/if}}
                </select>
                <span class="as-correlation__field-hint">{{i18n "admin.account_security.correlations.account_to_keep_hint"}}</span>
              </label>
            {{/if}}

            <label class="as-correlation__field as-correlation__field--note">
              <span>{{i18n "admin.account_security.correlations.review_note"}}</span>
              <textarea
                maxlength="1000"
                rows="5"
                value={{this.reviewNote}}
                placeholder={{i18n "admin.account_security.correlations.review_note_placeholder"}}
                {{on "input" this.setReviewNote}}
              ></textarea>
              <span class="as-correlation__field-hint">{{if this.noteRequired (i18n "admin.account_security.correlations.review_note_required_hint") (i18n "admin.account_security.correlations.review_note_optional_hint")}}</span>
            </label>

            <div class="as-correlation__review-footer">
              <span class="as-correlation__muted">{{i18n "admin.account_security.correlations.review_save_hint"}}</span>
              <button class="btn btn-primary" type="button" disabled={{this.saveDisabled}} {{on "click" this.saveReview}}>{{i18n "admin.account_security.correlations.save_review"}}</button>
            </div>
          </div>

          {{#if @item.review_history.length}}
            <div class="as-correlation__history">
              <h4>{{i18n "admin.account_security.correlations.review_history"}}</h4>
              <div class="as-correlation__history-list">
                {{#each @item.review_history as |review|}}
                  <article class="as-correlation__history-item">
                    <div class="as-correlation__history-header">
                      <strong>{{review.action_label}}</strong>
                      <span class="as-correlation__muted">{{review.created_at_display}}</span>
                    </div>
                    <div class="as-correlation__history-meta">
                      <span>{{i18n "admin.account_security.correlations.reviewed_by"}}: {{if review.actor review.actor.username "—"}}</span>
                      {{#if review.status_transition_display}}<span>{{i18n "admin.account_security.correlations.status"}}: {{review.status_transition_display}}</span>{{/if}}
                      {{#if review.primary_user}}<span>{{i18n "admin.account_security.correlations.account_to_keep"}}: {{review.primary_user.username}}</span>{{/if}}
                    </div>
                    {{#if review.note}}<p class="as-correlation__history-note">{{review.note}}</p>{{/if}}
                  </article>
                {{/each}}
              </div>
            </div>
          {{/if}}
        </section>
      </div>
    </details>
  </template>
}
