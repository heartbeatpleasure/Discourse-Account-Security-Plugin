import { fn } from "@ember/helper";
import { on } from "@ember/modifier";
import Component from "@glimmer/component";
import dIcon from "discourse/ui-kit/helpers/d-icon";
import { i18n } from "discourse-i18n";

export default class AccountSecurityCorrelationPair extends Component {
  <template>
    <details class="as-correlation__candidate">
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
                  <div>{{detail.seen_by_display}}</div>
                </div>
              </div>
            {{/each}}
          </div>
        {{/if}}

        {{#if @item.has_temporal_evidence}}
          <div class="as-correlation__evidence-title">
            <h4>{{i18n "admin.account_security.correlations.temporal_title"}}</h4>
            <p class="as-correlation__muted">{{i18n "admin.account_security.correlations.temporal_description"}}</p>
          </div>
          <div class="as-correlation__temporal-summary">
            <div class="as-correlation__compact-item">
              <div class="as-correlation__label">{{i18n "admin.account_security.correlations.temporal_closest_gap"}}</div>
              <div class="as-correlation__value">{{@item.temporal_closest_gap_display}}</div>
            </div>
            <div class="as-correlation__compact-item">
              <div class="as-correlation__label">{{i18n "admin.account_security.correlations.temporal_within_1h"}}</div>
              <div class="as-correlation__value">{{@item.evidence.temporal_within_1h_count}}</div>
            </div>
            <div class="as-correlation__compact-item">
              <div class="as-correlation__label">{{i18n "admin.account_security.correlations.temporal_within_24h"}}</div>
              <div class="as-correlation__value">{{@item.evidence.temporal_within_24h_count}}</div>
            </div>
            <div class="as-correlation__compact-item">
              <div class="as-correlation__label">{{i18n "admin.account_security.correlations.temporal_public_within_24h"}}</div>
              <div class="as-correlation__value">{{@item.evidence.temporal_public_within_24h_count}}</div>
            </div>
          </div>
          <div class="as-correlation__temporal-list">
            {{#each @item.temporal_ip_details as |detail|}}
              <div class="as-correlation__temporal-card">
                <div class="as-correlation__temporal-card-header">
                  <span class="as-correlation__ip-address">{{detail.ip_address}}</span>
                  <span class="as-correlation__badge">{{detail.closest_gap_display}}</span>
                </div>
                <div class="as-correlation__temporal-account-grid">
                  <div>
                    <div class="as-correlation__label">{{detail.account_a_label}}</div>
                    <div class="as-correlation__value">{{i18n "admin.account_security.correlations.temporal_observations" count=detail.observations_a}}</div>
                  </div>
                  <div>
                    <div class="as-correlation__label">{{detail.account_b_label}}</div>
                    <div class="as-correlation__value">{{i18n "admin.account_security.correlations.temporal_observations" count=detail.observations_b}}</div>
                  </div>
                </div>
              </div>
            {{/each}}
          </div>
          {{#if @item.evidence.temporal_ip_details_truncated}}
            <div class="as-correlation__continuity-note">{{i18n "admin.account_security.correlations.temporal_details_truncated"}}</div>
          {{/if}}
        {{/if}}

        {{#if @item.score_breakdown.length}}
          <div class="as-correlation__evidence-title">
            <h4>{{i18n "admin.account_security.correlations.score_explanation"}}</h4>
            <p class="as-correlation__muted">{{i18n "admin.account_security.correlations.score_explanation_description"}}</p>
          </div>
          <div class="as-correlation__breakdown">
            {{#each @item.score_breakdown as |entry|}}
              <div class="as-correlation__reason">
                <span>{{entry.label}}</span>
                <span class="as-correlation__points {{if entry.positive "as-correlation__points--positive" ""}} {{if entry.negative "as-correlation__points--negative" ""}}">{{entry.points_display}}</span>
              </div>
            {{/each}}
          </div>
        {{/if}}

        {{#if @item.evidence.browser_continuity_count}}
          <div class="as-correlation__continuity-note">{{i18n "admin.account_security.correlations.browser_continuity_note"}}</div>
        {{/if}}

        <div class="as-correlation__review">
          <div class="as-correlation__muted">{{@item.status_label}}</div>
          <div class="as-correlation__buttons">
            <button class="btn btn-small" type="button" {{on "click" (fn @controller.review @item "monitor")}}>{{i18n "admin.account_security.correlations.mark_monitor"}}</button>
            <button class="btn btn-small" type="button" {{on "click" (fn @controller.review @item "expected_shared_network")}}>{{i18n "admin.account_security.correlations.mark_expected"}}</button>
            <button class="btn btn-small btn-danger" type="button" {{on "click" (fn @controller.review @item "confirmed_duplicate")}}>{{i18n "admin.account_security.correlations.mark_duplicate"}}</button>
            <button class="btn btn-small" type="button" {{on "click" (fn @controller.review @item "dismissed")}}>{{i18n "admin.account_security.correlations.mark_dismissed"}}</button>
            {{#if @item.can_reopen}}<button class="btn btn-small" type="button" {{on "click" (fn @controller.review @item "open")}}>{{i18n "admin.account_security.correlations.reopen"}}</button>{{/if}}
          </div>
        </div>
      </div>
    </details>
  </template>
}
