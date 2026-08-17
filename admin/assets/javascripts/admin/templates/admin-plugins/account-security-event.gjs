import { fn } from "@ember/helper";
import { on } from "@ember/modifier";
import RouteTemplate from "ember-route-template";
import getURL from "discourse/lib/get-url";
import { i18n } from "discourse-i18n";

const overviewUrl = getURL("/admin/plugins/account-security");
const eventsUrl = getURL("/admin/plugins/account-security-events");

export default RouteTemplate(
  <template>
    <style>
      .as-page {
        --as-surface: var(--secondary);
        --as-surface-alt: var(--primary-very-low);
        --as-border: var(--primary-low);
        --as-muted: var(--primary-medium);
        display: flex;
        min-width: 0;
        flex-direction: column;
        gap: 1rem;
      }
      .as-page h1, .as-page h2, .as-page h3, .as-page p { margin: 0; }
      .as-page__hero, .as-page__panel {
        min-width: 0;
        padding: 1.2rem 1.35rem;
        border: 1px solid var(--as-border);
        border-radius: 18px;
        background: var(--as-surface);
        box-shadow: 0 1px 2px rgb(0 0 0 / 3%);
      }
      .as-page__hero, .as-page__panel-header {
        display: flex;
        align-items: flex-start;
        justify-content: space-between;
        gap: 1rem;
      }
      .as-page__copy {
        display: flex;
        min-width: 0;
        flex: 1 1 auto;
        flex-direction: column;
        gap: .35rem;
      }
      .as-page__muted, .as-page__hint { color: var(--as-muted); }
      .as-page__actions, .as-page__buttons {
        display: flex;
        flex: 0 0 auto;
        flex-wrap: wrap;
        align-items: center;
        justify-content: flex-end;
        gap: .5rem;
      }
      .as-page__actions { flex-wrap: nowrap; margin-left: auto; }
      .as-page__actions .btn, .as-page__buttons .btn { white-space: nowrap; }
      .as-page__metrics, .as-page__grid {
        display: grid;
        grid-template-columns: repeat(4, minmax(0, 1fr));
        gap: .75rem;
      }
      .as-page__grid { grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); }
      .as-page__item, .as-page__metric {
        min-width: 0;
        padding: .75rem;
        border-radius: 12px;
        background: var(--as-surface-alt);
      }
      .as-page__label {
        color: var(--as-muted);
        font-size: var(--font-down-1);
        font-weight: 700;
      }
      .as-page__value {
        margin-top: .2rem;
        overflow-wrap: anywhere;
        font-weight: 600;
      }
      .as-page__metric .as-page__value { font-size: var(--font-up-1); }
      .as-page__toolbar, .as-page__form-row {
        display: flex;
        flex-wrap: wrap;
        align-items: flex-end;
        gap: .75rem;
      }
      .as-page__field {
        display: grid;
        min-width: min(15rem, 100%);
        flex: 1 1 15rem;
        gap: .3rem;
      }
      .as-page__field label { font-weight: 700; }
      .as-page__control,
      .as-page__field input,
      .as-page__field select,
      .as-page__field textarea {
        width: 100%;
        min-height: 42px;
        box-sizing: border-box;
        margin: 0;
        border: 1px solid var(--as-border);
        border-radius: 10px;
        background: var(--as-surface);
      }
      .as-page__field textarea { min-height: 90px; padding: .65rem .75rem; resize: vertical; }
      .as-page__table-wrap {
        width: 100%;
        overflow-x: auto;
        border: 1px solid var(--as-border);
        border-radius: 12px;
      }
      .as-page__table { width: 100%; border-collapse: collapse; }
      .as-page__table th, .as-page__table td {
        padding: .7rem .75rem;
        border-bottom: 1px solid var(--as-border);
        text-align: left;
        vertical-align: top;
      }
      .as-page__table th {
        color: var(--as-muted);
        font-size: var(--font-down-1);
        white-space: nowrap;
      }
      .as-page__table tr:last-child td { border-bottom: 0; }
      .as-page__code {
        font-family: var(--d-font-family--monospace);
        overflow-wrap: anywhere;
      }
      .as-page__badge {
        display: inline-flex;
        width: max-content;
        padding: .25rem .5rem;
        border: 1px solid var(--as-border);
        border-radius: 999px;
        background: var(--as-surface-alt);
        font-size: var(--font-down-1);
        font-weight: 700;
      }
      .as-page__notice {
        padding: .75rem .85rem;
        border-left: 3px solid var(--tertiary);
        border-radius: 8px;
        background: var(--tertiary-very-low);
      }
      .as-page__warning {
        padding: .75rem .85rem;
        border-left: 3px solid var(--danger);
        border-radius: 8px;
        background: var(--danger-low, var(--primary-very-low));
      }
      .as-page__stack { display: grid; gap: .75rem; }
      .as-page__checkbox { display: flex; align-items: flex-start; gap: .5rem; }
      .as-page__checkbox input { flex: 0 0 auto; margin-top: .2rem; }
      .as-page__section-title { display: grid; gap: .25rem; margin-bottom: .8rem; }
      @media (max-width: 900px) {
        .as-page__hero { flex-direction: column; }
        .as-page__actions { align-self: flex-end; flex-wrap: wrap; margin-left: 0; }
        .as-page__metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      }
      @media (max-width: 650px) {
        .as-page__panel-header { flex-direction: column; }
        .as-page__metrics, .as-page__grid { grid-template-columns: 1fr; }
        .as-page__field { flex-basis: 100%; }
      }
    </style>
    <div class="as-page">
      <section class="as-page__hero">
        <div class="as-page__copy">
          <h1>{{i18n "admin.account_security.event_detail.title"}} #{{@controller.event.id}}</h1>
          <p class="as-page__muted">{{i18n "admin.account_security.event_detail.description"}}</p>
        </div>
        <div class="as-page__actions">
          <a class="btn" href={{eventsUrl}}>{{i18n "admin.account_security.event_detail.back_events"}}</a>
          <a class="btn" href={{overviewUrl}}>{{i18n "admin.account_security.back_overview"}}</a>
          <button class="btn" type="button" disabled={{@controller.isWorking}} {{on "click" @controller.refreshEvent}}>{{i18n "admin.account_security.event_detail.refresh"}}</button>
        </div>
      </section>

      <section class="as-page__metrics">
        <div class="as-page__metric"><div class="as-page__label">{{i18n "admin.account_security.events.risk"}}</div><div class="as-page__value">{{@controller.event.risk_level}}</div></div>
        <div class="as-page__metric"><div class="as-page__label">{{i18n "admin.account_security.events.evidence"}}</div><div class="as-page__value">{{@controller.event.evidence_strength}}</div></div>
        <div class="as-page__metric"><div class="as-page__label">{{i18n "admin.account_security.events.occurrences"}}</div><div class="as-page__value">{{@controller.event.occurrence_count}}</div></div>
        <div class="as-page__metric"><div class="as-page__label">{{i18n "admin.account_security.events.status"}}</div><div class="as-page__value">{{@controller.event.status}}</div></div>
      </section>

      <section class="as-page__panel">
        <div class="as-page__section-title"><h2>{{i18n "admin.account_security.event_detail.event_context"}}</h2></div>
        <div class="as-page__grid">
          <div class="as-page__item"><div class="as-page__label">{{i18n "admin.account_security.events.user"}}</div><div class="as-page__value">{{if @controller.event.user @controller.event.user.username "—"}}</div></div>
          <div class="as-page__item"><div class="as-page__label">IP</div><div class="as-page__value as-page__code">{{@controller.event.ip_address}}</div></div>
          <div class="as-page__item"><div class="as-page__label">{{i18n "admin.account_security.events.type"}}</div><div class="as-page__value">{{@controller.event.event_type}}</div></div>
          <div class="as-page__item"><div class="as-page__label">{{i18n "admin.account_security.events.last_seen"}}</div><div class="as-page__value">{{@controller.event.last_seen_at_display}}</div></div>
          <div class="as-page__item"><div class="as-page__label">Tor</div><div class="as-page__value">{{@controller.event.context.is_tor}}</div></div>
          <div class="as-page__item"><div class="as-page__label">{{i18n "admin.account_security.intelligence.blacklist"}}</div><div class="as-page__value">{{@controller.event.context.local_blacklist_match}}</div></div>
          <div class="as-page__item"><div class="as-page__label">{{i18n "admin.account_security.intelligence.usage_type"}}</div><div class="as-page__value">{{if @controller.event.context.usage_type @controller.event.context.usage_type "—"}}</div></div>
          <div class="as-page__item"><div class="as-page__label">{{i18n "admin.account_security.event_detail.familiarity_network"}}</div><div class="as-page__value as-page__code">{{if @controller.event.context.familiarity_network @controller.event.context.familiarity_network "—"}}</div></div>
          {{#if @controller.event.context.abuse_family}}
            <div class="as-page__item"><div class="as-page__label">{{i18n "admin.account_security.event_detail.abuse_family"}}</div><div class="as-page__value">{{@controller.event.context.abuse_family}}</div></div>
            <div class="as-page__item"><div class="as-page__label">{{i18n "admin.account_security.event_detail.failure_count"}}</div><div class="as-page__value">{{@controller.event.context.failure_count}}</div></div>
            <div class="as-page__item"><div class="as-page__label">{{i18n "admin.account_security.event_detail.distinct_targets"}}</div><div class="as-page__value">{{if @controller.event.context.distinct_targets @controller.event.context.distinct_targets "—"}}</div></div>
            <div class="as-page__item"><div class="as-page__label">{{i18n "admin.account_security.event_detail.staff_targeted"}}</div><div class="as-page__value">{{@controller.event.context.staff_targeted}}</div></div>
          {{/if}}
          {{#if @controller.event.notified_at}}
            <div class="as-page__item"><div class="as-page__label">{{i18n "admin.account_security.event_detail.notified_at"}}</div><div class="as-page__value">{{@controller.event.notified_at_display}}</div></div>
            <div class="as-page__item"><div class="as-page__label">{{i18n "admin.account_security.event_detail.notification_kind"}}</div><div class="as-page__value">{{@controller.event.notification_kind}}</div></div>
          {{/if}}
        </div>
      </section>

      {{#if @controller.data.intelligence}}
        <section class="as-page__panel">
          <div class="as-page__section-title"><h2>{{i18n "admin.account_security.event_detail.intelligence"}}</h2></div>
          <div class="as-page__grid">
            <div class="as-page__item"><div class="as-page__label">{{i18n "admin.account_security.intelligence.score"}}</div><div class="as-page__value">{{@controller.data.intelligence.primary_score}}</div></div>
            <div class="as-page__item"><div class="as-page__label">{{i18n "admin.account_security.event_detail.total_reports"}}</div><div class="as-page__value">{{@controller.data.intelligence.total_reports}}</div></div>
            <div class="as-page__item"><div class="as-page__label">{{i18n "admin.account_security.event_detail.distinct_reporters"}}</div><div class="as-page__value">{{@controller.data.intelligence.distinct_reporters}}</div></div>
            <div class="as-page__item"><div class="as-page__label">{{i18n "admin.account_security.event_detail.last_reported"}}</div><div class="as-page__value">{{@controller.data.intelligence.last_reported_at_display}}</div></div>
          </div>
        </section>
      {{/if}}

      <section class="as-page__panel">
        <div class="as-page__section-title">
          <h2>{{i18n "admin.account_security.event_detail.review_title"}}</h2>
          <p class="as-page__muted">{{i18n "admin.account_security.event_detail.review_description"}}</p>
        </div>
        <div class="as-page__stack">
          <div class="as-page__field">
            <label>{{i18n "admin.account_security.event_detail.reason"}}</label>
            <textarea value={{@controller.resolutionReason}} {{on "input" @controller.updateResolutionReason}}></textarea>
          </div>
          <div class="as-page__buttons">
            <button class="btn" type="button" disabled={{@controller.isWorking}} {{on "click" (fn @controller.review "acknowledged")}}>{{i18n "admin.account_security.events.acknowledge"}}</button>
            <button class="btn" type="button" disabled={{@controller.isWorking}} {{on "click" (fn @controller.review "monitor")}}>{{i18n "admin.account_security.events.monitor"}}</button>
            <button class="btn" type="button" disabled={{@controller.isWorking}} {{on "click" (fn @controller.review "benign")}}>{{i18n "admin.account_security.event_detail.mark_benign"}}</button>
            <button class="btn btn-primary" type="button" disabled={{@controller.isWorking}} {{on "click" (fn @controller.review "actioned")}}>{{i18n "admin.account_security.event_detail.mark_actioned"}}</button>
          </div>
        </div>
      </section>

      <section class="as-page__grid">
        <div class="as-page__panel">
          <div class="as-page__section-title"><h2>{{i18n "admin.account_security.event_detail.notification_suppression_title"}}</h2><p class="as-page__muted">{{i18n "admin.account_security.event_detail.notification_suppression_description"}}</p></div>
          {{#if @controller.notificationSuppressionActive}}
            <div class="as-page__notice">{{i18n "admin.account_security.event_detail.notification_suppressed_until"}} {{@controller.data.notification_suppression.expires_at_display}}</div>
            <button class="btn" type="button" disabled={{@controller.isWorking}} {{on "click" @controller.releaseNotificationSuppression}}>{{i18n "admin.account_security.event_detail.release_notification_suppression"}}</button>
          {{else if @controller.canCreateNotificationSuppression}}
            <div class="as-page__stack">
              <div class="as-page__field">
                <label>{{i18n "admin.account_security.event_detail.notification_suppression_duration"}}</label>
                <select class="as-page__control" value={{@controller.suppressionDurationHours}} {{on "change" @controller.updateSuppressionDuration}}>
                  <option value="24">1 day</option>
                  <option value="168">7 days</option>
                  <option value="720">30 days</option>
                  <option value="2160">90 days</option>
                </select>
              </div>
              <label class="as-page__checkbox"><input type="checkbox" checked={{@controller.confirmNotificationSuppression}} {{on "change" @controller.updateNotificationSuppressionConfirmation}} /><span>{{i18n "admin.account_security.event_detail.confirm_notification_suppression"}}</span></label>
              <button class="btn" type="button" disabled={{@controller.isWorking}} {{on "click" @controller.createNotificationSuppression}}>{{i18n "admin.account_security.event_detail.create_notification_suppression"}}</button>
            </div>
          {{else}}
            <p class="as-page__muted">{{i18n "admin.account_security.event_detail.notification_suppression_unavailable"}}</p>
          {{/if}}
        </div>

        <div class="as-page__panel">
          <div class="as-page__section-title"><h2>{{i18n "admin.account_security.event_detail.user_note_title"}}</h2><p class="as-page__muted">{{i18n "admin.account_security.event_detail.user_note_description"}}</p></div>
          {{#if @controller.event.user_note_created_at}}
            <div class="as-page__notice">{{i18n "admin.account_security.event_detail.user_note_created"}} {{@controller.event.user_note_created_at_display}}</div>
          {{else if @controller.canAddUserNote}}
            <button class="btn" type="button" disabled={{@controller.isWorking}} {{on "click" @controller.addUserNote}}>{{i18n "admin.account_security.event_detail.add_user_note"}}</button>
          {{else}}
            <p class="as-page__muted">{{i18n "admin.account_security.event_detail.user_note_unavailable"}}</p>
          {{/if}}
        </div>

        <div class="as-page__panel">
          <div class="as-page__section-title"><h2>{{i18n "admin.account_security.event_detail.temporary_block_title"}}</h2><p class="as-page__muted">{{i18n "admin.account_security.event_detail.temporary_block_description"}}</p></div>
          {{#if @controller.temporaryBlockActive}}
            <div class="as-page__notice">{{i18n "admin.account_security.event_detail.block_active_until"}} {{@controller.data.temporary_block.expires_at_display}}</div>
            <button class="btn" type="button" disabled={{@controller.isWorking}} {{on "click" @controller.releaseTemporaryBlock}}>{{i18n "admin.account_security.event_detail.release_block"}}</button>
          {{else if @controller.canCreateTemporaryBlock}}
            <div class="as-page__stack">
              <div class="as-page__field">
                <label>{{i18n "admin.account_security.event_detail.block_duration"}}</label>
                <select class="as-page__control" value={{@controller.durationMinutes}} {{on "change" @controller.updateDuration}}>
                  <option value="60">1 hour</option>
                  <option value="360">6 hours</option>
                  <option value="1440">24 hours</option>
                  <option value="4320">3 days</option>
                  <option value="10080">7 days</option>
                </select>
              </div>
              <label class="as-page__checkbox"><input type="checkbox" checked={{@controller.confirmTemporaryBlock}} {{on "change" @controller.updateTemporaryBlockConfirmation}} /><span>{{i18n "admin.account_security.event_detail.confirm_block"}}</span></label>
              <button class="btn btn-danger" type="button" disabled={{@controller.isWorking}} {{on "click" @controller.createTemporaryBlock}}>{{i18n "admin.account_security.event_detail.create_block"}}</button>
            </div>
          {{else}}
            <p class="as-page__muted">{{i18n "admin.account_security.event_detail.temporary_block_unavailable"}}</p>
          {{/if}}
        </div>

        <div class="as-page__panel">
          <div class="as-page__section-title"><h2>{{i18n "admin.account_security.event_detail.abuse_report_title"}}</h2><p class="as-page__muted">{{i18n "admin.account_security.event_detail.abuse_report_description"}}</p></div>
          {{#if @controller.data.provider_report}}
            <div class="as-page__notice">{{i18n "admin.account_security.event_detail.report_status"}}: {{@controller.data.provider_report.status}}</div>
          {{else if @controller.data.capabilities.abuse_reportable}}
            <div class="as-page__stack">
              <label class="as-page__checkbox"><input type="checkbox" checked={{@controller.confirmAbuseReport}} {{on "change" @controller.updateAbuseReportConfirmation}} /><span>{{i18n "admin.account_security.event_detail.confirm_report"}}</span></label>
              <button class="btn" type="button" disabled={{@controller.isWorking}} {{on "click" @controller.reportAbuse}}>{{i18n "admin.account_security.event_detail.report_abuse"}}</button>
            </div>
          {{else}}
            <p class="as-page__muted">{{i18n "admin.account_security.event_detail.abuse_report_unavailable"}}</p>
          {{/if}}
        </div>
      </section>
    </div>
  </template>
);
