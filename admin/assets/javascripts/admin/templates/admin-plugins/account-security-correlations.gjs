import { fn } from "@ember/helper";
import { on } from "@ember/modifier";
import RouteTemplate from "ember-route-template";
import getURL from "discourse/lib/get-url";
import { i18n } from "discourse-i18n";

const overviewUrl = getURL("/admin/plugins/account-security");
const settingsUrl = getURL(
  "/admin/site_settings/category/all_results?filter=account_security"
);

export default RouteTemplate(
  <template>
    <style>
      .as-correlation {
        --as-surface: var(--secondary);
        --as-surface-alt: var(--primary-very-low);
        --as-border: var(--primary-low);
        --as-muted: var(--primary-medium);
        display: flex;
        min-width: 0;
        flex-direction: column;
        gap: 1rem;
      }
      .as-correlation h1,
      .as-correlation h2,
      .as-correlation h3,
      .as-correlation h4,
      .as-correlation p { margin: 0; }
      .as-correlation__hero,
      .as-correlation__panel {
        min-width: 0;
        padding: 1.2rem 1.35rem;
        border: 1px solid var(--as-border);
        border-radius: 18px;
        background: var(--as-surface);
        box-shadow: 0 1px 2px rgb(0 0 0 / 3%);
      }
      .as-correlation__hero,
      .as-correlation__panel-header {
        display: flex;
        align-items: flex-start;
        justify-content: space-between;
        gap: 1rem;
      }
      .as-correlation__copy {
        display: flex;
        min-width: 0;
        flex: 1 1 auto;
        flex-direction: column;
        gap: .35rem;
      }
      .as-correlation__muted { color: var(--as-muted); }
      .as-correlation__actions,
      .as-correlation__buttons {
        display: flex;
        flex-wrap: wrap;
        align-items: center;
        gap: .5rem;
      }
      .as-correlation__actions {
        flex: 0 0 auto;
        justify-content: flex-end;
        margin-left: auto;
      }
      .as-correlation__actions .btn,
      .as-correlation__buttons .btn { white-space: nowrap; }
      .as-correlation__notice {
        padding: .85rem 1rem;
        border: 1px solid var(--tertiary-low);
        border-left: 3px solid var(--tertiary);
        border-radius: 12px;
        background: var(--tertiary-very-low);
      }
      .as-correlation__warning {
        padding: .85rem 1rem;
        border: 1px solid var(--danger-low-mid);
        border-radius: 12px;
        background: var(--danger-low);
        color: var(--danger);
      }
      .as-correlation__metrics {
        display: grid;
        grid-template-columns: repeat(3, minmax(0, 1fr));
        gap: .75rem;
      }
      .as-correlation__compact-grid,
      .as-correlation__diagnostics,
      .as-correlation__schedule-summary {
        display: grid;
        grid-template-columns: repeat(4, minmax(0, 1fr));
        gap: .75rem;
      }
      .as-correlation__metric,
      .as-correlation__compact-item,
      .as-correlation__diagnostic {
        min-width: 0;
        padding: .8rem .9rem;
        border: 1px solid var(--as-border);
        border-radius: 12px;
        background: var(--as-surface-alt);
      }
      .as-correlation__label {
        color: var(--as-muted);
        font-size: var(--font-down-1);
        font-weight: 700;
      }
      .as-correlation__value {
        margin-top: .2rem;
        overflow-wrap: anywhere;
        font-weight: 700;
      }
      .as-correlation__metric .as-correlation__value {
        font-size: var(--font-up-1);
        font-variant-numeric: tabular-nums;
      }
      .as-correlation__scan-stack {
        display: grid;
        gap: .8rem;
        margin-top: .9rem;
      }
      .as-correlation__subpanel {
        min-width: 0;
        padding: .95rem;
        border: 1px solid var(--as-border);
        border-radius: 14px;
        background: var(--as-surface-alt);
      }
      .as-correlation__subpanel h3 { margin-bottom: .25rem; }
      .as-correlation__diagnostics { margin-top: .75rem; }
      .as-correlation__diagnostic {
        padding: .65rem .75rem;
        background: var(--secondary);
      }
      .as-correlation__diagnostic .as-correlation__value {
        font-variant-numeric: tabular-nums;
      }
      .as-correlation__schedule-editor {
        display: grid;
        grid-template-columns: minmax(170px, 1fr) minmax(145px, .75fr) minmax(170px, 1fr) minmax(135px, .65fr) auto;
        align-items: end;
        gap: .75rem;
        margin-top: .9rem;
      }
      .as-correlation__schedule-summary {
        grid-template-columns: repeat(2, minmax(0, 1fr));
        margin-top: .85rem;
      }
      .as-correlation__field {
        display: grid;
        min-width: 0;
        gap: .3rem;
      }
      .as-correlation__field label { font-weight: 700; }
      .as-correlation__field input,
      .as-correlation__field select {
        width: 100%;
        min-height: 42px;
        box-sizing: border-box;
        margin: 0;
        border: 1px solid var(--as-border);
        border-radius: 10px;
        background: var(--as-surface);
      }
      .as-correlation__filters {
        display: grid;
        grid-template-columns: minmax(150px, .75fr) minmax(150px, .75fr) minmax(220px, 1.4fr) auto;
        align-items: end;
        gap: .75rem;
      }
      .as-correlation__group-list,
      .as-correlation__candidate-list {
        display: grid;
        gap: .75rem;
        margin-top: .85rem;
      }
      .as-correlation__group,
      .as-correlation__candidate {
        min-width: 0;
        border: 1px solid var(--as-border);
        border-radius: 14px;
        background: var(--as-surface-alt);
        overflow: hidden;
      }
      .as-correlation__group-summary,
      .as-correlation__candidate-summary-line {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 1rem;
        padding: .85rem 1rem;
        cursor: pointer;
        list-style: none;
      }
      .as-correlation__group-summary::-webkit-details-marker,
      .as-correlation__candidate-summary-line::-webkit-details-marker { display: none; }
      .as-correlation__group-summary::before,
      .as-correlation__candidate-summary-line::before {
        content: "▸";
        flex: 0 0 auto;
        color: var(--as-muted);
        font-size: var(--font-up-1);
        transition: transform .15s ease;
      }
      details[open] > .as-correlation__group-summary::before,
      details[open] > .as-correlation__candidate-summary-line::before { transform: rotate(90deg); }
      .as-correlation__summary-main {
        display: flex;
        min-width: 0;
        flex: 1 1 auto;
        flex-direction: column;
        gap: .2rem;
      }
      .as-correlation__summary-title {
        display: flex;
        flex-wrap: wrap;
        align-items: baseline;
        gap: .45rem;
      }
      .as-correlation__summary-title h3 { font-size: var(--font-up-1); }
      .as-correlation__ip-address {
        font-family: var(--d-font-family--monospace);
        font-weight: 700;
        overflow-wrap: anywhere;
      }
      .as-correlation__group-body,
      .as-correlation__candidate-body {
        padding: 0 1rem 1rem;
        border-top: 1px solid var(--as-border);
      }
      .as-correlation__group-meta {
        display: flex;
        flex-wrap: wrap;
        gap: .5rem 1rem;
        margin-top: .8rem;
        color: var(--as-muted);
        font-size: var(--font-down-1);
      }
      .as-correlation__group-accounts {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
        gap: .6rem;
        margin-top: .75rem;
      }
      .as-correlation__group-account {
        min-width: 0;
        padding: .65rem .75rem;
        border-radius: 10px;
        background: var(--secondary);
      }
      .as-correlation__group-account strong { overflow-wrap: anywhere; }
      .as-correlation__group-account .as-correlation__muted {
        margin-top: .25rem;
        font-size: var(--font-down-1);
        overflow-wrap: anywhere;
      }
      .as-correlation__badges {
        display: flex;
        flex: 0 0 auto;
        flex-wrap: wrap;
        justify-content: flex-end;
        gap: .4rem;
      }
      .as-correlation__badge {
        display: inline-flex;
        width: max-content;
        padding: .25rem .55rem;
        border: 1px solid var(--as-border);
        border-radius: 999px;
        background: var(--secondary);
        font-size: var(--font-down-1);
        font-weight: 700;
      }
      .as-correlation__score {
        border-color: var(--tertiary-low);
        background: var(--tertiary-very-low);
      }
      .as-correlation__pair-separator { color: var(--as-muted); }
      .as-correlation__accounts-grid {
        display: grid;
        grid-template-columns: repeat(2, minmax(0, 1fr));
        gap: .7rem;
        margin-top: .8rem;
      }
      .as-correlation__account-card {
        min-width: 0;
        padding: .75rem .85rem;
        border-radius: 12px;
        background: var(--secondary);
      }
      .as-correlation__account-card strong { overflow-wrap: anywhere; }
      .as-correlation__account-meta {
        display: grid;
        grid-template-columns: repeat(2, minmax(0, 1fr));
        gap: .45rem .75rem;
        margin-top: .55rem;
      }
      .as-correlation__account-meta .as-correlation__value {
        font-size: var(--font-down-1);
      }
      .as-correlation__candidate-meta {
        display: grid;
        grid-template-columns: minmax(0, 1.4fr) minmax(230px, .6fr);
        gap: .8rem;
        margin-top: .8rem;
      }
      .as-correlation__signal-box,
      .as-correlation__time-box {
        min-width: 0;
        padding: .75rem .85rem;
        border-radius: 12px;
        background: var(--secondary);
      }
      .as-correlation__time-box { display: grid; gap: .5rem; }
      .as-correlation__evidence-title {
        margin-top: .9rem;
        padding-top: .9rem;
        border-top: 1px solid var(--as-border);
      }
      .as-correlation__evidence-title p { margin-top: .25rem; }
      .as-correlation__ip-list {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
        gap: .7rem;
        margin-top: .7rem;
      }
      .as-correlation__ip-card {
        min-width: 0;
        padding: .8rem;
        border: 1px solid var(--as-border);
        border-radius: 12px;
        background: var(--secondary);
      }
      .as-correlation__ip-card--contextual { border-style: dashed; }
      .as-correlation__ip-meta {
        display: grid;
        gap: .35rem;
        margin-top: .6rem;
        font-size: var(--font-down-1);
      }
      .as-correlation__breakdown {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
        gap: .55rem;
        margin-top: .7rem;
      }
      .as-correlation__reason {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: .75rem;
        min-width: 0;
        padding: .65rem .75rem;
        border-radius: 10px;
        background: var(--secondary);
      }
      .as-correlation__points {
        flex: 0 0 auto;
        font-weight: 700;
        font-variant-numeric: tabular-nums;
      }
      .as-correlation__points--positive { color: var(--success); }
      .as-correlation__points--negative { color: var(--danger); }
      .as-correlation__continuity-note {
        margin-top: .7rem;
        padding: .7rem .8rem;
        border-radius: 10px;
        background: var(--secondary);
        color: var(--as-muted);
        font-size: var(--font-down-1);
      }
      .as-correlation__review {
        display: flex;
        flex-wrap: wrap;
        align-items: center;
        justify-content: space-between;
        gap: .75rem;
        margin-top: .9rem;
        padding-top: .8rem;
        border-top: 1px solid var(--as-border);
      }
      .as-correlation__pagination {
        display: flex;
        align-items: center;
        justify-content: flex-end;
        gap: .6rem;
        margin-top: .9rem;
      }
      .as-correlation__empty {
        padding: 1rem;
        border-radius: 12px;
        background: var(--as-surface-alt);
        color: var(--as-muted);
      }
      @media (max-width: 1150px) {
        .as-correlation__schedule-editor { grid-template-columns: repeat(2, minmax(0, 1fr)); }
        .as-correlation__compact-grid,
        .as-correlation__diagnostics { grid-template-columns: repeat(3, minmax(0, 1fr)); }
      }
      @media (max-width: 900px) {
        .as-correlation__compact-grid,
        .as-correlation__diagnostics { grid-template-columns: repeat(2, minmax(0, 1fr)); }
        .as-correlation__filters { grid-template-columns: 1fr 1fr; }
        .as-correlation__candidate-meta { grid-template-columns: 1fr; }
      }
      @media (max-width: 700px) {
        .as-correlation__hero,
        .as-correlation__panel-header { flex-direction: column; }
        .as-correlation__actions,
        .as-correlation__badges { justify-content: flex-start; margin-left: 0; }
        .as-correlation__metrics,
        .as-correlation__schedule-summary,
        .as-correlation__schedule-editor,
        .as-correlation__filters,
        .as-correlation__accounts-grid { grid-template-columns: 1fr; }
        .as-correlation__group-summary,
        .as-correlation__candidate-summary-line { align-items: flex-start; }
      }
      @media (max-width: 520px) {
        .as-correlation__compact-grid,
        .as-correlation__diagnostics { grid-template-columns: 1fr; }
      }
    </style>

    <div class="as-correlation">
      <section class="as-correlation__hero">
        <div class="as-correlation__copy">
          <h1>{{i18n "admin.account_security.correlations.title"}}</h1>
          <p class="as-correlation__muted">{{i18n "admin.account_security.correlations.description"}}</p>
        </div>
        <div class="as-correlation__actions">
          <a class="btn" href={{overviewUrl}}>{{i18n "admin.account_security.back_overview"}}</a>
          <button class="btn" type="button" disabled={{@controller.isLoading}} {{on "click" @controller.loadCorrelations}}>{{i18n "admin.account_security.correlations.refresh"}}</button>
        </div>
      </section>

      <div class="as-correlation__notice">{{i18n "admin.account_security.correlations.notice"}}</div>

      {{#if @controller.data}}
        <section class="as-correlation__metrics">
          <div class="as-correlation__metric"><div class="as-correlation__label">{{i18n "admin.account_security.correlations.enabled"}}</div><div class="as-correlation__value">{{@controller.data.enabled}}</div></div>
          <div class="as-correlation__metric"><div class="as-correlation__label">{{i18n "admin.account_security.correlations.open"}}</div><div class="as-correlation__value">{{@controller.data.open_count}}</div></div>
          <div class="as-correlation__metric"><div class="as-correlation__label">{{i18n "admin.account_security.correlations.strong"}}</div><div class="as-correlation__value">{{@controller.data.strong_open_count}}</div></div>
        </section>
      {{/if}}

      <section class="as-correlation__panel">
        <div class="as-correlation__panel-header">
          <div class="as-correlation__copy">
            <h2>{{i18n "admin.account_security.correlations.scan_title"}}</h2>
            <p class="as-correlation__muted">{{i18n "admin.account_security.correlations.scan_description"}}</p>
          </div>
          <button class="btn btn-primary" type="button" disabled={{@controller.scanBusy}} {{on "click" @controller.rebuild}}>{{i18n "admin.account_security.correlations.scan"}}</button>
        </div>

        <div class="as-correlation__scan-stack">
          <div class="as-correlation__subpanel">
            <div class="as-correlation__panel-header">
              <div class="as-correlation__copy">
                <h3>{{i18n "admin.account_security.correlations.automatic_scans"}}</h3>
                <p class="as-correlation__muted">{{i18n "admin.account_security.correlations.automatic_scans_description"}}</p>
              </div>
              <a class="btn" href={{settingsUrl}}>{{i18n "admin.account_security.open_settings"}}</a>
            </div>

            {{#if @controller.data.schedule}}
              <div class="as-correlation__schedule-editor">
                <div class="as-correlation__field">
                  <label for="as-correlation-frequency">{{i18n "admin.account_security.correlations.schedule_frequency"}}</label>
                  <select id="as-correlation-frequency" value={{@controller.scheduleFrequency}} {{on "change" @controller.setScheduleFrequency}}>
                    <option value="off">{{i18n "admin.account_security.correlations.frequencies.off"}}</option>
                    <option value="weekly">{{i18n "admin.account_security.correlations.frequencies.weekly"}}</option>
                    <option value="monthly">{{i18n "admin.account_security.correlations.frequencies.monthly"}}</option>
                    <option value="quarterly">{{i18n "admin.account_security.correlations.frequencies.quarterly"}}</option>
                    <option value="yearly">{{i18n "admin.account_security.correlations.frequencies.yearly"}}</option>
                  </select>
                </div>

                {{#if @controller.scheduleEnabled}}
                  <div class="as-correlation__field">
                    <label for="as-correlation-time">{{i18n "admin.account_security.correlations.schedule_time"}}</label>
                    <input id="as-correlation-time" type="time" value={{@controller.scheduleTime}} {{on "input" @controller.setScheduleTime}} />
                  </div>
                {{/if}}

                {{#if @controller.scheduleIsWeekly}}
                  <div class="as-correlation__field">
                    <label for="as-correlation-weekday">{{i18n "admin.account_security.correlations.schedule_weekday"}}</label>
                    <select id="as-correlation-weekday" value={{@controller.scheduleWeekday}} {{on "change" @controller.setScheduleWeekday}}>
                      <option value="monday">{{i18n "admin.account_security.correlations.weekdays.monday"}}</option>
                      <option value="tuesday">{{i18n "admin.account_security.correlations.weekdays.tuesday"}}</option>
                      <option value="wednesday">{{i18n "admin.account_security.correlations.weekdays.wednesday"}}</option>
                      <option value="thursday">{{i18n "admin.account_security.correlations.weekdays.thursday"}}</option>
                      <option value="friday">{{i18n "admin.account_security.correlations.weekdays.friday"}}</option>
                      <option value="saturday">{{i18n "admin.account_security.correlations.weekdays.saturday"}}</option>
                      <option value="sunday">{{i18n "admin.account_security.correlations.weekdays.sunday"}}</option>
                    </select>
                  </div>
                {{/if}}

                {{#if @controller.scheduleUsesDayOfMonth}}
                  <div class="as-correlation__field">
                    <label for="as-correlation-day">{{i18n "admin.account_security.correlations.schedule_day"}}</label>
                    <input id="as-correlation-day" type="number" min="1" max="28" value={{@controller.scheduleDayOfMonth}} {{on "input" @controller.setScheduleDay}} />
                  </div>
                {{/if}}

                <button class="btn btn-primary" type="button" disabled={{@controller.isSavingSchedule}} {{on "click" @controller.saveSchedule}}>{{i18n "admin.account_security.correlations.schedule_save"}}</button>
              </div>
              <p class="as-correlation__muted" style="margin-top: .55rem;">{{i18n "admin.account_security.correlations.schedule_local_time_hint"}}</p>

              <div class="as-correlation__schedule-summary">
                <div class="as-correlation__compact-item"><div class="as-correlation__label">{{i18n "admin.account_security.correlations.schedule_next"}}</div><div class="as-correlation__value">{{@controller.data.schedule.next_run_at_display}}</div></div>
                <div class="as-correlation__compact-item"><div class="as-correlation__label">{{i18n "admin.account_security.correlations.schedule_last"}}</div><div class="as-correlation__value">{{@controller.data.schedule.last_scheduled_at_display}}</div></div>
              </div>
            {{/if}}
          </div>

          <div class="as-correlation__subpanel">
            <h3>{{i18n "admin.account_security.correlations.scan_diagnostics"}}</h3>
            <p class="as-correlation__muted">{{i18n "admin.account_security.correlations.scan_diagnostics_description"}}</p>
            {{#if @controller.data.scan}}
              <div class="as-correlation__compact-grid" style="margin-top: .75rem;">
                <div class="as-correlation__compact-item"><div class="as-correlation__label">{{i18n "admin.account_security.correlations.scan_state"}}</div><div class="as-correlation__value">{{@controller.data.scan.state}}</div></div>
                <div class="as-correlation__compact-item"><div class="as-correlation__label">{{i18n "admin.account_security.correlations.scan_pairs"}}</div><div class="as-correlation__value">{{if @controller.data.scan.pairs_processed @controller.data.scan.pairs_processed 0}}</div></div>
                <div class="as-correlation__compact-item"><div class="as-correlation__label">{{i18n "admin.account_security.correlations.scan_candidates"}}</div><div class="as-correlation__value">{{if @controller.data.scan.candidates_found @controller.data.scan.candidates_found 0}}</div></div>
                <div class="as-correlation__compact-item"><div class="as-correlation__label">{{i18n "admin.account_security.correlations.scan_source"}}</div><div class="as-correlation__value">{{@controller.data.scan.source_label}}</div></div>
              </div>
              <div class="as-correlation__diagnostics">
                {{#each @controller.data.scan.diagnostic_cards as |card|}}
                  <div class="as-correlation__diagnostic"><div class="as-correlation__label">{{card.label}}</div><div class="as-correlation__value">{{card.value}}</div></div>
                {{/each}}
              </div>
              {{#if @controller.data.scan.started_at}}
                <p class="as-correlation__muted" style="margin-top: .65rem;">{{i18n "admin.account_security.correlations.scan_started"}}: {{@controller.data.scan.started_at_display}}{{#if @controller.data.scan.completed_at}} · {{i18n "admin.account_security.correlations.scan_completed"}}: {{@controller.data.scan.completed_at_display}}{{/if}}</p>
              {{/if}}
              {{#if @controller.data.scan.auth_log_truncated}}<div class="as-correlation__warning" style="margin-top: .7rem;">{{i18n "admin.account_security.correlations.diagnostics_auth_truncated"}}</div>{{/if}}
              {{#if @controller.data.scan.truncated}}<div class="as-correlation__warning" style="margin-top: .7rem;">{{i18n "admin.account_security.correlations.scan_truncated"}}</div>{{/if}}
            {{else}}
              <div class="as-correlation__empty" style="margin-top: .75rem;">{{i18n "admin.account_security.no_data"}}</div>
            {{/if}}
          </div>
        </div>
      </section>

      {{#if @controller.data.shared_ip_groups.length}}
        <section class="as-correlation__panel">
          <div class="as-correlation__copy">
            <h2>{{i18n "admin.account_security.correlations.shared_ip_groups_title"}}</h2>
            <p class="as-correlation__muted">{{i18n "admin.account_security.correlations.shared_ip_groups_description"}}</p>
          </div>
          <div class="as-correlation__group-list">
            {{#each @controller.data.shared_ip_groups as |group|}}
              <details class="as-correlation__group">
                <summary class="as-correlation__group-summary">
                  <div class="as-correlation__summary-main">
                    <div class="as-correlation__summary-title">
                      <span class="as-correlation__ip-address">{{group.ip_address}}</span>
                      <strong>{{group.account_count_label}}</strong>
                    </div>
                    <span class="as-correlation__muted">{{group.coverage_label}} · {{group.pair_count_label}}</span>
                  </div>
                  <div class="as-correlation__badges">
                    {{#unless group.public}}<span class="as-correlation__badge">{{i18n "admin.account_security.correlations.context_nonpublic"}}</span>{{/unless}}
                    {{#if group.tor}}<span class="as-correlation__badge">{{i18n "admin.account_security.correlations.context_tor"}}</span>{{/if}}
                    {{#if group.hosting}}<span class="as-correlation__badge">{{i18n "admin.account_security.correlations.context_hosting"}}</span>{{/if}}
                    {{#if group.mobile}}<span class="as-correlation__badge">{{i18n "admin.account_security.correlations.context_mobile"}}</span>{{/if}}
                    {{#if group.trusted}}<span class="as-correlation__badge">{{i18n "admin.account_security.correlations.context_trusted"}}</span>{{/if}}
                  </div>
                </summary>
                <div class="as-correlation__group-body">
                  <div class="as-correlation__group-meta">
                    <span>{{i18n "admin.account_security.correlations.group_registration_accounts" count=group.registration_account_count}}</span>
                    <span>{{i18n "admin.account_security.correlations.group_auth_accounts" count=group.auth_account_count}}</span>
                    <span>{{i18n "admin.account_security.correlations.ip_context"}}: {{group.context_display}}</span>
                  </div>
                  <div class="as-correlation__group-accounts">
                    {{#each group.accounts as |account|}}
                      <div class="as-correlation__group-account">
                        <strong>{{account.username}}</strong>
                        <div class="as-correlation__muted">{{account.sources_display}}</div>
                      </div>
                    {{/each}}
                  </div>
                </div>
              </details>
            {{/each}}
          </div>
        </section>
      {{/if}}

      <section class="as-correlation__panel">
        <div class="as-correlation__filters">
          <div class="as-correlation__field">
            <label>{{i18n "admin.account_security.correlations.filter_status"}}</label>
            <select {{on "change" @controller.setStatus}}>
              <option value="">{{i18n "admin.account_security.all"}}</option>
              <option value="open">{{i18n "admin.account_security.correlations.statuses.open"}}</option>
              <option value="monitor">{{i18n "admin.account_security.correlations.statuses.monitor"}}</option>
              <option value="expected_shared_network">{{i18n "admin.account_security.correlations.statuses.expected_shared_network"}}</option>
              <option value="confirmed_duplicate">{{i18n "admin.account_security.correlations.statuses.confirmed_duplicate"}}</option>
              <option value="dismissed">{{i18n "admin.account_security.correlations.statuses.dismissed"}}</option>
            </select>
          </div>
          <div class="as-correlation__field">
            <label>{{i18n "admin.account_security.correlations.filter_confidence"}}</label>
            <select {{on "change" @controller.setConfidence}}>
              <option value="">{{i18n "admin.account_security.all"}}</option>
              <option value="weak">{{i18n "admin.account_security.correlations.confidences.weak"}}</option>
              <option value="moderate">{{i18n "admin.account_security.correlations.confidences.moderate"}}</option>
              <option value="strong">{{i18n "admin.account_security.correlations.confidences.strong"}}</option>
              <option value="very_strong">{{i18n "admin.account_security.correlations.confidences.very_strong"}}</option>
            </select>
          </div>
          <div class="as-correlation__field">
            <label>{{i18n "admin.account_security.correlations.search"}}</label>
            <input type="search" placeholder={{i18n "admin.account_security.correlations.search_placeholder"}} value={{@controller.search}} {{on "input" @controller.setSearch}} />
          </div>
          <button class="btn" type="button" {{on "click" @controller.applyFilters}}>{{i18n "admin.account_security.correlations.apply"}}</button>
        </div>
      </section>

      <section class="as-correlation__panel">
        <div class="as-correlation__copy">
          <h2>{{i18n "admin.account_security.correlations.pair_comparisons_title"}}</h2>
          <p class="as-correlation__muted">{{i18n "admin.account_security.correlations.pair_comparisons_description"}}</p>
        </div>
        {{#if @controller.data.items.length}}
          <div class="as-correlation__candidate-list">
            {{#each @controller.data.items as |item|}}
              <details class="as-correlation__candidate">
                <summary class="as-correlation__candidate-summary-line">
                  <div class="as-correlation__summary-main">
                    <div class="as-correlation__summary-title">
                      <h3>{{if item.user_a item.user_a.username "—"}}</h3>
                      <span class="as-correlation__pair-separator">↔</span>
                      <h3>{{if item.user_b item.user_b.username "—"}}</h3>
                    </div>
                  </div>
                  <div class="as-correlation__badges">
                    <span class="as-correlation__badge as-correlation__score">{{i18n "admin.account_security.correlations.score"}} {{item.score}}</span>
                    <span class="as-correlation__badge">{{item.confidence_label}}</span>
                    <span class="as-correlation__badge">{{item.status_label}}</span>
                  </div>
                </summary>

                <div class="as-correlation__candidate-body">
                  <div class="as-correlation__accounts-grid">
                    {{#if item.user_a}}
                      <div class="as-correlation__account-card">
                        <strong>{{item.user_a.username}}</strong>
                        <div class="as-correlation__account-meta">
                          <div><div class="as-correlation__label">{{i18n "admin.account_security.correlations.registered"}}</div><div class="as-correlation__value">{{item.user_a.created_at_display}}</div></div>
                          <div><div class="as-correlation__label">{{i18n "admin.account_security.correlations.account_last_seen"}}</div><div class="as-correlation__value">{{item.user_a.last_seen_at_display}}</div></div>
                          <div><div class="as-correlation__label">{{i18n "admin.account_security.correlations.account_active"}}</div><div class="as-correlation__value">{{if item.user_a.active (i18n "admin.account_security.correlations.yes") (i18n "admin.account_security.correlations.no")}}</div></div>
                          <div><div class="as-correlation__label">{{i18n "admin.account_security.correlations.account_suspended"}}</div><div class="as-correlation__value">{{if item.user_a.suspended (i18n "admin.account_security.correlations.yes") (i18n "admin.account_security.correlations.no")}}</div></div>
                        </div>
                      </div>
                    {{/if}}
                    {{#if item.user_b}}
                      <div class="as-correlation__account-card">
                        <strong>{{item.user_b.username}}</strong>
                        <div class="as-correlation__account-meta">
                          <div><div class="as-correlation__label">{{i18n "admin.account_security.correlations.registered"}}</div><div class="as-correlation__value">{{item.user_b.created_at_display}}</div></div>
                          <div><div class="as-correlation__label">{{i18n "admin.account_security.correlations.account_last_seen"}}</div><div class="as-correlation__value">{{item.user_b.last_seen_at_display}}</div></div>
                          <div><div class="as-correlation__label">{{i18n "admin.account_security.correlations.account_active"}}</div><div class="as-correlation__value">{{if item.user_b.active (i18n "admin.account_security.correlations.yes") (i18n "admin.account_security.correlations.no")}}</div></div>
                          <div><div class="as-correlation__label">{{i18n "admin.account_security.correlations.account_suspended"}}</div><div class="as-correlation__value">{{if item.user_b.suspended (i18n "admin.account_security.correlations.yes") (i18n "admin.account_security.correlations.no")}}</div></div>
                        </div>
                      </div>
                    {{/if}}
                  </div>

                  <div class="as-correlation__candidate-meta">
                    <div class="as-correlation__signal-box">
                      <div class="as-correlation__label">{{i18n "admin.account_security.correlations.signals"}}</div>
                      <div class="as-correlation__value">{{item.signal_summary}}</div>
                      {{#if item.evidence.shared_networks.length}}<p class="as-correlation__muted" style="margin-top: .35rem;">{{item.evidence.shared_networks}}</p>{{/if}}
                    </div>
                    <div class="as-correlation__time-box">
                      <div><div class="as-correlation__label">{{i18n "admin.account_security.correlations.first_seen"}}</div><div class="as-correlation__value">{{item.first_seen_at_display}}</div></div>
                      <div><div class="as-correlation__label">{{i18n "admin.account_security.correlations.last_seen"}}</div><div class="as-correlation__value">{{item.last_seen_at_display}}</div></div>
                    </div>
                  </div>

                  {{#if item.shared_ip_details.length}}
                    <div class="as-correlation__evidence-title">
                      <h4>{{i18n "admin.account_security.correlations.exact_ip_evidence"}}</h4>
                      <p class="as-correlation__muted">{{i18n "admin.account_security.correlations.exact_ip_evidence_description"}}</p>
                    </div>
                    <div class="as-correlation__ip-list">
                      {{#each item.shared_ip_details as |detail|}}
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

                  {{#if item.score_breakdown.length}}
                    <div class="as-correlation__evidence-title">
                      <h4>{{i18n "admin.account_security.correlations.score_explanation"}}</h4>
                      <p class="as-correlation__muted">{{i18n "admin.account_security.correlations.score_explanation_description"}}</p>
                    </div>
                    <div class="as-correlation__breakdown">
                      {{#each item.score_breakdown as |entry|}}
                        <div class="as-correlation__reason">
                          <span>{{entry.label}}</span>
                          <span class="as-correlation__points {{if entry.positive "as-correlation__points--positive" ""}} {{if entry.negative "as-correlation__points--negative" ""}}">{{entry.points_display}}</span>
                        </div>
                      {{/each}}
                    </div>
                  {{/if}}

                  {{#if item.evidence.browser_continuity_count}}
                    <div class="as-correlation__continuity-note">{{i18n "admin.account_security.correlations.browser_continuity_note"}}</div>
                  {{/if}}

                  <div class="as-correlation__review">
                    <div class="as-correlation__muted">{{item.status_label}}</div>
                    <div class="as-correlation__buttons">
                      <button class="btn btn-small" type="button" {{on "click" (fn @controller.review item "monitor")}}>{{i18n "admin.account_security.correlations.mark_monitor"}}</button>
                      <button class="btn btn-small" type="button" {{on "click" (fn @controller.review item "expected_shared_network")}}>{{i18n "admin.account_security.correlations.mark_expected"}}</button>
                      <button class="btn btn-small btn-danger" type="button" {{on "click" (fn @controller.review item "confirmed_duplicate")}}>{{i18n "admin.account_security.correlations.mark_duplicate"}}</button>
                      <button class="btn btn-small" type="button" {{on "click" (fn @controller.review item "dismissed")}}>{{i18n "admin.account_security.correlations.mark_dismissed"}}</button>
                      {{#if item.can_reopen}}<button class="btn btn-small" type="button" {{on "click" (fn @controller.review item "open")}}>{{i18n "admin.account_security.correlations.reopen"}}</button>{{/if}}
                    </div>
                  </div>
                </div>
              </details>
            {{/each}}
          </div>

          <div class="as-correlation__pagination">
            <button class="btn" type="button" disabled={{unless @controller.hasPreviousPage true false}} {{on "click" @controller.previousPage}}>{{i18n "admin.account_security.correlations.previous"}}</button>
            <span class="as-correlation__muted">{{i18n "admin.account_security.correlations.page"}} {{@controller.data.page}}</span>
            <button class="btn" type="button" disabled={{unless @controller.hasNextPage true false}} {{on "click" @controller.nextPage}}>{{i18n "admin.account_security.correlations.next"}}</button>
          </div>
        {{else}}
          <div class="as-correlation__empty" style="margin-top: .85rem;">{{if @controller.isLoading (i18n "admin.account_security.loading") (i18n "admin.account_security.no_data")}}</div>
        {{/if}}
      </section>
    </div>
  </template>
);
