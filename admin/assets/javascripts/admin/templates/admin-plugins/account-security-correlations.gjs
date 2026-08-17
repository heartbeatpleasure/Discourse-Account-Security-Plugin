import { fn } from "@ember/helper";
import { on } from "@ember/modifier";
import RouteTemplate from "ember-route-template";
import getURL from "discourse/lib/get-url";
import { i18n } from "discourse-i18n";

const overviewUrl = getURL("/admin/plugins/account-security");

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
      .as-page__hero, .as-page__panel, .as-page__metric {
        border: 1px solid var(--as-border);
        border-radius: 18px;
        background: var(--as-surface);
        box-shadow: 0 1px 2px rgb(0 0 0 / 3%);
      }
      .as-page__hero, .as-page__panel {
        min-width: 0;
        padding: 1.2rem 1.35rem;
      }
      .as-page__hero, .as-page__panel-header {
        display: flex;
        align-items: flex-start;
        justify-content: space-between;
        gap: 1rem;
      }
      .as-page__copy { display: grid; min-width: 0; gap: .4rem; }
      .as-page__muted { color: var(--as-muted); }
      .as-page__actions, .as-page__buttons, .as-page__toolbar {
        display: flex;
        flex-wrap: wrap;
        align-items: center;
        gap: .55rem;
      }
      .as-page__actions { margin-left: auto; }
      .as-page__metrics {
        display: grid;
        grid-template-columns: repeat(3, minmax(0, 1fr));
        gap: .8rem;
      }
      .as-page__metric { min-width: 0; padding: .85rem 1rem; }
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
      .as-page__notice {
        padding: .8rem .9rem;
        border-left: 3px solid var(--tertiary);
        border-radius: 8px;
        background: var(--tertiary-very-low);
      }
      .as-page__warning {
        padding: .8rem .9rem;
        border-left: 3px solid var(--danger);
        border-radius: 8px;
        background: var(--danger-low, var(--primary-very-low));
      }
      .as-page__field {
        display: grid;
        min-width: min(12rem, 100%);
        flex: 1 1 12rem;
        gap: .3rem;
      }
      .as-page__field label { font-weight: 700; }
      .as-page__field input, .as-page__field select {
        width: 100%;
        min-height: 42px;
        box-sizing: border-box;
        margin: 0;
        border: 1px solid var(--as-border);
        border-radius: 10px;
        background: var(--as-surface);
      }
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
      .as-page__stack { display: grid; gap: .45rem; }
      .as-page__networks { color: var(--as-muted); font-size: var(--font-down-1); overflow-wrap: anywhere; }
      @media (max-width: 900px) {
        .as-page__hero, .as-page__panel-header { flex-direction: column; }
        .as-page__actions { align-self: flex-end; margin-left: 0; }
        .as-page__metrics { grid-template-columns: 1fr; }
      }
      @media (max-width: 650px) {
        .as-page__field { flex-basis: 100%; }
      }
    </style>

    <div class="as-page">
      <section class="as-page__hero">
        <div class="as-page__copy">
          <h1>{{i18n "admin.account_security.correlations.title"}}</h1>
          <p class="as-page__muted">{{i18n "admin.account_security.correlations.description"}}</p>
        </div>
        <div class="as-page__actions">
          <a class="btn" href={{overviewUrl}}>{{i18n "admin.account_security.back_overview"}}</a>
          <button class="btn" type="button" disabled={{@controller.isLoading}} {{on "click" @controller.loadCorrelations}}>{{i18n "admin.account_security.correlations.refresh"}}</button>
        </div>
      </section>

      <div class="as-page__notice">{{i18n "admin.account_security.correlations.notice"}}</div>

      {{#if @controller.data}}
        <section class="as-page__metrics">
          <div class="as-page__metric">
            <div class="as-page__label">{{i18n "admin.account_security.correlations.enabled"}}</div>
            <div class="as-page__value">{{@controller.data.enabled}}</div>
          </div>
          <div class="as-page__metric">
            <div class="as-page__label">{{i18n "admin.account_security.correlations.open"}}</div>
            <div class="as-page__value">{{@controller.data.open_count}}</div>
          </div>
          <div class="as-page__metric">
            <div class="as-page__label">{{i18n "admin.account_security.correlations.strong"}}</div>
            <div class="as-page__value">{{@controller.data.strong_open_count}}</div>
          </div>
        </section>
      {{/if}}

      <section class="as-page__panel">
        <div class="as-page__panel-header">
          <div class="as-page__copy">
            <h2>{{i18n "admin.account_security.correlations.scan_title"}}</h2>
            <p class="as-page__muted">{{i18n "admin.account_security.correlations.scan_description"}}</p>
          </div>
          <button class="btn btn-primary" type="button" disabled={{@controller.scanBusy}} {{on "click" @controller.rebuild}}>
            {{i18n "admin.account_security.correlations.scan"}}
          </button>
        </div>
        {{#if @controller.data.scan}}
          <div class="as-page__metrics" style="margin-top: .9rem;">
            <div class="as-page__metric">
              <div class="as-page__label">{{i18n "admin.account_security.correlations.scan_state"}}</div>
              <div class="as-page__value">{{@controller.data.scan.state}}</div>
            </div>
            <div class="as-page__metric">
              <div class="as-page__label">{{i18n "admin.account_security.correlations.scan_pairs"}}</div>
              <div class="as-page__value">{{if @controller.data.scan.pairs_processed @controller.data.scan.pairs_processed 0}}</div>
            </div>
            <div class="as-page__metric">
              <div class="as-page__label">{{i18n "admin.account_security.correlations.scan_candidates"}}</div>
              <div class="as-page__value">{{if @controller.data.scan.candidates_found @controller.data.scan.candidates_found 0}}</div>
            </div>
          </div>
          {{#if @controller.data.scan.truncated}}
            <div class="as-page__warning" style="margin-top: .8rem;">{{i18n "admin.account_security.correlations.scan_truncated"}}</div>
          {{/if}}
        {{/if}}
      </section>

      <section class="as-page__panel">
        <div class="as-page__toolbar">
          <div class="as-page__field">
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
          <div class="as-page__field">
            <label>{{i18n "admin.account_security.correlations.filter_confidence"}}</label>
            <select {{on "change" @controller.setConfidence}}>
              <option value="">{{i18n "admin.account_security.all"}}</option>
              <option value="moderate">{{i18n "admin.account_security.correlations.confidences.moderate"}}</option>
              <option value="strong">{{i18n "admin.account_security.correlations.confidences.strong"}}</option>
              <option value="very_strong">{{i18n "admin.account_security.correlations.confidences.very_strong"}}</option>
              <option value="weak">{{i18n "admin.account_security.correlations.confidences.weak"}}</option>
            </select>
          </div>
          <div class="as-page__field">
            <label>{{i18n "admin.account_security.correlations.search"}}</label>
            <input type="search" placeholder={{i18n "admin.account_security.correlations.search_placeholder"}} value={{@controller.search}} {{on "input" @controller.setSearch}} />
          </div>
          <button class="btn" type="button" {{on "click" @controller.applyFilters}}>{{i18n "admin.account_security.correlations.apply"}}</button>
        </div>
      </section>

      <section class="as-page__panel">
        {{#if @controller.data.items.length}}
          <div class="as-page__table-wrap">
            <table class="as-page__table">
              <thead>
                <tr>
                  <th>{{i18n "admin.account_security.correlations.accounts"}}</th>
                  <th>{{i18n "admin.account_security.correlations.score"}}</th>
                  <th>{{i18n "admin.account_security.correlations.confidence"}}</th>
                  <th>{{i18n "admin.account_security.correlations.signals"}}</th>
                  <th>{{i18n "admin.account_security.correlations.last_seen"}}</th>
                  <th>{{i18n "admin.account_security.correlations.status"}}</th>
                  <th>{{i18n "admin.account_security.correlations.actions"}}</th>
                </tr>
              </thead>
              <tbody>
                {{#each @controller.data.items as |item|}}
                  <tr>
                    <td>
                      <div class="as-page__stack">
                        <strong>{{if item.user_a item.user_a.username "—"}}</strong>
                        <strong>{{if item.user_b item.user_b.username "—"}}</strong>
                      </div>
                    </td>
                    <td><span class="as-page__badge">{{item.score}}</span></td>
                    <td>{{item.confidence_label}}</td>
                    <td>
                      <div class="as-page__stack">
                        <span>{{item.signal_summary}}</span>
                        {{#if item.evidence.shared_networks.length}}
                          <span class="as-page__networks">{{item.evidence.shared_networks}}</span>
                        {{/if}}
                        <span class="as-page__networks">
                          {{i18n "admin.account_security.correlations.registration_delta"}}: {{item.evidence.registration_delta_minutes}} {{i18n "admin.account_security.correlations.minutes"}};
                          {{i18n "admin.account_security.correlations.network_users"}}: {{item.evidence.max_shared_network_users}} {{i18n "admin.account_security.correlations.users"}}
                        </span>
                      </div>
                    </td>
                    <td>{{item.last_seen_at}}</td>
                    <td>{{item.status_label}}</td>
                    <td>
                      <div class="as-page__buttons">
                        <button class="btn btn-small" type="button" {{on "click" (fn @controller.review item "monitor")}}>{{i18n "admin.account_security.correlations.mark_monitor"}}</button>
                        <button class="btn btn-small" type="button" {{on "click" (fn @controller.review item "expected_shared_network")}}>{{i18n "admin.account_security.correlations.mark_expected"}}</button>
                        <button class="btn btn-small btn-danger" type="button" {{on "click" (fn @controller.review item "confirmed_duplicate")}}>{{i18n "admin.account_security.correlations.mark_duplicate"}}</button>
                        <button class="btn btn-small" type="button" {{on "click" (fn @controller.review item "dismissed")}}>{{i18n "admin.account_security.correlations.mark_dismissed"}}</button>
                        {{#if item.can_reopen}}
                          <button class="btn btn-small" type="button" {{on "click" (fn @controller.review item "open")}}>{{i18n "admin.account_security.correlations.reopen"}}</button>
                        {{/if}}
                      </div>
                    </td>
                  </tr>
                {{/each}}
              </tbody>
            </table>
          </div>
          <div class="as-page__buttons" style="margin-top: .8rem; justify-content: flex-end;">
            <button class="btn" type="button" disabled={{unless @controller.hasPreviousPage true false}} {{on "click" @controller.previousPage}}>{{i18n "admin.account_security.correlations.previous"}}</button>
            <span class="as-page__muted">{{i18n "admin.account_security.correlations.page"}} {{@controller.data.page}}</span>
            <button class="btn" type="button" disabled={{unless @controller.hasNextPage true false}} {{on "click" @controller.nextPage}}>{{i18n "admin.account_security.correlations.next"}}</button>
          </div>
        {{else}}
          <p class="as-page__muted">{{if @controller.isLoading (i18n "admin.account_security.loading") (i18n "admin.account_security.no_data")}}</p>
        {{/if}}
      </section>
    </div>
  </template>
);
