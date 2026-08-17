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
          <h1>{{i18n "admin.account_security.events.title"}}</h1>
          <p class="as-page__muted">{{i18n "admin.account_security.events.description"}}</p>
        </div>
        <div class="as-page__actions">
          <a class="btn" href={{overviewUrl}}>{{i18n "admin.account_security.back_overview"}}</a>
        </div>
      </section>

      <section class="as-page__panel">
        <div class="as-page__toolbar">
          <div class="as-page__field">
            <label>{{i18n "admin.account_security.events.filter_status"}}</label>
            <select class="as-page__control" {{on "change" @controller.setStatus}}>
              <option value="">{{i18n "admin.account_security.all"}}</option>
              <option value="open">Open</option>
              <option value="acknowledged">Acknowledged</option>
              <option value="benign">Benign</option>
              <option value="monitor">Monitor</option>
              <option value="actioned">Actioned</option>
            </select>
          </div>
          <div class="as-page__field">
            <label>{{i18n "admin.account_security.events.filter_severity"}}</label>
            <select class="as-page__control" {{on "change" @controller.setSeverity}}>
              <option value="">{{i18n "admin.account_security.all"}}</option>
              <option value="elevated">Elevated</option>
              <option value="high">High</option>
              <option value="critical">Critical</option>
            </select>
          </div>
        </div>
      </section>

      <section class="as-page__panel">
        {{#if @controller.data}}
          {{#if @controller.data.items.length}}
            <div class="as-page__table-wrap">
              <table class="as-page__table">
                <thead>
                  <tr>
                    <th>{{i18n "admin.account_security.events.last_seen"}}</th>
                    <th>{{i18n "admin.account_security.events.user"}}</th>
                    <th>IP</th>
                    <th>{{i18n "admin.account_security.events.type"}}</th>
                    <th>{{i18n "admin.account_security.events.risk"}}</th>
                    <th>{{i18n "admin.account_security.events.evidence"}}</th>
                    <th>{{i18n "admin.account_security.events.occurrences"}}</th>
                    <th>{{i18n "admin.account_security.events.status"}}</th>
                    <th>{{i18n "admin.account_security.events.actions"}}</th>
                  </tr>
                </thead>
                <tbody>
                  {{#each @controller.data.items as |item|}}
                    <tr>
                      <td>{{item.last_seen_at}}</td>
                      <td>{{if item.user item.user.username "—"}}</td>
                      <td class="as-page__code">{{item.ip_address}}</td>
                      <td>{{item.event_type}}</td>
                      <td><span class="as-page__badge">{{item.risk_level}}</span></td>
                      <td>{{item.evidence_strength}}</td>
                      <td>{{item.occurrence_count}}</td>
                      <td>{{item.status}}</td>
                      <td>
                        <div class="as-page__buttons">
                          <a class="btn btn-small" href={{item.detail_url}}>{{i18n "admin.account_security.events.open_detail"}}</a>
                          <button class="btn btn-small" type="button" {{on "click" (fn @controller.review item "acknowledged")}}>{{i18n "admin.account_security.events.acknowledge"}}</button>
                          <button class="btn btn-small" type="button" {{on "click" (fn @controller.review item "benign")}}>{{i18n "admin.account_security.event_detail.mark_benign"}}</button>
                          <button class="btn btn-small" type="button" {{on "click" (fn @controller.review item "monitor")}}>{{i18n "admin.account_security.events.monitor"}}</button>
                        </div>
                      </td>
                    </tr>
                  {{/each}}
                </tbody>
              </table>
            </div>
          {{else}}
            <p class="as-page__muted">{{i18n "admin.account_security.no_data"}}</p>
          {{/if}}
        {{else}}
          <p class="as-page__muted">{{if @controller.isLoading (i18n "admin.account_security.loading") (i18n "admin.account_security.no_data")}}</p>
        {{/if}}
      </section>
    </div>
  </template>
);
