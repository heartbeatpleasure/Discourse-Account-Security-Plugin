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
          <h1>{{i18n "admin.account_security.intelligence.title"}}</h1>
          <p class="as-page__muted">{{i18n "admin.account_security.intelligence.description"}}</p>
        </div>
        <div class="as-page__actions">
          <a class="btn" href={{overviewUrl}}>{{i18n "admin.account_security.back_overview"}}</a>
        </div>
      </section>

      <section class="as-page__panel">
        <div class="as-page__form-row">
          <div class="as-page__field">
            <label for="as-ip">{{i18n "admin.account_security.intelligence.ip_label"}}</label>
            <input id="as-ip" class="as-page__control" type="text" value={{@controller.ip}} placeholder="8.8.8.8" autocomplete="off" {{on "input" @controller.updateIp}} />
          </div>
          <div class="as-page__buttons">
            <button class="btn btn-primary" type="button" disabled={{@controller.isLoading}} {{on "click" @controller.lookup}}>{{i18n "admin.account_security.intelligence.lookup"}}</button>
            <button class="btn" type="button" disabled={{@controller.isLoading}} {{on "click" (fn @controller.lookup true)}}>{{i18n "admin.account_security.intelligence.refresh"}}</button>
          </div>
        </div>
        <p class="as-page__hint">{{i18n "admin.account_security.intelligence.refresh_hint"}}</p>
      </section>

      {{#if @controller.data}}
        <section class="as-page__metrics">
          <div class="as-page__metric"><div class="as-page__label">IP</div><div class="as-page__value as-page__code">{{if @controller.data.intelligence @controller.data.intelligence.ip_address "—"}}</div></div>
          <div class="as-page__metric"><div class="as-page__label">{{i18n "admin.account_security.intelligence.risk"}}</div><div class="as-page__value">{{if @controller.data.intelligence @controller.data.intelligence.risk_level "—"}}</div></div>
          <div class="as-page__metric"><div class="as-page__label">{{i18n "admin.account_security.intelligence.score"}}</div><div class="as-page__value">{{if @controller.data.intelligence @controller.data.intelligence.primary_score "—"}}</div></div>
          <div class="as-page__metric"><div class="as-page__label">{{i18n "admin.account_security.intelligence.evidence"}}</div><div class="as-page__value">{{if @controller.data.intelligence @controller.data.intelligence.evidence_strength "—"}}</div></div>
        </section>

        {{#if @controller.data.intelligence}}
          <section class="as-page__panel">
            <div class="as-page__section-title"><h2>{{i18n "admin.account_security.intelligence.context"}}</h2></div>
            <div class="as-page__grid">
              <div class="as-page__item"><div class="as-page__label">Tor</div><div class="as-page__value">{{@controller.data.intelligence.is_tor}}</div></div>
              <div class="as-page__item"><div class="as-page__label">{{i18n "admin.account_security.intelligence.blacklist"}}</div><div class="as-page__value">{{@controller.data.intelligence.local_blacklist_match}}</div></div>
              <div class="as-page__item"><div class="as-page__label">ISP</div><div class="as-page__value">{{if @controller.data.intelligence.isp @controller.data.intelligence.isp "—"}}</div></div>
              <div class="as-page__item"><div class="as-page__label">{{i18n "admin.account_security.intelligence.usage_type"}}</div><div class="as-page__value">{{if @controller.data.intelligence.usage_type @controller.data.intelligence.usage_type "—"}}</div></div>
            </div>
          </section>
        {{/if}}

        <section class="as-page__panel">
          <div class="as-page__section-title"><h2>{{i18n "admin.account_security.intelligence.recent_users"}}</h2></div>
          {{#if @controller.data.recent_users.length}}
            <div class="as-page__table-wrap">
              <table class="as-page__table">
                <thead><tr><th>{{i18n "admin.account_security.events.user"}}</th><th>{{i18n "admin.account_security.intelligence.last_seen"}}</th></tr></thead>
                <tbody>{{#each @controller.data.recent_users as |user|}}<tr><td>{{user.username}}</td><td>{{user.last_seen_at}}</td></tr>{{/each}}</tbody>
              </table>
            </div>
          {{else}}
            <p class="as-page__muted">{{i18n "admin.account_security.no_data"}}</p>
          {{/if}}
        </section>
      {{/if}}
    </div>
  </template>
);
