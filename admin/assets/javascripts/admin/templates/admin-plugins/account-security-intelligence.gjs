import { fn } from "@ember/helper";
import { on } from "@ember/modifier";
import RouteTemplate from "ember-route-template";
import getURL from "discourse/lib/get-url";
import { i18n } from "discourse-i18n";

const overviewUrl = getURL("/admin/plugins/account-security");

export default RouteTemplate(
  <template>
    <div class="as-admin">
      <section class="as-admin__hero">
        <div class="as-admin__hero-copy">
          <h1>{{i18n "admin.account_security.intelligence.title"}}</h1>
          <p>{{i18n "admin.account_security.intelligence.description"}}</p>
        </div>
        <div class="as-admin__hero-actions">
          <a class="btn" href={{overviewUrl}}>{{i18n "admin.account_security.back_overview"}}</a>
        </div>
      </section>

      <section class="as-admin__panel">
        <div class="as-admin__form">
          <div class="as-admin__field">
            <label for="as-ip">{{i18n "admin.account_security.intelligence.ip_label"}}</label>
            <input id="as-ip" type="text" value={{this.ip}} placeholder="8.8.8.8" {{on "input" this.updateIp}} />
          </div>
          <div class="as-admin__buttons">
            <button class="btn btn-primary" type="button" disabled={{this.isLoading}} {{on "click" this.lookup}}>
              {{i18n "admin.account_security.intelligence.lookup"}}
            </button>
            <button class="btn" type="button" disabled={{this.isLoading}} {{on "click" (fn this.lookup true)}}>
              {{i18n "admin.account_security.intelligence.refresh"}}
            </button>
          </div>
          <p class="as-admin__hint">{{i18n "admin.account_security.intelligence.refresh_hint"}}</p>
        </div>
      </section>

      {{#if this.data}}
        <section class="as-admin__section">
          <div class="as-admin__metrics">
            <div class="as-admin__metric"><div class="as-admin__metric-label">IP</div><div class="as-admin__metric-value as-admin__code">{{if this.data.intelligence this.data.intelligence.ip_address "—"}}</div></div>
            <div class="as-admin__metric"><div class="as-admin__metric-label">{{i18n "admin.account_security.intelligence.risk"}}</div><div class="as-admin__metric-value">{{if this.data.intelligence this.data.intelligence.risk_level "—"}}</div></div>
            <div class="as-admin__metric"><div class="as-admin__metric-label">{{i18n "admin.account_security.intelligence.score"}}</div><div class="as-admin__metric-value">{{if this.data.intelligence this.data.intelligence.primary_score "—"}}</div></div>
            <div class="as-admin__metric"><div class="as-admin__metric-label">{{i18n "admin.account_security.intelligence.evidence"}}</div><div class="as-admin__metric-value">{{if this.data.intelligence this.data.intelligence.evidence_strength "—"}}</div></div>
          </div>
        </section>

        {{#if this.data.intelligence}}
          <section class="as-admin__panel">
            <h2>{{i18n "admin.account_security.intelligence.context"}}</h2>
            <div class="as-admin__form-row">
              <div><strong>Tor:</strong> {{this.data.intelligence.is_tor}}</div>
              <div><strong>{{i18n "admin.account_security.intelligence.blacklist"}}:</strong> {{this.data.intelligence.local_blacklist_match}}</div>
              <div><strong>ISP:</strong> {{if this.data.intelligence.isp this.data.intelligence.isp "—"}}</div>
              <div><strong>{{i18n "admin.account_security.intelligence.usage_type"}}:</strong> {{if this.data.intelligence.usage_type this.data.intelligence.usage_type "—"}}</div>
            </div>
          </section>
        {{/if}}

        <section class="as-admin__panel">
          <h2>{{i18n "admin.account_security.intelligence.recent_users"}}</h2>
          {{#if this.data.recent_users.length}}
            <div class="as-admin__table-wrap">
              <table class="as-admin__table">
                <thead><tr><th>User</th><th>{{i18n "admin.account_security.intelligence.last_seen"}}</th></tr></thead>
                <tbody>{{#each this.data.recent_users as |user|}}<tr><td>{{user.username}}</td><td>{{user.last_seen_at}}</td></tr>{{/each}}</tbody>
              </table>
            </div>
          {{else}}
            <p class="as-admin__muted">{{i18n "admin.account_security.no_data"}}</p>
          {{/if}}
        </section>
      {{/if}}
    </div>
  </template>
);
