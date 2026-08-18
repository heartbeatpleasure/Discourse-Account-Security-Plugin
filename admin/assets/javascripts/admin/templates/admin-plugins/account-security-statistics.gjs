import { on } from "@ember/modifier";
import RouteTemplate from "ember-route-template";
import getURL from "discourse/lib/get-url";
import { i18n } from "discourse-i18n";

const overviewUrl = getURL("/admin/plugins/account-security");

export default RouteTemplate(
  <template>
    <style>
      .as-stats {
        --as-surface: var(--secondary);
        --as-surface-alt: var(--primary-very-low);
        --as-border: var(--primary-low);
        --as-muted: var(--primary-medium);
        display: flex;
        flex-direction: column;
        gap: 1rem;
        min-width: 0;
      }
      .as-stats h1, .as-stats h2, .as-stats h3, .as-stats h4, .as-stats p { margin: 0; }
      .as-stats__hero, .as-stats__panel {
        min-width: 0;
        padding: 1.2rem 1.35rem;
        border: 1px solid var(--as-border);
        border-radius: 18px;
        background: var(--as-surface);
        box-shadow: 0 1px 2px rgb(0 0 0 / 3%);
      }
      .as-stats__hero {
        display: flex;
        align-items: flex-start;
        justify-content: space-between;
        gap: 1rem;
      }
      .as-stats__copy {
        display: flex;
        min-width: 0;
        flex: 1 1 auto;
        flex-direction: column;
        gap: .35rem;
      }
      .as-stats__muted { color: var(--as-muted); }
      .as-stats__actions {
        display: flex;
        flex: 0 0 auto;
        flex-wrap: wrap;
        align-items: center;
        justify-content: flex-end;
        gap: .5rem;
        margin-left: auto;
      }
      .as-stats__actions .btn { white-space: nowrap; }
      .as-stats__toolbar {
        display: flex;
        align-items: flex-end;
        justify-content: space-between;
        gap: 1rem;
      }
      .as-stats__period-control {
        width: min(18rem, 100%);
        min-height: 42px;
        margin: 0;
        padding: 0 .85rem;
        border: 1px solid var(--as-border);
        border-radius: 12px;
        background: var(--as-surface-alt);
        color: var(--primary);
        box-sizing: border-box;
      }
      .as-stats__summary-grid {
        display: grid;
        grid-template-columns: repeat(4, minmax(0, 1fr));
        gap: .75rem;
      }
      .as-stats__summary-card {
        min-width: 0;
        padding: .8rem .9rem;
        border: 1px solid var(--as-border);
        border-radius: 12px;
        background: var(--as-surface-alt);
      }
      .as-stats__summary-label {
        color: var(--as-muted);
        font-size: var(--font-down-1);
        font-weight: 700;
      }
      .as-stats__summary-value {
        margin-top: .2rem;
        font-size: var(--font-up-2);
        font-weight: 700;
        font-variant-numeric: tabular-nums;
      }
      .as-stats__daily-list {
        display: grid;
        gap: .8rem;
        margin-top: .9rem;
      }
      .as-stats__daily-card {
        min-width: 0;
        padding: .9rem;
        border: 1px solid var(--as-border);
        border-radius: 14px;
        background: var(--as-surface-alt);
      }
      .as-stats__daily-header {
        display: flex;
        align-items: baseline;
        justify-content: space-between;
        gap: 1rem;
        padding-bottom: .7rem;
        border-bottom: 1px solid var(--as-border);
      }
      .as-stats__daily-header h3 { font-size: var(--font-up-1); }
      .as-stats__daily-subtitle {
        color: var(--as-muted);
        font-size: var(--font-down-1);
        font-weight: 700;
      }
      .as-stats__daily-groups {
        display: grid;
        grid-template-columns: repeat(3, minmax(0, 1fr));
        gap: .65rem;
        margin-top: .7rem;
      }
      .as-stats__daily-group {
        min-width: 0;
        padding: .7rem;
        border-radius: 11px;
        background: var(--secondary);
      }
      .as-stats__daily-group h4 {
        margin-bottom: .55rem;
        color: var(--as-muted);
        font-size: var(--font-down-1);
        font-weight: 700;
      }
      .as-stats__daily-metrics {
        display: grid;
        grid-template-columns: repeat(2, minmax(0, 1fr));
        gap: .5rem .75rem;
      }
      .as-stats__daily-metric { min-width: 0; }
      .as-stats__daily-metric-label {
        color: var(--as-muted);
        font-size: var(--font-down-2);
      }
      .as-stats__daily-metric-value {
        margin-top: .08rem;
        font-weight: 700;
        font-variant-numeric: tabular-nums;
        overflow-wrap: anywhere;
      }
      .as-stats__empty {
        margin-top: .8rem;
        padding: 1rem;
        border-radius: 12px;
        background: var(--as-surface-alt);
        color: var(--as-muted);
      }
      @media (max-width: 1000px) {
        .as-stats__summary-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
        .as-stats__daily-groups { grid-template-columns: 1fr 1fr; }
      }
      @media (max-width: 700px) {
        .as-stats__hero { flex-direction: column; }
        .as-stats__actions { justify-content: flex-start; margin-left: 0; }
        .as-stats__toolbar { flex-direction: column; align-items: stretch; }
        .as-stats__period-control { width: 100%; }
        .as-stats__summary-grid,
        .as-stats__daily-groups { grid-template-columns: 1fr; }
        .as-stats__daily-header { flex-direction: column; align-items: flex-start; gap: .25rem; }
      }
      @media (max-width: 460px) {
        .as-stats__daily-metrics { grid-template-columns: 1fr; }
      }
    </style>

    <div class="as-stats">
      <section class="as-stats__hero">
        <div class="as-stats__copy">
          <h1>{{i18n "admin.account_security.statistics.title"}}</h1>
          <p class="as-stats__muted">{{i18n "admin.account_security.statistics.description"}}</p>
        </div>
        <div class="as-stats__actions">
          <a class="btn" href={{overviewUrl}}>{{i18n "admin.account_security.back_overview"}}</a>
        </div>
      </section>

      <section class="as-stats__panel">
        <div class="as-stats__toolbar">
          <div class="as-stats__copy">
            <h2>{{i18n "admin.account_security.statistics.period"}}</h2>
            <p class="as-stats__muted">{{i18n "admin.account_security.statistics.period_description"}}</p>
          </div>
          <select class="as-stats__period-control" id="account-security-statistics-period" value={{@controller.period}} aria-label={{i18n "admin.account_security.statistics.period"}} disabled={{@controller.isLoading}} {{on "change" @controller.setPeriod}}>
            <option value="7">{{i18n "admin.account_security.statistics.days_7"}}</option>
            <option value="30">{{i18n "admin.account_security.statistics.days_30"}}</option>
            <option value="90">{{i18n "admin.account_security.statistics.days_90"}}</option>
            <option value="365">{{i18n "admin.account_security.statistics.days_365"}}</option>
          </select>
        </div>
      </section>

      {{#if @controller.data}}
        <section class="as-stats__summary-grid">
          <div class="as-stats__summary-card"><div class="as-stats__summary-label">{{i18n "admin.account_security.statistics.assessments"}}</div><div class="as-stats__summary-value">{{@controller.data.totals.assessments}}</div></div>
          <div class="as-stats__summary-card"><div class="as-stats__summary-label">{{i18n "admin.account_security.statistics.provider_calls"}}</div><div class="as-stats__summary-value">{{@controller.data.totals.provider_calls}}</div></div>
          <div class="as-stats__summary-card"><div class="as-stats__summary-label">{{i18n "admin.account_security.statistics.cache_hits"}}</div><div class="as-stats__summary-value">{{@controller.data.totals.cache_hits}}</div></div>
          <div class="as-stats__summary-card"><div class="as-stats__summary-label">{{i18n "admin.account_security.statistics.events"}}</div><div class="as-stats__summary-value">{{@controller.data.totals.events_created}}</div></div>
          <div class="as-stats__summary-card"><div class="as-stats__summary-label">{{i18n "admin.account_security.statistics.auth_abuse_clusters"}}</div><div class="as-stats__summary-value">{{@controller.data.totals.auth_abuse_clusters}}</div></div>
          <div class="as-stats__summary-card"><div class="as-stats__summary-label">{{i18n "admin.account_security.statistics.notifications_sent"}}</div><div class="as-stats__summary-value">{{@controller.data.totals.notifications_sent}}</div></div>
          <div class="as-stats__summary-card"><div class="as-stats__summary-label">{{i18n "admin.account_security.statistics.correlation_candidates"}}</div><div class="as-stats__summary-value">{{@controller.data.totals.correlation_candidates}}</div></div>
          <div class="as-stats__summary-card"><div class="as-stats__summary-label">{{i18n "admin.account_security.statistics.correlation_scans"}}</div><div class="as-stats__summary-value">{{@controller.data.totals.correlation_scans}}</div></div>
        </section>

        <section class="as-stats__panel">
          <div class="as-stats__copy">
            <h2>{{i18n "admin.account_security.statistics.daily_breakdown"}}</h2>
            <p class="as-stats__muted">{{i18n "admin.account_security.statistics.daily_breakdown_description"}}</p>
          </div>

          {{#if @controller.data.daily.length}}
            <div class="as-stats__daily-list">
              {{#each @controller.data.daily as |day|}}
                <article class="as-stats__daily-card">
                  <div class="as-stats__daily-header">
                    <h3>{{day.stat_date_display}}</h3>
                    <div class="as-stats__daily-subtitle">{{i18n "admin.account_security.statistics.daily_summary"}}</div>
                  </div>
                  <div class="as-stats__daily-groups">
                    <section class="as-stats__daily-group">
                      <h4>{{i18n "admin.account_security.statistics.group_provider"}}</h4>
                      <div class="as-stats__daily-metrics">
                        <div class="as-stats__daily-metric"><div class="as-stats__daily-metric-label">{{i18n "admin.account_security.statistics.assessments"}}</div><div class="as-stats__daily-metric-value">{{day.assessments}}</div></div>
                        <div class="as-stats__daily-metric"><div class="as-stats__daily-metric-label">{{i18n "admin.account_security.statistics.provider_calls"}}</div><div class="as-stats__daily-metric-value">{{day.provider_calls}}</div></div>
                        <div class="as-stats__daily-metric"><div class="as-stats__daily-metric-label">{{i18n "admin.account_security.statistics.cache_hits"}}</div><div class="as-stats__daily-metric-value">{{day.cache_hits}}</div></div>
                        <div class="as-stats__daily-metric"><div class="as-stats__daily-metric-label">{{i18n "admin.account_security.statistics.quota_skips"}}</div><div class="as-stats__daily-metric-value">{{day.quota_skips}}</div></div>
                      </div>
                    </section>
                    <section class="as-stats__daily-group">
                      <h4>{{i18n "admin.account_security.statistics.group_local"}}</h4>
                      <div class="as-stats__daily-metrics">
                        <div class="as-stats__daily-metric"><div class="as-stats__daily-metric-label">{{i18n "admin.account_security.statistics.blacklist_hits"}}</div><div class="as-stats__daily-metric-value">{{day.local_blacklist_hits}}</div></div>
                        <div class="as-stats__daily-metric"><div class="as-stats__daily-metric-label">{{i18n "admin.account_security.statistics.tor_hits"}}</div><div class="as-stats__daily-metric-value">{{day.tor_hits}}</div></div>
                        <div class="as-stats__daily-metric"><div class="as-stats__daily-metric-label">{{i18n "admin.account_security.statistics.auth_abuse_clusters"}}</div><div class="as-stats__daily-metric-value">{{day.auth_abuse_clusters}}</div></div>
                        <div class="as-stats__daily-metric"><div class="as-stats__daily-metric-label">{{i18n "admin.account_security.statistics.correlation_candidates"}}</div><div class="as-stats__daily-metric-value">{{day.correlation_candidates}}</div></div>
                      </div>
                    </section>
                    <section class="as-stats__daily-group">
                      <h4>{{i18n "admin.account_security.statistics.group_outcomes"}}</h4>
                      <div class="as-stats__daily-metrics">
                        <div class="as-stats__daily-metric"><div class="as-stats__daily-metric-label">{{i18n "admin.account_security.statistics.events"}}</div><div class="as-stats__daily-metric-value">{{day.events_created}}</div></div>
                        <div class="as-stats__daily-metric"><div class="as-stats__daily-metric-label">{{i18n "admin.account_security.statistics.notifications_sent"}}</div><div class="as-stats__daily-metric-value">{{day.notifications_sent}}</div></div>
                        <div class="as-stats__daily-metric"><div class="as-stats__daily-metric-label">{{i18n "admin.account_security.statistics.correlation_scans"}}</div><div class="as-stats__daily-metric-value">{{day.correlation_scans}}</div></div>
                      </div>
                    </section>
                  </div>
                </article>
              {{/each}}
            </div>
          {{else}}
            <div class="as-stats__empty">{{i18n "admin.account_security.no_data"}}</div>
          {{/if}}
        </section>
      {{else}}
        <p class="as-stats__muted">{{i18n "admin.account_security.loading"}}</p>
      {{/if}}
    </div>
  </template>
);
