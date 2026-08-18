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
        gap: .5rem;
      }
      .as-page__actions {
        justify-content: flex-end;
        margin-left: auto;
      }
      .as-page__buttons { justify-content: flex-start; }
      .as-page__actions .btn, .as-page__buttons .btn { white-space: nowrap; }
      .as-page__metrics {
        display: grid;
        grid-template-columns: repeat(4, minmax(0, 1fr));
        gap: .75rem;
      }
      .as-page__health-grid {
        display: grid;
        grid-template-columns: minmax(280px, 1fr) minmax(340px, 1.25fr);
        gap: .75rem;
      }
      .as-page__feed-summary {
        display: grid;
        grid-template-columns: repeat(2, minmax(0, 1fr));
        gap: .75rem;
      }
      .as-page__local-context-grid {
        display: grid;
        grid-template-columns: repeat(3, minmax(0, 1fr));
        gap: .75rem;
      }
      .as-page__item, .as-page__metric {
        min-width: 0;
        padding: .8rem .9rem;
        border: 1px solid var(--as-border);
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
        font-weight: 700;
      }
      .as-page__metric .as-page__value {
        font-size: var(--font-up-1);
        font-variant-numeric: tabular-nums;
      }
      .as-page__stack { display: grid; gap: .85rem; }
      .as-page__hint--spaced { margin-top: .3rem !important; }
      .as-page__section-title { display: grid; gap: .25rem; margin-bottom: .85rem; }
      .as-page__status-block {
        margin-top: .15rem;
        display: grid;
        gap: .4rem;
      }
      .as-page__alert {
        padding: .8rem 1rem;
        border-radius: 12px;
        border: 1px solid var(--primary-low);
      }
      .as-page__alert-title {
        font-weight: 700;
        margin-bottom: .2rem;
      }
      .as-page__alert--success {
        border-color: var(--success-low-mid);
        background: var(--success-low);
        color: var(--success);
      }
      .as-page__alert--error {
        border-color: var(--danger-low-mid);
        background: var(--danger-low);
        color: var(--danger);
      }
      .as-page__warning {
        padding: .8rem 1rem;
        border: 1px solid var(--danger-low-mid);
        border-radius: 12px;
        background: var(--danger-low);
        color: var(--danger);
      }
      @media (max-width: 980px) {
        .as-page__hero { flex-direction: column; }
        .as-page__actions { align-self: flex-end; margin-left: 0; }
        .as-page__metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); }
        .as-page__health-grid { grid-template-columns: 1fr; }
      }
      @media (max-width: 700px) {
        .as-page__panel-header { flex-direction: column; }
        .as-page__metrics, .as-page__feed-summary, .as-page__local-context-grid { grid-template-columns: 1fr; }
        .as-page__actions { width: 100%; justify-content: flex-start; }
      }
    </style>

    <div class="as-page">
      <section class="as-page__hero">
        <div class="as-page__copy">
          <h1>{{i18n "admin.account_security.health.title"}}</h1>
          <p class="as-page__muted">{{i18n "admin.account_security.health.description"}}</p>
        </div>
        <div class="as-page__actions">
          <a class="btn" href={{overviewUrl}}>{{i18n "admin.account_security.back_overview"}}</a>
          <a class="btn" href={{settingsUrl}}>{{i18n "admin.account_security.open_settings"}}</a>
          <button class="btn" type="button" {{on "click" @controller.loadHealth}} disabled={{@controller.isLoading}}>{{i18n "admin.account_security.health.refresh"}}</button>
        </div>
      </section>

      {{#if @controller.data}}
        <section class="as-page__metrics">
          <div class="as-page__metric"><div class="as-page__label">{{i18n "admin.account_security.health.overall"}}</div><div class="as-page__value">{{@controller.data.overall}}</div></div>
          <div class="as-page__metric"><div class="as-page__label">{{i18n "admin.account_security.health.provider"}}</div><div class="as-page__value">{{@controller.data.provider.status}}</div></div>
          <div class="as-page__metric"><div class="as-page__label">{{i18n "admin.account_security.remaining_checks"}}</div><div class="as-page__value">{{if @controller.data.provider.status @controller.data.provider.remaining "—"}}</div></div>
          <div class="as-page__metric"><div class="as-page__label">{{i18n "admin.account_security.health.circuit"}}</div><div class="as-page__value">{{@controller.data.circuit_breaker.state}}</div></div>
        </section>

        {{#if @controller.overallReasonText}}
          <div class="as-page__warning" role="alert"><strong>{{i18n "admin.account_security.health.reason"}}:</strong> {{@controller.overallReasonText}}</div>
        {{/if}}

        <section class="as-page__health-grid">
          <div class="as-page__panel">
            <div class="as-page__section-title"><h2>{{i18n "admin.account_security.health.configuration"}}</h2></div>
            <div class="as-page__stack">
              <div><strong>{{i18n "admin.account_security.health.api_key"}}:</strong> {{@controller.data.configuration.api_key_configured}}</div>
              <div><strong>{{i18n "admin.account_security.health.reporting"}}:</strong> {{@controller.data.configuration.abuse_reporting_enabled}}</div>
              <div><strong>{{i18n "admin.account_security.health.auth_abuse_detection"}}:</strong> {{@controller.data.configuration.auth_abuse_detection_enabled}}</div>
              <div><strong>{{i18n "admin.account_security.health.account_correlation"}}:</strong> {{@controller.data.configuration.account_correlation_enabled}}</div>
              <div><strong>{{i18n "admin.account_security.health.browser_continuity"}}:</strong> {{@controller.data.configuration.browser_continuity_enabled}}</div>
              <div><strong>{{i18n "admin.account_security.health.correlation_auto_scan"}}:</strong> {{@controller.correlationAutoScanLabel}}</div>
              <div><strong>{{i18n "admin.account_security.health.staff_notifications"}}:</strong> {{@controller.data.configuration.staff_notifications_enabled}}</div>
              <div><strong>{{i18n "admin.account_security.health.correlation_notifications"}}:</strong> {{@controller.data.configuration.correlation_notifications_enabled}}</div>
              <div><strong>{{i18n "admin.account_security.health.user_notes"}}:</strong> {{@controller.data.configuration.user_notes_enabled}}</div>
              <div><strong>{{i18n "admin.account_security.health.temporary_blocks"}}:</strong> {{@controller.data.configuration.temporary_ip_blocks_enabled}}</div>
            </div>
          </div>

          <div class="as-page__panel">
            <div class="as-page__section-title"><h2>{{i18n "admin.account_security.health.feeds"}}</h2></div>
            <div class="as-page__stack">
              <div class="as-page__feed-summary">
                <div class="as-page__item">
                  <div class="as-page__label">Tor</div>
                  <div class="as-page__status-block">
                    <div class="as-page__value">{{@controller.data.feeds.tor.status}}</div>
                    <div class="as-page__muted">{{@controller.data.feeds.tor.entry_count}} {{i18n "admin.account_security.health.entries"}}</div>
                  </div>
                </div>
                <div class="as-page__item">
                  <div class="as-page__label">AbuseIPDB blacklist</div>
                  <div class="as-page__status-block">
                    <div class="as-page__value">{{@controller.data.feeds.abuseipdb_blacklist.status}}</div>
                    <div class="as-page__muted">{{@controller.data.feeds.abuseipdb_blacklist.entry_count}} {{i18n "admin.account_security.health.entries"}}</div>
                  </div>
                </div>
              </div>
              <div class="as-page__buttons">
                <button class="btn" type="button" disabled={{@controller.syncingFeed}} {{on "click" @controller.syncTorFeed}}>{{i18n "admin.account_security.health.sync_tor_short"}}</button>
                <button class="btn" type="button" disabled={{@controller.syncingFeed}} {{on "click" @controller.syncBlacklistFeed}}>{{i18n "admin.account_security.health.sync_blacklist_short"}}</button>
              </div>
              <p class="as-page__hint as-page__hint--spaced">{{i18n "admin.account_security.health.sync_blacklist_hint"}}</p>
              {{#if @controller.feedSyncAlert}}
                <div class="as-page__alert {{if @controller.feedSyncAlert.success "as-page__alert--success" "as-page__alert--error"}}" role={{if @controller.feedSyncAlert.success "status" "alert"}}>
                  <div class="as-page__alert-title">{{@controller.feedSyncAlert.title}}</div>
                  <div>{{@controller.feedSyncAlert.message}}</div>
                </div>
              {{/if}}
            </div>
          </div>
        </section>

        {{#if @controller.correlationHealth}}
          <section class="as-page__panel">
            <div class="as-page__section-title">
              <h2>{{i18n "admin.account_security.health.correlation_health_title"}}</h2>
              <p class="as-page__muted">{{i18n "admin.account_security.health.correlation_health_description"}}</p>
            </div>
            <div class="as-page__grid">
              <div class="as-page__item"><div class="as-page__label">{{i18n "admin.account_security.health.correlation_health_state"}}</div><div class="as-page__value">{{@controller.correlationHealth.state_label}}</div></div>
              {{#if @controller.correlationHealth.scan}}
                <div class="as-page__item"><div class="as-page__label">{{i18n "admin.account_security.health.correlation_scan_state"}}</div><div class="as-page__value">{{@controller.correlationHealth.scan.state_label}}</div>{{#if @controller.correlationHealth.scan.completed_at_display}}<div class="as-page__muted">{{@controller.correlationHealth.scan.completed_at_display}}</div>{{/if}}</div>
                <div class="as-page__item"><div class="as-page__label">{{i18n "admin.account_security.health.correlation_last_success"}}</div><div class="as-page__value">{{if @controller.correlationHealth.scan.last_success_at_display @controller.correlationHealth.scan.last_success_at_display "—"}}</div></div>
                <div class="as-page__item"><div class="as-page__label">{{i18n "admin.account_security.health.correlation_last_failure"}}</div><div class="as-page__value">{{if @controller.correlationHealth.scan.last_failure_at_display @controller.correlationHealth.scan.last_failure_at_display "—"}}</div></div>
                <div class="as-page__item"><div class="as-page__label">{{i18n "admin.account_security.health.correlation_pairs_processed"}}</div><div class="as-page__value">{{@controller.correlationHealth.scan.pairs_processed}}</div></div>
                <div class="as-page__item"><div class="as-page__label">{{i18n "admin.account_security.health.correlation_pairs_failed"}}</div><div class="as-page__value">{{@controller.correlationHealth.scan.pairs_failed}}</div></div>
              {{/if}}
              {{#if @controller.correlationHealth.schedule}}
                <div class="as-page__item"><div class="as-page__label">{{i18n "admin.account_security.health.correlation_next_run"}}</div><div class="as-page__value">{{if @controller.correlationHealth.schedule.next_run_at_display @controller.correlationHealth.schedule.next_run_at_display "—"}}</div></div>
                <div class="as-page__item"><div class="as-page__label">{{i18n "admin.account_security.health.correlation_last_scheduled"}}</div><div class="as-page__value">{{if @controller.correlationHealth.schedule.last_scheduled_at_display @controller.correlationHealth.schedule.last_scheduled_at_display "—"}}</div></div>
              {{/if}}
            </div>
            {{#if @controller.correlationHealth.reason}}
              <div class="as-page__warning" style="margin-top: .75rem;">{{@controller.correlationReasonText}}</div>
            {{/if}}
          </section>
        {{/if}}

        {{#if @controller.localNetworkContext}}
          <section class="as-page__panel">
            <div class="as-page__section-title">
              <h2>{{i18n "admin.account_security.health.local_network_context"}}</h2>
              <p class="as-page__muted">{{i18n "admin.account_security.health.local_network_context_description"}}</p>
            </div>
            <div class="as-page__local-context-grid">
              <div class="as-page__item">
                <div class="as-page__label">{{i18n "admin.account_security.health.maxmind_status"}}</div>
                <div class="as-page__value">{{@controller.localNetworkContext.state_label}}</div>
              </div>
              <div class="as-page__item">
                <div class="as-page__label">MaxMind GeoLite2 City</div>
                <div class="as-page__value">{{if @controller.localNetworkContext.city.available (i18n "admin.account_security.health.maxmind_available") (i18n "admin.account_security.health.maxmind_unavailable")}}</div>
                {{#if @controller.localNetworkContext.city_updated_at_display}}<div class="as-page__muted" style="margin-top: .25rem;">{{i18n "admin.account_security.health.maxmind_updated"}}: {{@controller.localNetworkContext.city_updated_at_display}}</div>{{/if}}
              </div>
              <div class="as-page__item">
                <div class="as-page__label">MaxMind GeoLite2 ASN</div>
                <div class="as-page__value">{{if @controller.localNetworkContext.asn.available (i18n "admin.account_security.health.maxmind_available") (i18n "admin.account_security.health.maxmind_unavailable")}}</div>
                {{#if @controller.localNetworkContext.asn_updated_at_display}}<div class="as-page__muted" style="margin-top: .25rem;">{{i18n "admin.account_security.health.maxmind_updated"}}: {{@controller.localNetworkContext.asn_updated_at_display}}</div>{{/if}}
              </div>
            </div>
            {{#if @controller.localNetworkContext.incomplete}}
              <p class="as-page__hint" style="margin-top: .65rem;">{{i18n "admin.account_security.health.maxmind_not_available"}}</p>
            {{/if}}
          </section>
        {{/if}}

        <section class="as-page__panel">
          <div class="as-page__panel-header">
            <div class="as-page__copy">
              <h2>{{i18n "admin.account_security.health.provider_test_title"}}</h2>
              <p class="as-page__hint">{{i18n "admin.account_security.health.test_hint"}}</p>
            </div>
            <div class="as-page__buttons">
              <button class="btn btn-primary" type="button" disabled={{@controller.isTesting}} {{on "click" @controller.runTest}}>{{i18n "admin.account_security.health.test"}}</button>
              <button class="btn" type="button" {{on "click" @controller.resetCircuit}}>{{i18n "admin.account_security.health.reset_circuit"}}</button>
            </div>
          </div>
          {{#if @controller.testResultAlert}}
            <div class="as-page__alert {{if @controller.testResultAlert.success "as-page__alert--success" "as-page__alert--error"}}" role={{if @controller.testResultAlert.success "status" "alert"}}>
              <div class="as-page__alert-title">{{@controller.testResultAlert.title}}</div>
              <div>{{@controller.testResultAlert.message}}</div>
            </div>
          {{/if}}
        </section>
      {{else}}
        <p class="as-page__muted">{{i18n "admin.account_security.loading"}}</p>
      {{/if}}
    </div>
  </template>
);
