import RouteTemplate from "ember-route-template";
import getURL from "discourse/lib/get-url";
import { i18n } from "discourse-i18n";

const settingsUrl = getURL(
  "/admin/site_settings/category/all_results?filter=account_security"
);
const eventsUrl = getURL("/admin/plugins/account-security-events");
const intelligenceUrl = getURL("/admin/plugins/account-security-intelligence");
const trustedUrl = getURL("/admin/plugins/account-security-trusted-networks");
const healthUrl = getURL("/admin/plugins/account-security-health");
const statsUrl = getURL("/admin/plugins/account-security-statistics");

export default RouteTemplate(
  <template>
    <style>
      .as-admin {
        --as-surface: var(--secondary);
        --as-border: var(--primary-low);
        --as-muted: var(--primary-medium);
        display: flex;
        min-width: 0;
        flex-direction: column;
        gap: 1rem;
      }
      .as-admin h1, .as-admin h2, .as-admin h3, .as-admin p { margin: 0; }
      .as-admin__hero, .as-admin__card, .as-admin__metric {
        border: 1px solid var(--as-border);
        border-radius: 18px;
        background: var(--as-surface);
        box-shadow: 0 1px 2px rgb(0 0 0 / 3%);
      }
      .as-admin__hero {
        display: flex;
        align-items: flex-start;
        justify-content: space-between;
        gap: 1rem;
        padding: 1.25rem 1.35rem;
      }
      .as-admin__hero-copy {
        display: grid;
        min-width: 0;
        flex: 1 1 auto;
        gap: .45rem;
        max-width: 760px;
      }
      .as-admin__hero > .btn {
        flex: 0 0 auto;
        margin-left: auto;
        white-space: nowrap;
      }
      .as-admin__hero-copy p, .as-admin__muted, .as-admin__card p {
        color: var(--as-muted);
      }
      .as-admin__section { display: grid; gap: .7rem; }
      .as-admin__metrics {
        display: grid;
        grid-template-columns: repeat(4, minmax(0, 1fr));
        gap: .8rem;
      }
      .as-admin__metric { min-width: 0; padding: .85rem 1rem; }
      .as-admin__metric-label {
        color: var(--as-muted);
        font-size: var(--font-down-1);
        font-weight: 700;
      }
      .as-admin__metric-value {
        margin-top: .25rem;
        font-size: var(--font-up-2);
        font-weight: 700;
        overflow-wrap: anywhere;
      }
      .as-admin__grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
        gap: 1rem;
      }
      .as-admin__card {
        display: flex;
        min-height: 165px;
        flex-direction: column;
        gap: .8rem;
        padding: 1rem 1.1rem;
        color: var(--primary);
        text-decoration: none;
        transition: border-color .12s ease, box-shadow .12s ease, transform .12s ease;
      }
      .as-admin__card:hover, .as-admin__card:focus {
        border-color: var(--tertiary-medium);
        box-shadow: 0 6px 18px rgb(0 0 0 / 6%);
        color: var(--primary);
        text-decoration: none;
        transform: translateY(-1px);
      }
      .as-admin__card.is-primary {
        border-color: var(--tertiary-low);
        background: linear-gradient(180deg, var(--secondary), var(--tertiary-very-low));
      }
      .as-admin__badge {
        display: inline-flex;
        width: max-content;
        padding: .35rem .55rem;
        border: 1px solid var(--primary-low);
        border-radius: 999px;
        background: var(--primary-very-low);
        color: var(--primary-medium);
        font-size: var(--font-down-1);
        line-height: 1;
      }
      .as-admin__badge.is-primary {
        border-color: var(--tertiary-low);
        background: var(--tertiary-low);
        color: var(--tertiary);
      }
      .as-admin__action {
        margin-top: auto;
        color: var(--tertiary);
        font-weight: 600;
      }
      @media (max-width: 850px) {
        .as-admin__metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      }
      @media (max-width: 700px) {
        .as-admin__hero { flex-direction: column; }
        .as-admin__hero > .btn { align-self: flex-end; margin-left: 0; }
      }
      @media (max-width: 600px) {
        .as-admin__metrics { grid-template-columns: 1fr; }
      }
    </style>

    <div class="as-admin">
      <section class="as-admin__hero">
        <div class="as-admin__hero-copy">
          <h1>{{i18n "admin.account_security.title"}}</h1>
          <p>{{i18n "admin.account_security.description"}}</p>
        </div>
        <a class="btn btn-primary" href={{settingsUrl}}>
          {{i18n "admin.account_security.open_settings"}}
        </a>
      </section>

      <section class="as-admin__section">
        <div>
          <h2>{{i18n "admin.account_security.current_status"}}</h2>
          <p class="as-admin__muted">{{i18n "admin.account_security.current_status_description"}}</p>
        </div>
        <div class="as-admin__metrics">
          <div class="as-admin__metric">
            <div class="as-admin__metric-label">{{i18n "admin.account_security.status"}}</div>
            <div class="as-admin__metric-value">{{@model.health.overall}}</div>
          </div>
          <div class="as-admin__metric">
            <div class="as-admin__metric-label">{{i18n "admin.account_security.open_events"}}</div>
            <div class="as-admin__metric-value">{{@model.open_events}}</div>
          </div>
          <div class="as-admin__metric">
            <div class="as-admin__metric-label">{{i18n "admin.account_security.cached_addresses"}}</div>
            <div class="as-admin__metric-value">{{@model.cached_addresses}}</div>
          </div>
          <div class="as-admin__metric">
            <div class="as-admin__metric-label">{{i18n "admin.account_security.remaining_checks"}}</div>
            <div class="as-admin__metric-value">{{if @model.health.provider.status @model.health.provider.remaining "—"}}</div>
          </div>
        </div>
      </section>

      <section class="as-admin__section">
        <div>
          <h2>{{i18n "admin.account_security.tools_title"}}</h2>
          <p class="as-admin__muted">{{i18n "admin.account_security.tools_description"}}</p>
        </div>
        <div class="as-admin__grid">
          <a class="as-admin__card is-primary" href={{settingsUrl}}>
            <span class="as-admin__badge is-primary">{{i18n "admin.account_security.category_configuration"}}</span>
            <h3>{{i18n "admin.account_security.open_settings"}}</h3>
            <p>{{i18n "admin.account_security.settings_description"}}</p>
            <span class="as-admin__action">{{i18n "admin.account_security.open_tool"}}</span>
          </a>
          <a class="as-admin__card" href={{eventsUrl}}>
            <span class="as-admin__badge">{{i18n "admin.account_security.category_security"}}</span>
            <h3>{{i18n "admin.account_security.events.title"}}</h3>
            <p>{{i18n "admin.account_security.events.description"}}</p>
            <span class="as-admin__action">{{i18n "admin.account_security.open_tool"}}</span>
          </a>
          <a class="as-admin__card" href={{intelligenceUrl}}>
            <span class="as-admin__badge">{{i18n "admin.account_security.category_investigation"}}</span>
            <h3>{{i18n "admin.account_security.intelligence.title"}}</h3>
            <p>{{i18n "admin.account_security.intelligence.description"}}</p>
            <span class="as-admin__action">{{i18n "admin.account_security.open_tool"}}</span>
          </a>
          <a class="as-admin__card" href={{trustedUrl}}>
            <span class="as-admin__badge">{{i18n "admin.account_security.category_policy"}}</span>
            <h3>{{i18n "admin.account_security.trusted.title"}}</h3>
            <p>{{i18n "admin.account_security.trusted.description"}}</p>
            <span class="as-admin__action">{{i18n "admin.account_security.open_tool"}}</span>
          </a>
          <a class="as-admin__card" href={{healthUrl}}>
            <span class="as-admin__badge">{{i18n "admin.account_security.category_monitoring"}}</span>
            <h3>{{i18n "admin.account_security.health.title"}}</h3>
            <p>{{i18n "admin.account_security.health.description"}}</p>
            <span class="as-admin__action">{{i18n "admin.account_security.open_tool"}}</span>
          </a>
          <a class="as-admin__card" href={{statsUrl}}>
            <span class="as-admin__badge">{{i18n "admin.account_security.category_reporting"}}</span>
            <h3>{{i18n "admin.account_security.statistics.title"}}</h3>
            <p>{{i18n "admin.account_security.statistics.description"}}</p>
            <span class="as-admin__action">{{i18n "admin.account_security.open_tool"}}</span>
          </a>
        </div>
      </section>
    </div>
  </template>
);
