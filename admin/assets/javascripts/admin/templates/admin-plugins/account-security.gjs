import RouteTemplate from "ember-route-template";
import getURL from "discourse/lib/get-url";
import { i18n } from "discourse-i18n";
const settingsUrl = getURL("/admin/site_settings/category/all_results?filter=account_security");
const eventsUrl = getURL("/admin/plugins/account-security-events");
const intelligenceUrl = getURL("/admin/plugins/account-security-intelligence");
const trustedUrl = getURL("/admin/plugins/account-security-trusted-networks");
const healthUrl = getURL("/admin/plugins/account-security-health");
const statsUrl = getURL("/admin/plugins/account-security-statistics");
export default RouteTemplate(<template>
  <div class="as-admin">
    <section class="as-admin__hero">
      <div class="as-admin__hero-copy"><h1>{{i18n "admin.account_security.title"}}</h1><p>{{i18n "admin.account_security.description"}}</p></div>
      <div class="as-admin__hero-actions"><a class="btn btn-primary" href={{settingsUrl}}>{{i18n "admin.account_security.open_settings"}}</a></div>
    </section>
    <section class="as-admin__section">
      <div><h2>{{i18n "admin.account_security.current_status"}}</h2><p class="as-admin__muted">{{i18n "admin.account_security.current_status_description"}}</p></div>
      <div class="as-admin__metrics">
        <div class="as-admin__metric"><div class="as-admin__metric-label">{{i18n "admin.account_security.status"}}</div><div class="as-admin__metric-value">{{@model.health.overall}}</div></div>
        <div class="as-admin__metric"><div class="as-admin__metric-label">{{i18n "admin.account_security.open_events"}}</div><div class="as-admin__metric-value">{{@model.open_events}}</div></div>
        <div class="as-admin__metric"><div class="as-admin__metric-label">{{i18n "admin.account_security.cached_addresses"}}</div><div class="as-admin__metric-value">{{@model.cached_addresses}}</div></div>
        <div class="as-admin__metric"><div class="as-admin__metric-label">{{i18n "admin.account_security.remaining_checks"}}</div><div class="as-admin__metric-value">{{if @model.health.provider.status @model.health.provider.remaining "—"}}</div></div>
      </div>
    </section>
    <section class="as-admin__section">
      <div><h2>{{i18n "admin.account_security.tools_title"}}</h2><p class="as-admin__muted">{{i18n "admin.account_security.tools_description"}}</p></div>
      <div class="as-admin__grid">
        <a class="as-admin__card is-primary" href={{settingsUrl}}><span class="as-admin__badge is-primary">{{i18n "admin.account_security.category_configuration"}}</span><h3>{{i18n "admin.account_security.open_settings"}}</h3><p>{{i18n "admin.account_security.settings_description"}}</p><span class="as-admin__action">{{i18n "admin.account_security.open_tool"}}</span></a>
        <a class="as-admin__card" href={{eventsUrl}}><span class="as-admin__badge">{{i18n "admin.account_security.category_security"}}</span><h3>{{i18n "admin.account_security.events.title"}}</h3><p>{{i18n "admin.account_security.events.description"}}</p><span class="as-admin__action">{{i18n "admin.account_security.open_tool"}}</span></a>
        <a class="as-admin__card" href={{intelligenceUrl}}><span class="as-admin__badge">{{i18n "admin.account_security.category_investigation"}}</span><h3>{{i18n "admin.account_security.intelligence.title"}}</h3><p>{{i18n "admin.account_security.intelligence.description"}}</p><span class="as-admin__action">{{i18n "admin.account_security.open_tool"}}</span></a>
        <a class="as-admin__card" href={{trustedUrl}}><span class="as-admin__badge">{{i18n "admin.account_security.category_policy"}}</span><h3>{{i18n "admin.account_security.trusted.title"}}</h3><p>{{i18n "admin.account_security.trusted.description"}}</p><span class="as-admin__action">{{i18n "admin.account_security.open_tool"}}</span></a>
        <a class="as-admin__card" href={{healthUrl}}><span class="as-admin__badge">{{i18n "admin.account_security.category_monitoring"}}</span><h3>{{i18n "admin.account_security.health.title"}}</h3><p>{{i18n "admin.account_security.health.description"}}</p><span class="as-admin__action">{{i18n "admin.account_security.open_tool"}}</span></a>
        <a class="as-admin__card" href={{statsUrl}}><span class="as-admin__badge">{{i18n "admin.account_security.category_reporting"}}</span><h3>{{i18n "admin.account_security.statistics.title"}}</h3><p>{{i18n "admin.account_security.statistics.description"}}</p><span class="as-admin__action">{{i18n "admin.account_security.open_tool"}}</span></a>
      </div>
    </section>
  </div>
</template>);
