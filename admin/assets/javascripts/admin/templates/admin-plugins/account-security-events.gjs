import { fn } from "@ember/helper";
import { on } from "@ember/modifier";
import RouteTemplate from "ember-route-template";
import getURL from "discourse/lib/get-url";
import { i18n } from "discourse-i18n";
const overviewUrl = getURL("/admin/plugins/account-security");
export default RouteTemplate(<template>
  <div class="as-admin">
    <section class="as-admin__hero"><div class="as-admin__hero-copy"><h1>{{i18n "admin.account_security.events.title"}}</h1><p>{{i18n "admin.account_security.events.description"}}</p></div><div class="as-admin__hero-actions"><a class="btn" href={{overviewUrl}}>{{i18n "admin.account_security.back_overview"}}</a></div></section>
    <section class="as-admin__panel">
      <div class="as-admin__form-row">
        <div class="as-admin__field"><label>{{i18n "admin.account_security.events.filter_status"}}</label><select {{on "change" this.setStatus}}><option value="">{{i18n "admin.account_security.all"}}</option><option value="open">Open</option><option value="acknowledged">Acknowledged</option><option value="benign">Benign</option><option value="monitor">Monitor</option><option value="actioned">Actioned</option></select></div>
        <div class="as-admin__field"><label>{{i18n "admin.account_security.events.filter_severity"}}</label><select {{on "change" this.setSeverity}}><option value="">{{i18n "admin.account_security.all"}}</option><option value="elevated">Elevated</option><option value="high">High</option><option value="critical">Critical</option></select></div>
      </div>
      {{#if this.data}}
        <div class="as-admin__table-wrap"><table class="as-admin__table"><thead><tr><th>{{i18n "admin.account_security.events.time"}}</th><th>{{i18n "admin.account_security.events.user"}}</th><th>IP</th><th>{{i18n "admin.account_security.events.type"}}</th><th>{{i18n "admin.account_security.events.risk"}}</th><th>{{i18n "admin.account_security.events.evidence"}}</th><th>{{i18n "admin.account_security.events.status"}}</th><th>{{i18n "admin.account_security.events.actions"}}</th></tr></thead><tbody>
          {{#each this.data.items as |item|}}<tr><td>{{item.created_at}}</td><td>{{if item.user item.user.username "—"}}</td><td class="as-admin__code">{{item.ip_address}}</td><td>{{item.event_type}}</td><td>{{item.risk_level}}</td><td>{{item.evidence_strength}}</td><td>{{item.status}}</td><td><div class="as-admin__buttons"><button class="btn btn-small" type="button" {{on "click" (fn this.review item "acknowledged")}}>Acknowledge</button><button class="btn btn-small" type="button" {{on "click" (fn this.review item "benign")}}>Benign</button><button class="btn btn-small" type="button" {{on "click" (fn this.review item "monitor")}}>Monitor</button></div></td></tr>{{/each}}
        </tbody></table></div>
      {{else}}<p class="as-admin__muted">{{if this.isLoading (i18n "admin.account_security.loading") (i18n "admin.account_security.no_data")}}</p>{{/if}}
    </section>
  </div>
</template>);
