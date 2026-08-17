import { fn } from "@ember/helper";
import { on } from "@ember/modifier";
import RouteTemplate from "ember-route-template";
import getURL from "discourse/lib/get-url";
import { i18n } from "discourse-i18n";
const overviewUrl = getURL("/admin/plugins/account-security");
export default RouteTemplate(<template>
  <div class="as-admin">
    <section class="as-admin__hero"><div class="as-admin__hero-copy"><h1>{{i18n "admin.account_security.trusted.title"}}</h1><p>{{i18n "admin.account_security.trusted.description"}}</p></div><div class="as-admin__hero-actions"><a class="btn" href={{overviewUrl}}>{{i18n "admin.account_security.back_overview"}}</a></div></section>
    <section class="as-admin__panel">
      <h2>{{i18n "admin.account_security.trusted.add_title"}}</h2>
      <div class="as-admin__form"><div class="as-admin__form-row"><div class="as-admin__field"><label>{{i18n "admin.account_security.trusted.network"}}</label><input type="text" value={{this.network}} placeholder="198.51.100.0/24" {{on "input" this.setNetwork}} /></div><div class="as-admin__field"><label>{{i18n "admin.account_security.trusted.label"}}</label><input type="text" value={{this.label}} {{on "input" this.setLabel}} /></div></div><div class="as-admin__field"><label>{{i18n "admin.account_security.trusted.reason"}}</label><input type="text" value={{this.reason}} {{on "input" this.setReason}} /></div><div class="as-admin__field"><label>{{i18n "admin.account_security.trusted.expires"}}</label><input type="datetime-local" value={{this.expiresAt}} {{on "input" this.setExpires}} /></div><label><input type="checkbox" checked={{this.confirmBroad}} {{on "change" this.setConfirmBroad}} /> {{i18n "admin.account_security.trusted.confirm_broad"}}</label><div class="as-admin__buttons"><button class="btn btn-primary" type="button" {{on "click" this.addItem}}>{{i18n "admin.account_security.trusted.add"}}</button></div></div>
    </section>
    <section class="as-admin__panel"><h2>{{i18n "admin.account_security.trusted.current"}}</h2>{{#if this.data.items.length}}<div class="as-admin__table-wrap"><table class="as-admin__table"><thead><tr><th>{{i18n "admin.account_security.trusted.network"}}</th><th>{{i18n "admin.account_security.trusted.label"}}</th><th>{{i18n "admin.account_security.trusted.reason"}}</th><th>{{i18n "admin.account_security.trusted.expires"}}</th><th></th></tr></thead><tbody>{{#each this.data.items as |item|}}<tr><td class="as-admin__code">{{item.network}}</td><td>{{item.label}}</td><td>{{item.reason}}</td><td>{{if item.expires_at item.expires_at "—"}}</td><td><button class="btn btn-danger btn-small" type="button" {{on "click" (fn this.removeItem item)}}>{{i18n "admin.account_security.trusted.remove"}}</button></td></tr>{{/each}}</tbody></table></div>{{else}}<p class="as-admin__muted">{{i18n "admin.account_security.no_data"}}</p>{{/if}}</section>
  </div>
</template>);
