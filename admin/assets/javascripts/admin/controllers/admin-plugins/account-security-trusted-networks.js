import Controller from "@ember/controller";
import { action } from "@ember/object";
import { tracked } from "@glimmer/tracking";
import { ajax } from "discourse/lib/ajax";
import { popupAjaxError } from "discourse/lib/ajax-error";
export default class AdminPluginsAccountSecurityTrustedNetworksController extends Controller {
  @tracked data;
  @tracked network = "";
  @tracked label = "";
  @tracked reason = "";
  @tracked expiresAt = "";
  @tracked confirmBroad = false;
  @tracked isLoading = false;
  resetState() { this.data = { items: [] }; this.network = ""; this.label = ""; this.reason = ""; this.expiresAt = ""; this.confirmBroad = false; this.isLoading = false; }
  @action async loadItems() { this.isLoading = true; try { this.data = await ajax("/admin/plugins/account-security/trusted-networks.json"); } catch (e) { popupAjaxError(e); } finally { this.isLoading = false; } }
  @action setNetwork(e) { this.network = e.target.value; }
  @action setLabel(e) { this.label = e.target.value; }
  @action setReason(e) { this.reason = e.target.value; }
  @action setExpires(e) { this.expiresAt = e.target.value; }
  @action setConfirmBroad(e) { this.confirmBroad = e.target.checked; }
  @action async addItem() {
    try {
      await ajax("/admin/plugins/account-security/trusted-networks.json", { type: "POST", data: { account_security_network: this.network, label: this.label, reason: this.reason, expires_at: this.expiresAt || null, confirm_broad: this.confirmBroad } });
      this.network = ""; this.label = ""; this.reason = ""; this.expiresAt = ""; this.confirmBroad = false; await this.loadItems();
    } catch (e) { popupAjaxError(e); }
  }
  @action async removeItem(item) { try { await ajax(`/admin/plugins/account-security/trusted-networks/${item.id}.json`, { type: "DELETE" }); await this.loadItems(); } catch (e) { popupAjaxError(e); } }
}
