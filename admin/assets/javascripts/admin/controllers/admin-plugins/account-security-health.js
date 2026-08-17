import Controller from "@ember/controller";
import { action } from "@ember/object";
import { tracked } from "@glimmer/tracking";
import { ajax } from "discourse/lib/ajax";
import { popupAjaxError } from "discourse/lib/ajax-error";
export default class AdminPluginsAccountSecurityHealthController extends Controller {
  @tracked data;
  @tracked isLoading = false;
  @tracked isTesting = false;
  resetState() { this.data = undefined; this.isLoading = false; this.isTesting = false; }
  @action async loadHealth() { this.isLoading = true; try { this.data = await ajax("/admin/plugins/account-security/health.json"); } catch (e) { popupAjaxError(e); } finally { this.isLoading = false; } }
  @action async runTest() { this.isTesting = true; try { this.data = await ajax("/admin/plugins/account-security/health/test.json", { type: "POST" }); } catch (e) { popupAjaxError(e); } finally { this.isTesting = false; } }
  @action async resetCircuit() { try { await ajax("/admin/plugins/account-security/health/reset-circuit.json", { type: "POST" }); await this.loadHealth(); } catch (e) { popupAjaxError(e); } }
}
