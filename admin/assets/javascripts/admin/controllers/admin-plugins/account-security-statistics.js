import Controller from "@ember/controller";
import { action } from "@ember/object";
import { tracked } from "@glimmer/tracking";
import { ajax } from "discourse/lib/ajax";
import { popupAjaxError } from "discourse/lib/ajax-error";
export default class AdminPluginsAccountSecurityStatisticsController extends Controller {
  @tracked data;
  @tracked period = 30;
  @tracked isLoading = false;
  resetState() { this.data = undefined; this.period = 30; this.isLoading = false; }
  @action async loadStatistics() { this.isLoading = true; try { this.data = await ajax("/admin/plugins/account-security/statistics.json", { data: { period: this.period } }); } catch (e) { popupAjaxError(e); } finally { this.isLoading = false; } }
  @action setPeriod(e) { this.period = Number(e.target.value); this.loadStatistics(); }
}
