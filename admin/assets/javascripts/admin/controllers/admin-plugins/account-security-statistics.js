import Controller from "@ember/controller";
import { action } from "@ember/object";
import { tracked } from "@glimmer/tracking";
import { ajax } from "discourse/lib/ajax";
import { popupAjaxError } from "discourse/lib/ajax-error";
import { formatAccountSecurityDateOnly } from "../../lib/account-security-date";

export default class AdminPluginsAccountSecurityStatisticsController extends Controller {
  @tracked data;
  @tracked period = 30;
  @tracked isLoading = false;

  resetState() {
    this.data = undefined;
    this.period = 30;
    this.isLoading = false;
  }

  decorateData(data) {
    if (!data) {
      return data;
    }
    return {
      ...data,
      daily: (data.daily || []).map((day) => ({
        ...day,
        stat_date_display: formatAccountSecurityDateOnly(day.stat_date),
      })),
    };
  }

  @action
  async loadStatistics() {
    this.isLoading = true;
    try {
      const data = await ajax("/admin/plugins/account-security/statistics.json", {
        data: { period: this.period },
      });
      this.data = this.decorateData(data);
    } catch (e) {
      popupAjaxError(e);
    } finally {
      this.isLoading = false;
    }
  }

  @action
  setPeriod(e) {
    this.period = Number(e.target.value);
    this.loadStatistics();
  }
}
