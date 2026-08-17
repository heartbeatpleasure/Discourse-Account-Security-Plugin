import Controller from "@ember/controller";
import { action } from "@ember/object";
import { tracked } from "@glimmer/tracking";
import { ajax } from "discourse/lib/ajax";
import { popupAjaxError } from "discourse/lib/ajax-error";
import getURL from "discourse/lib/get-url";

export default class AdminPluginsAccountSecurityEventsController extends Controller {
  @tracked data;
  @tracked isLoading = false;
  @tracked status = "";
  @tracked severity = "";

  resetState() {
    this.data = undefined;
    this.isLoading = false;
    this.status = "";
    this.severity = "";
  }

  @action
  async loadEvents() {
    this.isLoading = true;
    try {
      const data = await ajax("/admin/plugins/account-security/events.json", {
        data: { status: this.status, severity: this.severity },
      });
      data.items = (data.items || []).map((item) => ({
        ...item,
        detail_url: getURL(`/admin/plugins/account-security-events/${item.id}`),
      }));
      this.data = data;
    } catch (error) {
      popupAjaxError(error);
    } finally {
      this.isLoading = false;
    }
  }

  @action
  setStatus(event) {
    this.status = event.target.value;
    this.loadEvents();
  }

  @action
  setSeverity(event) {
    this.severity = event.target.value;
    this.loadEvents();
  }

  @action
  async review(item, status) {
    try {
      await ajax(`/admin/plugins/account-security/events/${item.id}.json`, {
        type: "PUT",
        data: { status },
      });
      await this.loadEvents();
    } catch (error) {
      popupAjaxError(error);
    }
  }
}
