import Controller from "@ember/controller";
import { action } from "@ember/object";
import { tracked } from "@glimmer/tracking";
import { ajax } from "discourse/lib/ajax";
import { popupAjaxError } from "discourse/lib/ajax-error";

export default class AdminPluginsAccountSecurityIntelligenceController extends Controller {
  @tracked ip = "";
  @tracked data;
  @tracked isLoading = false;

  resetState() {
    this.ip = "";
    this.data = undefined;
    this.isLoading = false;
  }

  @action
  updateIp(event) {
    this.ip = event.target.value;
  }

  @action
  async lookup(refresh = false) {
    if (!this.ip.trim()) {
      return;
    }

    this.isLoading = true;
    try {
      this.data = await ajax("/admin/plugins/account-security/lookup.json", {
        type: "POST",
        data: { account_security_ip: this.ip.trim(), refresh },
      });
    } catch (error) {
      popupAjaxError(error);
    } finally {
      this.isLoading = false;
    }
  }
}
