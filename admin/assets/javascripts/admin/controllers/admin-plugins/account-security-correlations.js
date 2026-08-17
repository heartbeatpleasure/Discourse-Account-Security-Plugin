import Controller from "@ember/controller";
import { action } from "@ember/object";
import { tracked } from "@glimmer/tracking";
import { ajax } from "discourse/lib/ajax";
import { popupAjaxError } from "discourse/lib/ajax-error";
import { i18n } from "discourse-i18n";

export default class AdminPluginsAccountSecurityCorrelationsController extends Controller {
  @tracked data;
  @tracked isLoading = false;
  @tracked isScanning = false;
  @tracked status = "";
  @tracked confidence = "";
  @tracked search = "";
  @tracked page = 1;

  resetState() {
    this.data = undefined;
    this.isLoading = false;
    this.isScanning = false;
    this.status = "";
    this.confidence = "";
    this.search = "";
    this.page = 1;
  }

  decorateItem(item) {
    const evidence = item.evidence || {};
    const signals = [];

    if (evidence.shared_registration_ip) {
      signals.push(i18n("admin.account_security.correlations.shared_registration_ip"));
    }
    if (evidence.same_current_ip) {
      signals.push(i18n("admin.account_security.correlations.same_current_ip"));
    }
    if (evidence.shared_network_count > 0) {
      signals.push(
        `${evidence.shared_network_count} ${i18n("admin.account_security.correlations.shared_networks")}`
      );
    }
    if (evidence.shared_session_signature_count > 0) {
      signals.push(
        `${evidence.shared_session_signature_count} ${i18n("admin.account_security.correlations.shared_session_signatures")}`
      );
    }

    return {
      ...item,
      confidence_label: i18n(
        `admin.account_security.correlations.confidences.${item.confidence}`
      ),
      status_label: i18n(
        `admin.account_security.correlations.statuses.${item.status}`
      ),
      signal_summary:
        signals.join(", ") || i18n("admin.account_security.correlations.no_signals"),
      can_reopen: item.status !== "open",
    };
  }

  @action
  async loadCorrelations() {
    this.isLoading = true;
    try {
      const data = await ajax("/admin/plugins/account-security/correlations.json", {
        data: {
          status: this.status,
          confidence: this.confidence,
          search: this.search,
          page: this.page,
        },
      });
      data.items = (data.items || []).map((item) => this.decorateItem(item));
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
  }

  @action
  setConfidence(event) {
    this.confidence = event.target.value;
  }

  @action
  setSearch(event) {
    this.search = event.target.value;
  }

  @action
  applyFilters() {
    this.page = 1;
    this.loadCorrelations();
  }

  get scanBusy() {
    return (
      this.isScanning ||
      this.data?.scan?.state === "queued" ||
      this.data?.scan?.state === "running"
    );
  }

  get hasPreviousPage() {
    return (this.data?.page || 1) > 1;
  }

  get hasNextPage() {
    if (!this.data) {
      return false;
    }
    return this.data.page * this.data.per_page < this.data.total;
  }

  @action
  previousPage() {
    if (!this.hasPreviousPage) {
      return;
    }
    this.page = Math.max(1, this.page - 1);
    this.loadCorrelations();
  }

  @action
  nextPage() {
    if (!this.hasNextPage) {
      return;
    }
    this.page += 1;
    this.loadCorrelations();
  }

  @action
  async review(item, status) {
    if (
      status === "confirmed_duplicate" &&
      !window.confirm(i18n("admin.account_security.correlations.confirm_duplicate"))
    ) {
      return;
    }

    try {
      await ajax(`/admin/plugins/account-security/correlations/${item.id}.json`, {
        type: "PUT",
        data: {
          status,
          confirmed: status === "confirmed_duplicate",
        },
      });
      await this.loadCorrelations();
    } catch (error) {
      popupAjaxError(error);
    }
  }

  @action
  async rebuild() {
    this.isScanning = true;
    try {
      await ajax("/admin/plugins/account-security/correlations/rebuild.json", {
        type: "POST",
      });
      await this.loadCorrelations();
    } catch (error) {
      popupAjaxError(error);
      await this.loadCorrelations();
    } finally {
      this.isScanning = false;
    }
  }
}
