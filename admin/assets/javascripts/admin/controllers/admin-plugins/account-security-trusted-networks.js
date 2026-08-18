import Controller from "@ember/controller";
import { action } from "@ember/object";
import { tracked } from "@glimmer/tracking";
import { ajax } from "discourse/lib/ajax";
import { popupAjaxError } from "discourse/lib/ajax-error";
import {
  accountSecurityLocalInputToIso,
  accountSecurityUserTimezone,
  formatAccountSecurityDateTime,
} from "../../lib/account-security-date";

export default class AdminPluginsAccountSecurityTrustedNetworksController extends Controller {
  @tracked data;
  @tracked network = "";
  @tracked label = "";
  @tracked reason = "";
  @tracked expiresAt = "";
  @tracked confirmBroad = false;
  @tracked isLoading = false;
  @tracked search = "";
  @tracked page = 1;

  resetState() {
    this.data = { items: [] };
    this.network = "";
    this.label = "";
    this.reason = "";
    this.expiresAt = "";
    this.confirmBroad = false;
    this.isLoading = false;
    this.search = "";
    this.page = 1;
  }

  decorateData(data) {
    return {
      ...(data || {}),
      items: (data?.items || []).map((item) => ({
        ...item,
        expires_at_display: item.expires_at
          ? formatAccountSecurityDateTime(item.expires_at)
          : "—",
        created_at_display: formatAccountSecurityDateTime(item.created_at),
      })),
    };
  }

  get userTimezone() {
    return accountSecurityUserTimezone();
  }

  @action
  async loadItems() {
    this.isLoading = true;
    try {
      this.data = this.decorateData(
        await ajax("/admin/plugins/account-security/trusted-networks.json", {
          data: { search: this.search, page: this.page },
        })
      );
      this.page = Number(this.data?.page || 1);
    } catch (e) {
      popupAjaxError(e);
    } finally {
      this.isLoading = false;
    }
  }

  get hasPreviousPage() {
    return Number(this.data?.page || 1) > 1;
  }

  get hasNextPage() {
    if (!this.data) { return false; }
    return Number(this.data.page || 1) * Number(this.data.per_page || 50) < Number(this.data.total || 0);
  }

  @action setSearch(e) { this.search = e.target.value; }
  @action
  applySearch() {
    this.page = 1;
    this.loadItems();
  }

  @action
  previousPage() {
    if (!this.hasPreviousPage) { return; }
    this.page = Math.max(1, this.page - 1);
    this.loadItems();
  }

  @action
  nextPage() {
    if (!this.hasNextPage) { return; }
    this.page += 1;
    this.loadItems();
  }

  @action setNetwork(e) { this.network = e.target.value; }
  @action setLabel(e) { this.label = e.target.value; }
  @action setReason(e) { this.reason = e.target.value; }
  @action setExpires(e) { this.expiresAt = e.target.value; }
  @action setConfirmBroad(e) { this.confirmBroad = e.target.checked; }

  @action
  async addItem() {
    const expiresAt = this.expiresAt
      ? accountSecurityLocalInputToIso(this.expiresAt)
      : null;
    if (this.expiresAt && !expiresAt) {
      return;
    }

    try {
      await ajax("/admin/plugins/account-security/trusted-networks.json", {
        type: "POST",
        data: {
          account_security_network: this.network,
          label: this.label,
          reason: this.reason,
          expires_at: expiresAt,
          confirm_broad: this.confirmBroad,
        },
      });
      this.network = "";
      this.label = "";
      this.reason = "";
      this.expiresAt = "";
      this.confirmBroad = false;
      await this.loadItems();
    } catch (e) {
      popupAjaxError(e);
    }
  }

  @action
  async removeItem(item) {
    try {
      await ajax(`/admin/plugins/account-security/trusted-networks/${item.id}.json`, {
        type: "DELETE",
      });
      await this.loadItems();
    } catch (e) {
      popupAjaxError(e);
    }
  }
}
