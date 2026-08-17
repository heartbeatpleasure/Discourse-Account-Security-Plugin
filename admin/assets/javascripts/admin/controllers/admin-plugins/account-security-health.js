import Controller from "@ember/controller";
import { action } from "@ember/object";
import { tracked } from "@glimmer/tracking";
import { ajax } from "discourse/lib/ajax";
import { popupAjaxError } from "discourse/lib/ajax-error";
import { i18n } from "discourse-i18n";

const REASON_KEYS = {
  plugin_disabled: "plugin_disabled",
  ip_reputation_disabled: "ip_reputation_disabled",
  api_key_missing: "api_key_missing",
  circuit_open: "circuit_open",
  invalid_credentials: "invalid_credentials",
  quota_exhausted: "quota_exhausted",
  tor_never_synced: "tor_never_synced",
  tor_error: "tor_error",
  tor_stale: "tor_stale",
  abuseipdb_blacklist_never_synced: "blacklist_never_synced",
  abuseipdb_blacklist_error: "blacklist_error",
  abuseipdb_blacklist_stale: "blacklist_stale",
  notification_groups_missing: "notification_groups_missing",
  database_initializing: "database_initializing",
};

export default class AdminPluginsAccountSecurityHealthController extends Controller {
  @tracked data;
  @tracked isLoading = false;
  @tracked isTesting = false;
  @tracked syncingFeed = null;

  resetState() {
    this.data = undefined;
    this.isLoading = false;
    this.isTesting = false;
    this.syncingFeed = null;
  }

  get overallReasonText() {
    const reason = this.data?.overall_reason;
    if (!reason) {
      return null;
    }
    const key = REASON_KEYS[reason] || "generic";
    return i18n(`admin.account_security.health.reasons.${key}`);
  }

  @action
  async loadHealth() {
    this.isLoading = true;
    try {
      this.data = await ajax("/admin/plugins/account-security/health.json");
    } catch (e) {
      popupAjaxError(e);
    } finally {
      this.isLoading = false;
    }
  }

  @action
  async runTest() {
    this.isTesting = true;
    try {
      this.data = await ajax(
        "/admin/plugins/account-security/health/test.json",
        { type: "POST" }
      );
    } catch (e) {
      popupAjaxError(e);
    } finally {
      this.isTesting = false;
    }
  }

  @action
  async resetCircuit() {
    try {
      await ajax("/admin/plugins/account-security/health/reset-circuit.json", {
        type: "POST",
      });
      await this.loadHealth();
    } catch (e) {
      popupAjaxError(e);
    }
  }

  @action
  async syncTorFeed() {
    await this.syncFeed("tor");
  }

  @action
  async syncBlacklistFeed() {
    await this.syncFeed("abuseipdb_blacklist");
  }

  async syncFeed(source) {
    if (this.syncingFeed) {
      return;
    }
    this.syncingFeed = source;
    try {
      this.data = await ajax(
        "/admin/plugins/account-security/health/sync-feed.json",
        { type: "POST", data: { source } }
      );
    } catch (e) {
      popupAjaxError(e);
    } finally {
      this.syncingFeed = null;
    }
  }
}
