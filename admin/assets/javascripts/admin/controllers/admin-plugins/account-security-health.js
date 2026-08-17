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

const FEED_SOURCE_KEYS = {
  tor: "tor",
  abuseipdb_blacklist: "abuseipdb_blacklist",
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

  get feedSyncAlert() {
    const sync = this.data?.feed_sync;
    if (!sync) {
      return null;
    }

    const sourceKey = FEED_SOURCE_KEYS[sync.source] || "generic";
    const sourceLabel = i18n(
      `admin.account_security.health.feed_sources.${sourceKey}`
    );

    if (sync.success) {
      let message;
      if (typeof sync.entry_count === "number") {
        message = i18n(
          "admin.account_security.health.feed_sync_success_with_entries",
          { source: sourceLabel, count: sync.entry_count }
        );
      } else {
        message = i18n("admin.account_security.health.feed_sync_success", {
          source: sourceLabel,
        });
      }

      return {
        success: true,
        title: i18n("admin.account_security.health.feed_sync_result"),
        message,
      };
    }

    const reason = this.humanizeErrorCode(sync.error_code);
    const message = reason
      ? i18n("admin.account_security.health.feed_sync_failure_reason", {
          source: sourceLabel,
          reason,
        })
      : i18n("admin.account_security.health.feed_sync_failure", {
          source: sourceLabel,
        });

    return {
      success: false,
      title: i18n("admin.account_security.health.feed_sync_result"),
      message,
    };
  }

  get testResultAlert() {
    const result = this.data?.test_result;
    if (!result) {
      return null;
    }

    if (result.success) {
      let message;
      if (result.latency_ms) {
        message = i18n(
          "admin.account_security.health.test_success_with_latency",
          { latency: result.latency_ms }
        );
      } else {
        message = i18n("admin.account_security.health.test_success");
      }

      return {
        success: true,
        title: i18n("admin.account_security.health.test_result"),
        message,
      };
    }

    const reason = this.humanizeErrorCode(result.error_code || result.status);
    return {
      success: false,
      title: i18n("admin.account_security.health.test_result"),
      message: reason
        ? i18n("admin.account_security.health.test_failure_reason", { reason })
        : i18n("admin.account_security.health.test_failure"),
    };
  }

  humanizeErrorCode(value) {
    if (!value) {
      return null;
    }

    const key = String(value).trim().toLowerCase();
    const translated = i18n(
      `admin.account_security.health.error_codes.${key}`
    );

    if (translated && translated !== `admin.account_security.health.error_codes.${key}`) {
      return translated;
    }

    return String(value)
      .replace(/[_-]+/g, " ")
      .replace(/\s+/g, " ")
      .trim()
      .replace(/^./, (char) => char.toUpperCase());
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
