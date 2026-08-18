import Controller from "@ember/controller";
import { action } from "@ember/object";
import { tracked } from "@glimmer/tracking";
import { ajax } from "discourse/lib/ajax";
import { popupAjaxError } from "discourse/lib/ajax-error";
import { i18n } from "discourse-i18n";
import { formatAccountSecurityDateTime } from "../../lib/account-security-date";

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
  correlation_scan_failed: "correlation_scan_failed",
  correlation_scan_stale: "correlation_scan_stale",
  correlation_schedule_overdue: "correlation_schedule_overdue",
  correlation_scheduler_failed: "correlation_scheduler_failed",
  correlation_health_failed: "correlation_health_failed",
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

  get correlationAutoScanLabel() {
    const allowed = ["off", "weekly", "monthly", "quarterly", "yearly"];
    const value = this.data?.configuration?.correlation_auto_scan_frequency;
    const key = allowed.includes(value) ? value : "monthly";
    return i18n(`admin.account_security.correlations.frequencies.${key}`);
  }

  get correlationHealth() {
    const value = this.data?.correlation;
    if (!value) { return null; }
    const allowedStates = ["disabled", "initializing", "healthy", "busy", "degraded"];
    const state = allowedStates.includes(value.state) ? value.state : "unknown";
    const allowedScanStates = ["never", "disabled", "queued", "running", "completed", "failed", "unknown"];
    const scanState = allowedScanStates.includes(value.scan?.state)
      ? value.scan.state
      : "unknown";
    return {
      ...value,
      state_label: i18n(`admin.account_security.health.correlation_states.${state}`),
      scan: value.scan
        ? {
            ...value.scan,
            state_label: i18n(`admin.account_security.health.correlation_scan_states.${scanState}`),
            queued_at_display: formatAccountSecurityDateTime(value.scan.queued_at),
            started_at_display: formatAccountSecurityDateTime(value.scan.started_at),
            heartbeat_at_display: formatAccountSecurityDateTime(value.scan.heartbeat_at),
            completed_at_display: formatAccountSecurityDateTime(value.scan.completed_at),
            last_success_at_display: formatAccountSecurityDateTime(value.scan.last_success_at),
            last_failure_at_display: formatAccountSecurityDateTime(value.scan.last_failure_at),
          }
        : null,
      schedule: value.schedule
        ? {
            ...value.schedule,
            next_run_at_display: formatAccountSecurityDateTime(value.schedule.next_run_at),
            last_scheduled_at_display: formatAccountSecurityDateTime(value.schedule.last_scheduled_at),
            expected_slot_at_display: formatAccountSecurityDateTime(value.schedule.expected_slot_at),
          }
        : null,
    };
  }

  get localNetworkContext() {
    const context = this.data?.local_network_context;
    if (!context) {
      return null;
    }

    const allowed = ["available", "partial", "unavailable", "unknown"];
    const state = allowed.includes(context.overall) ? context.overall : "unknown";
    return {
      ...context,
      incomplete: context.city?.available !== true || context.asn?.available !== true,
      state_label: i18n(`admin.account_security.health.maxmind_states.${state}`),
      city_updated_at_display: formatAccountSecurityDateTime(context.city?.updated_at),
      asn_updated_at_display: formatAccountSecurityDateTime(context.asn?.updated_at),
    };
  }

  get overallReasonText() {
    const reason = this.data?.overall_reason;
    if (!reason) {
      return null;
    }
    const key = REASON_KEYS[reason] || "generic";
    return i18n(`admin.account_security.health.reasons.${key}`);
  }

  get correlationReasonText() {
    const reason = this.data?.correlation?.reason;
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
