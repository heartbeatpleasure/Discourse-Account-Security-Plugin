import Controller from "@ember/controller";
import { action } from "@ember/object";
import { tracked } from "@glimmer/tracking";
import { ajax } from "discourse/lib/ajax";
import { popupAjaxError } from "discourse/lib/ajax-error";
import { i18n } from "discourse-i18n";
import { formatAccountSecurityDateTime } from "../../lib/account-security-date";


const AUDIT_ACTIONS = new Set([
  "event_created",
  "incident_escalated",
  "review_changed",
  "intelligence_refreshed",
  "user_note_added",
  "temporary_block_created",
  "temporary_block_released",
  "notification_suppression_created",
  "notification_suppression_released",
  "abuse_report_attempted",
  "abuse_reported",
  "staff_notified",
]);

export default class AdminPluginsAccountSecurityEventController extends Controller {
  @tracked data;
  @tracked resolutionReason = "";
  @tracked durationMinutes = 1440;
  @tracked confirmTemporaryBlock = false;
  @tracked confirmAbuseReport = false;
  @tracked suppressionDurationHours = 168;
  @tracked confirmNotificationSuppression = false;
  @tracked isWorking = false;

  resetState(model) {
    this.data = this.decorateData(model);
    this.resolutionReason = model?.event?.resolution_reason || "";
    this.durationMinutes = 1440;
    this.confirmTemporaryBlock = false;
    this.confirmAbuseReport = false;
    this.suppressionDurationHours = 168;
    this.confirmNotificationSuppression = false;
    this.isWorking = false;
  }

  decorateData(data) {
    if (!data) {
      return data;
    }

    const event = data.event
      ? {
          ...data.event,
          created_at_display: formatAccountSecurityDateTime(data.event.created_at),
          last_seen_at_display: formatAccountSecurityDateTime(data.event.last_seen_at),
          reviewed_at_display: formatAccountSecurityDateTime(data.event.reviewed_at),
          user_note_created_at_display: formatAccountSecurityDateTime(
            data.event.user_note_created_at
          ),
          notified_at_display: formatAccountSecurityDateTime(data.event.notified_at),
        }
      : null;

    const intelligence = data.intelligence
      ? {
          ...data.intelligence,
          last_reported_at_display: formatAccountSecurityDateTime(
            data.intelligence.last_reported_at
          ),
          provider_checked_at_display: formatAccountSecurityDateTime(
            data.intelligence.provider_checked_at
          ),
          next_check_after_display: formatAccountSecurityDateTime(
            data.intelligence.next_check_after
          ),
        }
      : null;

    const intelligenceSnapshot = data.intelligence_snapshot
      ? {
          ...data.intelligence_snapshot,
          captured_at_display: formatAccountSecurityDateTime(
            data.intelligence_snapshot.captured_at
          ),
          last_reported_at_display: formatAccountSecurityDateTime(
            data.intelligence_snapshot.last_reported_at
          ),
          provider_checked_at_display: formatAccountSecurityDateTime(
            data.intelligence_snapshot.provider_checked_at
          ),
        }
      : null;

    const auditHistory = (data.audit_history || []).map((audit) =>
      this.decorateAudit(audit)
    );

    const temporaryBlock = data.temporary_block
      ? {
          ...data.temporary_block,
          expires_at_display: formatAccountSecurityDateTime(
            data.temporary_block.expires_at
          ),
        }
      : null;

    const notificationSuppression = data.notification_suppression
      ? {
          ...data.notification_suppression,
          expires_at_display: formatAccountSecurityDateTime(
            data.notification_suppression.expires_at
          ),
        }
      : null;

    return {
      ...data,
      event,
      intelligence,
      intelligence_snapshot: intelligenceSnapshot,
      audit_history: auditHistory,
      temporary_block: temporaryBlock,
      notification_suppression: notificationSuppression,
    };
  }

  decorateAudit(audit) {
    const action = AUDIT_ACTIONS.has(audit?.action) ? audit.action : "generic";
    const details = audit?.details || {};

    return {
      ...audit,
      action_label: i18n(
        `admin.account_security.event_detail.audit.actions.${action}`
      ),
      actor_display:
        audit?.actor?.username ||
        i18n("admin.account_security.event_detail.audit.system_actor"),
      created_at_display: formatAccountSecurityDateTime(audit?.created_at),
      status_display: this.auditStatusDisplay(audit),
      details_display: this.auditDetailsDisplay(details),
    };
  }

  auditStatusDisplay(audit) {
    if (!audit?.from_status && !audit?.to_status) {
      return null;
    }

    const from = audit.from_status || "—";
    const to = audit.to_status || "—";
    return i18n("admin.account_security.event_detail.audit.status_change", {
      from,
      to,
    });
  }

  auditDetailsDisplay(details) {
    const parts = [];
    const addChange = (key, fromKey, toKey) => {
      if (details[fromKey] || details[toKey]) {
        parts.push(
          i18n(`admin.account_security.event_detail.audit.${key}`, {
            from: details[fromKey] || "—",
            to: details[toKey] || "—",
          })
        );
      }
    };

    addChange("risk_change", "risk_level_from", "risk_level_to");
    addChange("severity_change", "severity_from", "severity_to");
    addChange("evidence_change", "evidence_from", "evidence_to");

    if (details.resolution_reason) {
      parts.push(
        i18n("admin.account_security.event_detail.audit.reason_detail", {
          value: details.resolution_reason,
        })
      );
    }
    if (details.duration_minutes) {
      parts.push(
        i18n("admin.account_security.event_detail.audit.duration_minutes", {
          value: details.duration_minutes,
        })
      );
    }
    if (details.duration_hours) {
      parts.push(
        i18n("admin.account_security.event_detail.audit.duration_hours", {
          value: details.duration_hours,
        })
      );
    }
    if (details.result) {
      parts.push(
        i18n("admin.account_security.event_detail.audit.result_detail", {
          value: details.result,
        })
      );
    }
    if (details.provider_status) {
      parts.push(
        i18n("admin.account_security.event_detail.audit.provider_status_detail", {
          value: details.provider_status,
        })
      );
    }
    if (details.notification_kind) {
      parts.push(
        i18n("admin.account_security.event_detail.audit.notification_detail", {
          value: details.notification_kind,
        })
      );
    }

    return parts.join(" · ");
  }

  get event() {
    return this.data?.event;
  }

  get temporaryBlockActive() {
    return this.data?.temporary_block?.active === true;
  }

  get notificationSuppressionActive() {
    return this.data?.notification_suppression?.active === true;
  }

  get canCreateNotificationSuppression() {
    return (
      this.data?.capabilities?.notification_suppression_eligible === true &&
      !this.notificationSuppressionActive
    );
  }

  get canCreateTemporaryBlock() {
    return (
      this.data?.capabilities?.temporary_ip_blocks_enabled === true &&
      this.data?.capabilities?.temporary_block_eligible === true &&
      !this.temporaryBlockActive
    );
  }

  get canAddUserNote() {
    return (
      this.data?.capabilities?.user_note_available === true &&
      !this.event?.user_note_created_at
    );
  }

  @action
  updateResolutionReason(event) {
    this.resolutionReason = event.target.value;
  }

  @action
  updateDuration(event) {
    this.durationMinutes = Number(event.target.value);
  }

  @action
  updateSuppressionDuration(event) {
    this.suppressionDurationHours = Number(event.target.value);
  }

  @action
  updateNotificationSuppressionConfirmation(event) {
    this.confirmNotificationSuppression = event.target.checked;
  }

  @action
  updateTemporaryBlockConfirmation(event) {
    this.confirmTemporaryBlock = event.target.checked;
  }

  @action
  updateAbuseReportConfirmation(event) {
    this.confirmAbuseReport = event.target.checked;
  }

  @action
  async review(status) {
    await this.perform(async () => {
      await ajax(`/admin/plugins/account-security/events/${this.event.id}.json`, {
        type: "PUT",
        data: {
          status,
          resolution_reason: this.resolutionReason,
        },
      });
      await this.reloadData();
    });
  }

  @action
  async refreshEvent() {
    await this.perform(async () => {
      await ajax(
        `/admin/plugins/account-security/events/${this.event.id}/refresh.json`,
        { type: "POST" }
      );
      await this.reloadData();
    });
  }

  @action
  async addUserNote() {
    await this.perform(async () => {
      await ajax(
        `/admin/plugins/account-security/events/${this.event.id}/user-note.json`,
        { type: "POST", data: { confirmed: true } }
      );
      await this.reloadData();
    });
  }

  @action
  async createTemporaryBlock() {
    if (!this.confirmTemporaryBlock) {
      return;
    }

    await this.perform(async () => {
      await ajax(
        `/admin/plugins/account-security/events/${this.event.id}/temporary-block.json`,
        {
          type: "POST",
          data: {
            confirmed: true,
            duration_minutes: this.durationMinutes,
          },
        }
      );
      this.confirmTemporaryBlock = false;
      await this.reloadData();
    });
  }

  @action
  async releaseTemporaryBlock() {
    await this.perform(async () => {
      await ajax(
        `/admin/plugins/account-security/events/${this.event.id}/temporary-block.json`,
        { type: "DELETE" }
      );
      await this.reloadData();
    });
  }

  @action
  async createNotificationSuppression() {
    if (!this.confirmNotificationSuppression) {
      return;
    }

    await this.perform(async () => {
      await ajax(
        `/admin/plugins/account-security/events/${this.event.id}/notification-suppression.json`,
        {
          type: "POST",
          data: {
            confirmed: true,
            duration_hours: this.suppressionDurationHours,
          },
        }
      );
      this.confirmNotificationSuppression = false;
      await this.reloadData();
    });
  }

  @action
  async releaseNotificationSuppression() {
    await this.perform(async () => {
      await ajax(
        `/admin/plugins/account-security/events/${this.event.id}/notification-suppression.json`,
        { type: "DELETE" }
      );
      await this.reloadData();
    });
  }

  @action
  async reportAbuse() {
    if (!this.confirmAbuseReport) {
      return;
    }

    await this.perform(async () => {
      await ajax("/admin/plugins/account-security/report.json", {
        type: "POST",
        data: {
          event_id: this.event.id,
          confirmed: true,
        },
      });
      this.confirmAbuseReport = false;
      await this.reloadData();
    });
  }

  async reloadData() {
    this.data = this.decorateData(
      await ajax(`/admin/plugins/account-security/events/${this.event.id}.json`)
    );
    this.resolutionReason = this.event?.resolution_reason || this.resolutionReason;
  }

  async perform(callback) {
    if (this.isWorking) {
      return;
    }

    this.isWorking = true;
    try {
      await callback();
    } catch (error) {
      popupAjaxError(error);
    } finally {
      this.isWorking = false;
    }
  }
}
