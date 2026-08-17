import Controller from "@ember/controller";
import { action } from "@ember/object";
import { tracked } from "@glimmer/tracking";
import { ajax } from "discourse/lib/ajax";
import { popupAjaxError } from "discourse/lib/ajax-error";

export default class AdminPluginsAccountSecurityEventController extends Controller {
  @tracked data;
  @tracked resolutionReason = "";
  @tracked durationMinutes = 1440;
  @tracked confirmTemporaryBlock = false;
  @tracked confirmAbuseReport = false;
  @tracked isWorking = false;

  resetState(model) {
    this.data = model;
    this.resolutionReason = model?.event?.resolution_reason || "";
    this.durationMinutes = 1440;
    this.confirmTemporaryBlock = false;
    this.confirmAbuseReport = false;
    this.isWorking = false;
  }

  get event() {
    return this.data?.event;
  }

  get temporaryBlockActive() {
    return this.data?.temporary_block?.active === true;
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
    this.data = await ajax(
      `/admin/plugins/account-security/events/${this.event.id}.json`
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
