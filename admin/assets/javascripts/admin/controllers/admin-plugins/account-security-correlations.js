import Controller from "@ember/controller";
import { action } from "@ember/object";
import { tracked } from "@glimmer/tracking";
import { ajax } from "discourse/lib/ajax";
import { popupAjaxError } from "discourse/lib/ajax-error";
import { i18n } from "discourse-i18n";
import { formatAccountSecurityDateTime } from "../../lib/account-security-date";

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

  sourceLabel(source) {
    const allowed = [
      "registration",
      "current",
      "history",
      "auth_session",
      "active_session",
    ];
    const key = allowed.includes(source) ? source : "history";
    return i18n(`admin.account_security.correlations.ip_sources.${key}`);
  }

  decorateIpDetail(detail, userA, userB) {
    const contexts = [];
    if (!detail.public) {
      contexts.push(i18n("admin.account_security.correlations.context_nonpublic"));
    }
    if (detail.trusted) {
      contexts.push(i18n("admin.account_security.correlations.context_trusted"));
    }
    if (detail.tor) {
      contexts.push(i18n("admin.account_security.correlations.context_tor"));
    }
    if (detail.hosting) {
      contexts.push(i18n("admin.account_security.correlations.context_hosting"));
    }
    if (detail.mobile) {
      contexts.push(i18n("admin.account_security.correlations.context_mobile"));
    }
    if (detail.local_blacklist) {
      contexts.push(i18n("admin.account_security.correlations.context_blacklist"));
    }
    if (detail.usage_type) {
      contexts.push(detail.usage_type);
    }

    return {
      ...detail,
      sources_a_display: (detail.sources_a || [])
        .map((source) => this.sourceLabel(source))
        .join(", "),
      sources_b_display: (detail.sources_b || [])
        .map((source) => this.sourceLabel(source))
        .join(", "),
      context_display:
        contexts.join(" · ") ||
        i18n("admin.account_security.correlations.context_standard"),
      low_weight: !detail.public || detail.trusted || detail.tor || detail.hosting || detail.mobile,
      seen_by_display: i18n("admin.account_security.correlations.ip_seen_by", {
        count: Number(detail.user_count || 0),
      }),
      account_a_sources_label: i18n(
        "admin.account_security.correlations.ip_account_a",
        { username: userA?.username || "—" }
      ),
      account_b_sources_label: i18n(
        "admin.account_security.correlations.ip_account_b",
        { username: userB?.username || "—" }
      ),
    };
  }

  decorateBreakdown(entry) {
    const label = i18n(
      `admin.account_security.correlations.score_reasons.${entry.key}`
    );
    const points = Number(entry.points || 0);
    return {
      ...entry,
      label,
      points_display: points > 0 ? `+${points}` : `${points}`,
      positive: points > 0,
      negative: points < 0,
      neutral: points === 0,
    };
  }

  decorateUser(user) {
    if (!user) {
      return null;
    }
    return {
      ...user,
      created_at_display: formatAccountSecurityDateTime(user.created_at),
      last_seen_at_display: formatAccountSecurityDateTime(user.last_seen_at),
    };
  }

  decorateItem(item) {
    const evidence = item.evidence || {};
    const userA = this.decorateUser(item.user_a);
    const userB = this.decorateUser(item.user_b);
    const signals = [];

    if (evidence.shared_exact_ip_count > 0) {
      signals.push(
        `${evidence.shared_exact_ip_count} ${i18n("admin.account_security.correlations.shared_exact_ips")}`
      );
    }
    if (evidence.shared_registration_ip) {
      signals.push(i18n("admin.account_security.correlations.shared_registration_ip"));
    }
    if (evidence.browser_continuity_count > 0) {
      signals.push(
        `${evidence.browser_continuity_count} ${i18n("admin.account_security.correlations.browser_continuity")}`
      );
    }
    if (evidence.shared_session_signature_count > 0) {
      signals.push(
        `${evidence.shared_session_signature_count} ${i18n("admin.account_security.correlations.shared_session_signatures")}`
      );
    }
    if (evidence.shared_network_count > 0) {
      signals.push(
        `${evidence.shared_network_count} ${i18n("admin.account_security.correlations.shared_networks")}`
      );
    }

    return {
      ...item,
      user_a: userA,
      user_b: userB,
      confidence_label: i18n(
        `admin.account_security.correlations.confidences.${item.confidence}`
      ),
      status_label: i18n(
        `admin.account_security.correlations.statuses.${item.status}`
      ),
      signal_summary:
        signals.join(" · ") ||
        i18n("admin.account_security.correlations.no_signals"),
      last_seen_at_display: formatAccountSecurityDateTime(item.last_seen_at),
      first_seen_at_display: formatAccountSecurityDateTime(item.first_seen_at),
      reviewed_at_display: formatAccountSecurityDateTime(item.reviewed_at),
      shared_ip_details: (evidence.shared_ip_details || []).map((detail) =>
        this.decorateIpDetail(detail, userA, userB)
      ),
      score_breakdown: (evidence.score_breakdown || []).map((entry) =>
        this.decorateBreakdown(entry)
      ),
      can_reopen: item.status !== "open",
    };
  }

  decorateScan(scan) {
    if (!scan) {
      return null;
    }

    const diagnostics = scan.diagnostics || {};
    const diagnosticCards = [
      ["diagnostics_registration_rows", diagnostics.registration_rows],
      ["diagnostics_current_rows", diagnostics.current_rows],
      ["diagnostics_history_rows", diagnostics.history_rows],
      ["diagnostics_auth_session_rows", diagnostics.auth_session_rows],
      ["diagnostics_active_session_rows", diagnostics.active_session_rows],
      ["diagnostics_exact_groups", diagnostics.exact_ip_groups],
      ["diagnostics_public_groups", diagnostics.public_ip_groups],
      ["diagnostics_nonpublic_groups", diagnostics.nonpublic_ip_groups],
      ["diagnostics_exact_pairs", diagnostics.exact_ip_pairs_generated],
      ["diagnostics_network_pairs", diagnostics.network_pairs_added],
      ["diagnostics_signature_pairs", diagnostics.signature_pairs_added],
      ["diagnostics_large_groups", diagnostics.large_ip_groups_skipped],
      ["diagnostics_total_pairs", diagnostics.total_candidate_pairs],
    ].map(([key, value]) => ({
      label: i18n(`admin.account_security.correlations.${key}`),
      value: Number(value || 0),
    }));

    const sourceKey = ["manual", "scheduled"].includes(scan.source)
      ? scan.source
      : "manual";

    return {
      ...scan,
      source_label: i18n(
        `admin.account_security.correlations.sources.${sourceKey}`
      ),
      queued_at_display: formatAccountSecurityDateTime(scan.queued_at),
      started_at_display: formatAccountSecurityDateTime(scan.started_at),
      completed_at_display: formatAccountSecurityDateTime(scan.completed_at),
      diagnostic_cards: diagnosticCards,
      auth_log_truncated: diagnostics.auth_log_truncated === true,
    };
  }

  decorateSchedule(schedule) {
    if (!schedule) {
      return null;
    }

    const allowed = ["off", "weekly", "monthly", "quarterly", "yearly"];
    const key = allowed.includes(schedule.frequency) ? schedule.frequency : "monthly";

    return {
      ...schedule,
      frequency_label: i18n(
        `admin.account_security.correlations.frequencies.${key}`
      ),
      next_run_at_display: formatAccountSecurityDateTime(schedule.next_run_at),
      last_scheduled_at_display: formatAccountSecurityDateTime(
        schedule.last_scheduled_at
      ),
    };
  }

  decorateData(data) {
    if (!data) {
      return data;
    }

    return {
      ...data,
      scan: this.decorateScan(data.scan),
      schedule: this.decorateSchedule(data.schedule),
      items: (data.items || []).map((item) => this.decorateItem(item)),
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
      this.data = this.decorateData(data);
    } catch (error) {
      popupAjaxError(error);
    } finally {
      this.isLoading = false;
    }
  }

  @action setStatus(event) { this.status = event.target.value; }
  @action setConfidence(event) { this.confidence = event.target.value; }
  @action setSearch(event) { this.search = event.target.value; }

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
