import Controller from "@ember/controller";
import { action } from "@ember/object";
import { tracked } from "@glimmer/tracking";
import { cancel, later, schedule } from "@ember/runloop";
import { ajax } from "discourse/lib/ajax";
import { popupAjaxError } from "discourse/lib/ajax-error";
import getURL from "discourse/lib/get-url";
import { userPath } from "discourse/lib/url";
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
  @tracked groupPage = 1;
  @tracked sharedIpPage = 1;
  @tracked focusedPairId = null;
  @tracked activeView = "groups";
  @tracked loadedView = null;
  @tracked viewInitialized = false;
  @tracked calibrationOpen = false;
  @tracked calibrationLoading = false;
  @tracked calibrationSaving = false;
  @tracked calibrationData;
  @tracked calibrationFields = [];
  @tracked calibrationPreview;
  @tracked calibrationPreviewLimit = 2000;

  _scanPollTimer = null;
  _scanPollingActive = false;
  _correlationRequestSerial = 0;

  resetState() {
    this.stopScanPolling();
    this._scanPollingActive = true;
    this.data = undefined;
    this.isLoading = false;
    this.isScanning = false;
    this.status = "";
    this.confidence = "";
    this.search = "";
    this.page = 1;
    this.groupPage = 1;
    this.sharedIpPage = 1;
    this.focusedPairId = this.pairIdFromUrl();
    this.activeView = this.focusedPairId ? "pairs" : "groups";
    this.loadedView = null;
    this._correlationRequestSerial += 1;
    this.viewInitialized = Boolean(this.focusedPairId);
    this.calibrationOpen = false;
    this.calibrationLoading = false;
    this.calibrationSaving = false;
    this.calibrationData = undefined;
    this.calibrationFields = [];
    this.calibrationPreview = undefined;
    this.calibrationPreviewLimit = 2000;
  }

  pairIdFromUrl() {
    try {
      const value = Number(new URL(window.location.href).searchParams.get("pair_id"));
      return Number.isInteger(value) && value > 0 ? value : null;
    } catch {
      return null;
    }
  }

  clearFocusedPair() {
    this.focusedPairId = null;
    try {
      const url = new URL(window.location.href);
      if (url.searchParams.has("pair_id")) {
        url.searchParams.delete("pair_id");
        window.history.replaceState({}, "", `${url.pathname}${url.search}${url.hash}`);
      }
    } catch {
      // URL cleanup is best effort only.
    }
  }

  get isGroupsView() {
    return this.activeView === "groups";
  }

  get isSharedIpsView() {
    return this.activeView === "shared_ips";
  }

  get isPairsView() {
    return this.activeView === "pairs";
  }

  get sharedIpsReady() {
    return this.loadedView === "shared_ips";
  }

  get activeTabId() {
    return `account-security-correlation-tab-${this.activeView}`;
  }

  initializeView(data) {
    if (this.viewInitialized || !data) {
      return;
    }

    if ((data.account_groups || []).length > 0) {
      this.activeView = "groups";
    } else if ((data.shared_ip_groups || []).length > 0) {
      this.activeView = "shared_ips";
    } else {
      this.activeView = "pairs";
    }
    this.viewInitialized = true;
  }

  @action
  selectView(view) {
    if (!["groups", "shared_ips", "pairs"].includes(view)) {
      return;
    }

    const changed = this.activeView !== view;
    const wasFocused = Boolean(this.focusedPairId);
    if (wasFocused && view !== "pairs") {
      this.clearFocusedPair();
    }

    this.activeView = view;
    this.viewInitialized = true;

    if (changed || (wasFocused && view !== "pairs")) {
      this.loadedView = null;
      this.loadCorrelations();
    }
  }

  @action
  navigateViews(index, event) {
    const views = ["groups", "shared_ips", "pairs"];
    let nextIndex;

    if (event.key === "ArrowLeft") {
      nextIndex = (index - 1 + views.length) % views.length;
    } else if (event.key === "ArrowRight") {
      nextIndex = (index + 1) % views.length;
    } else if (event.key === "Home") {
      nextIndex = 0;
    } else if (event.key === "End") {
      nextIndex = views.length - 1;
    } else {
      return;
    }

    event.preventDefault();
    this.selectView(views[nextIndex]);
    schedule("afterRender", () => {
      document
        .getElementById(`account-security-correlation-tab-${views[nextIndex]}`)
        ?.focus();
    });
  }

  sourceLabel(source) {
    const allowed = [
      "registration",
      "current",
      "history",
      "auth_session",
      "active_session",
      "session_observation",
    ];
    const key = allowed.includes(source) ? source : "history";
    return i18n(`admin.account_security.correlations.ip_sources.${key}`);
  }

  decorateNetworkContext(context) {
    const value = context || {};
    const maxmind = value.maxmind || {};
    const asn = Number(maxmind.asn || 0);
    const asnDisplay = asn > 0 ? `AS${asn}` : null;
    const networkDisplay = [asnDisplay, maxmind.organization]
      .filter(Boolean)
      .join(" · ");
    const locationDisplay = maxmind.location || null;

    return {
      ...value,
      maxmind,
      asn_display: asnDisplay,
      network_display: networkDisplay || null,
      location_display: locationDisplay,
      has_local_context: Boolean(networkDisplay || locationDisplay),
    };
  }

  sharedExactIpLabel(count) {
    const value = Number(count || 0);
    const key = value === 1 ? "shared_exact_ip_one" : "shared_exact_ip_other";
    return i18n(`admin.account_security.correlations.${key}`, { count: value });
  }

  decorateIpDetail(detail, userA, userB) {
    const contexts = [];
    const networkContext = this.decorateNetworkContext(detail.network_context);
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
      network_context: networkContext,
      sources_a_display: (detail.sources_a || [])
        .map((source) => this.sourceLabel(source))
        .join(", "),
      sources_b_display: (detail.sources_b || [])
        .map((source) => this.sourceLabel(source))
        .join(", "),
      context_display:
        contexts.join(" · ") ||
        i18n("admin.account_security.correlations.context_standard"),
      contextual:
        !detail.public ||
        detail.trusted ||
        detail.tor ||
        detail.hosting ||
        detail.mobile ||
        networkContext.country_mismatch === true,
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


  temporalGapLabel(seconds) {
    if (seconds === null || seconds === undefined || seconds === "") {
      return "—";
    }
    const value = Number(seconds);
    if (!Number.isFinite(value) || value < 0) {
      return "—";
    }
    if (value < 60) {
      return i18n("admin.account_security.correlations.temporal_gap_less_than_minute");
    }
    if (value < 3600) {
      return i18n("admin.account_security.correlations.temporal_gap_minutes", {
        count: Math.max(1, Math.round(value / 60)),
      });
    }
    if (value < 86400) {
      return i18n("admin.account_security.correlations.temporal_gap_hours", {
        count: Math.max(1, Math.round(value / 3600)),
      });
    }
    return i18n("admin.account_security.correlations.temporal_gap_days", {
      count: Math.max(1, Math.round(value / 86400)),
    });
  }

  decorateTemporalDetail(detail, userA, userB) {
    return {
      ...detail,
      closest_gap_display: this.temporalGapLabel(detail.closest_gap_seconds),
      account_a_label: userA?.username || "—",
      account_b_label: userB?.username || "—",
    };
  }

  decorateAuthProximityDetail(detail) {
    return {
      ...detail,
      closest_gap_display: this.temporalGapLabel(detail.closest_gap_seconds),
    };
  }

  decorateTransitionDetail(detail) {
    return {
      ...detail,
      closest_gap_display: this.temporalGapLabel(
        detail.closest_transition_gap_seconds
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
      profile_url: userPath(user.username),
      admin_url: getURL(`/admin/users/${user.id}/${encodeURIComponent(user.username)}`),
      created_at_display: formatAccountSecurityDateTime(user.created_at),
      last_seen_at_display: formatAccountSecurityDateTime(user.last_seen_at),
    };
  }

  decorateReview(review) {
    const actionKey = [
      "status_changed",
      "note_added",
      "primary_account_changed",
      "duplicate_user_note_added",
    ].includes(review.action)
      ? review.action
      : "note_added";

    const fromStatusLabel = review.from_status
      ? i18n(`admin.account_security.correlations.statuses.${review.from_status}`)
      : null;
    const toStatusLabel = review.to_status
      ? i18n(`admin.account_security.correlations.statuses.${review.to_status}`)
      : null;

    return {
      ...review,
      created_at_display: formatAccountSecurityDateTime(review.created_at),
      action_label: i18n(
        `admin.account_security.correlations.review_actions.${actionKey}`
      ),
      from_status_label: fromStatusLabel,
      to_status_label: toStatusLabel,
      status_transition_display:
        fromStatusLabel && toStatusLabel && fromStatusLabel !== toStatusLabel
          ? `${fromStatusLabel} → ${toStatusLabel}`
          : toStatusLabel,
    };
  }

  decorateCompactItem(item) {
    if (!item) {
      return null;
    }
    return {
      ...item,
      user_a: this.decorateUser(item.user_a),
      user_b: this.decorateUser(item.user_b),
      confidence_label: i18n(
        `admin.account_security.correlations.confidences.${item.confidence}`
      ),
      status_label: i18n(
        `admin.account_security.correlations.statuses.${item.status}`
      ),
      context_only_label: item.context_only
        ? i18n(
            `admin.account_security.correlations.context_only_reasons.${item.context_only_reason || "non_scoring_context"}`
          )
        : null,
    };
  }

  decorateItem(item) {
    const evidence = item.evidence || {};
    const userA = this.decorateUser(item.user_a);
    const userB = this.decorateUser(item.user_b);
    const primaryUser = this.decorateUser(item.primary_user);
    const rawPolicyActions = item.policy_actions || {};
    const additionalUserId = Number(rawPolicyActions.additional_user_id || 0);
    const additionalUser =
      userA?.id === additionalUserId
        ? userA
        : userB?.id === additionalUserId
          ? userB
          : null;
    const policyActions = {
      ...rawPolicyActions,
      additional_user: additionalUser,
      duplicate_user_note_added_at_display: formatAccountSecurityDateTime(
        rawPolicyActions.duplicate_user_note_added_at
      ),
    };
    const signals = [];

    if (evidence.shared_exact_ip_count > 0) {
      signals.push(this.sharedExactIpLabel(evidence.shared_exact_ip_count));
    }
    if (evidence.shared_registration_ip) {
      signals.push(i18n("admin.account_security.correlations.shared_registration_ip"));
    }
    if (evidence.shared_auth_ip_count > 0) {
      signals.push(
        i18n("admin.account_security.correlations.shared_auth_evidence", {
          count: evidence.shared_auth_ip_count,
        })
      );
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

    const networkSummary = evidence.network_context_summary || {};

    return {
      ...item,
      user_a: userA,
      user_b: userB,
      primary_user: primaryUser,
      policy_actions: policyActions,
      review_history: (item.review_history || []).map((review) =>
        this.decorateReview(review)
      ),
      confidence_label: i18n(
        `admin.account_security.correlations.confidences.${item.confidence}`
      ),
      context_only_label: item.context_only
        ? i18n(`admin.account_security.correlations.context_only_reasons.${item.context_only_reason || "non_scoring_context"}`)
        : null,
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
      temporal_ip_details: (evidence.temporal_ip_details || []).map((detail) =>
        this.decorateTemporalDetail(detail, userA, userB)
      ),
      temporal_closest_gap_display: this.temporalGapLabel(
        evidence.closest_shared_ip_gap_seconds
      ),
      auth_proximity_closest_gap_display: this.temporalGapLabel(
        evidence.auth_proximity_closest_gap_seconds
      ),
      public_ip_transition_closest_gap_display: this.temporalGapLabel(
        evidence.public_ip_transition_closest_gap_seconds
      ),
      browser_account_switch_closest_gap_display: this.temporalGapLabel(
        evidence.browser_account_switch_closest_gap_seconds
      ),
      has_temporal_evidence: Number(evidence.timed_shared_ip_count || 0) > 0,
      auth_proximity_details: (evidence.auth_proximity_details || []).map(
        (detail) => this.decorateAuthProximityDetail(detail)
      ),
      public_ip_transition_details: (
        evidence.public_ip_transition_details || []
      ).map((detail) => this.decorateTransitionDetail(detail)),
      has_auth_pattern_evidence:
        Number(evidence.auth_proximity_within_7d_count || 0) > 0 ||
        Number(evidence.shared_auth_client_signature_count || 0) > 0 ||
        Number(evidence.public_ip_transition_pattern_count || 0) > 0 ||
        Number(evidence.repeated_browser_continuity_count || 0) > 0 ||
        Number(evidence.browser_account_switch_count || 0) > 0 ||
        Number(evidence.repeated_shared_session_signature_count || 0) > 0,
      auth_pattern_history_incomplete:
        evidence.auth_pattern_history_complete !== true ||
        evidence.combined_session_login_history_complete !== true ||
        evidence.core_auth_history_complete !== true ||
        evidence.exact_ip_population_complete !== true ||
        (Number(evidence.client_signature_group_count || 0) > 0 &&
          evidence.client_signature_population_complete !== true),
      network_context_summary: {
        ...networkSummary,
        organizations_display: (networkSummary.organizations || []).join(", "),
        countries_display: (networkSummary.country_codes || []).join(", "),
        asns_display: (networkSummary.asns || [])
          .map((asn) => `AS${asn}`)
          .join(", "),
      },
      has_network_context:
        Number(networkSummary.locally_enriched_ip_count || 0) > 0,
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
      ["diagnostics_session_observation_rows", diagnostics.session_observation_rows],
      ["diagnostics_browser_switch_rows", diagnostics.browser_switch_rows],
      ["diagnostics_exact_groups", diagnostics.exact_ip_groups],
      ["diagnostics_public_groups", diagnostics.public_ip_groups],
      ["diagnostics_nonpublic_groups", diagnostics.nonpublic_ip_groups],
      ["diagnostics_exact_pairs", diagnostics.exact_ip_pairs_generated],
      ["diagnostics_network_pairs", diagnostics.network_pairs_added],
      ["diagnostics_signature_pairs", diagnostics.signature_pairs_added],
      ["diagnostics_large_groups", diagnostics.large_ip_groups_skipped],
      ["diagnostics_existing_pairs", diagnostics.existing_pairs_total],
      ["diagnostics_discovery_pairs", diagnostics.discovery_pairs_selected],
      ["diagnostics_existing_processed", diagnostics.existing_pairs_processed],
      ["diagnostics_discovery_processed", diagnostics.discovery_pairs_processed],
      ["diagnostics_temporal_observations", diagnostics.temporal_observation_rows],
      ["diagnostics_auth_pattern_rows", diagnostics.auth_pattern_rows],
      ["diagnostics_total_pairs", diagnostics.total_candidate_pairs],
    ].map(([key, value]) => ({
      label: i18n(`admin.account_security.correlations.${key}`),
      value: Number(value || 0),
    }));

    const sourceKey = ["manual", "scheduled"].includes(scan.source)
      ? scan.source
      : "manual";

    const largeSharedGroups = (diagnostics.large_ip_group_summaries || []).map(
      (group) => {
        const networkContext = this.decorateNetworkContext(group.network_context);
        const contexts = [];
        if (!group.public) {
          contexts.push(i18n("admin.account_security.correlations.context_nonpublic"));
        }
        if (group.trusted) {
          contexts.push(i18n("admin.account_security.correlations.context_trusted"));
        }
        if (group.tor) {
          contexts.push(i18n("admin.account_security.correlations.context_tor"));
        }
        if (group.hosting) {
          contexts.push(i18n("admin.account_security.correlations.context_hosting"));
        }
        if (group.mobile) {
          contexts.push(i18n("admin.account_security.correlations.context_mobile"));
        }
        return {
          ...group,
          network_context: networkContext,
          context_display:
            contexts.join(" · ") ||
            i18n("admin.account_security.correlations.context_standard"),
          account_count_label: i18n(
            "admin.account_security.correlations.group_account_count",
            { count: Number(group.user_count || 0) }
          ),
        };
      }
    );

    return {
      ...scan,
      source_label: i18n(
        `admin.account_security.correlations.sources.${sourceKey}`
      ),
      queued_at_display: formatAccountSecurityDateTime(scan.queued_at),
      started_at_display: formatAccountSecurityDateTime(scan.started_at),
      completed_at_display: formatAccountSecurityDateTime(scan.completed_at),
      diagnostic_cards: diagnosticCards,
      large_shared_groups: largeSharedGroups,
      auth_log_truncated:
        diagnostics.auth_log_truncated === true ||
        diagnostics.temporal_auth_log_truncated === true,
      session_observation_truncated:
        diagnostics.session_observation_truncated === true ||
        diagnostics.temporal_session_observation_truncated === true ||
        diagnostics.browser_switch_rows_truncated === true,
      stale_recovered: scan.stale_recovered === true,
      has_pair_failures: Number(scan.pairs_failed || 0) > 0,
      has_pair_skips: Number(scan.pairs_skipped || 0) > 0,
    };
  }

  decorateSchedule(schedule) {
    if (!schedule) {
      return null;
    }

    return {
      ...schedule,
      next_run_at_display: formatAccountSecurityDateTime(schedule.next_run_at),
    };
  }

  decorateSharedIpGroup(group) {
    const networkContext = this.decorateNetworkContext(group.network_context);
    const contexts = [];
    if (!group.public) { contexts.push(i18n("admin.account_security.correlations.context_nonpublic")); }
    if (group.trusted) { contexts.push(i18n("admin.account_security.correlations.context_trusted")); }
    if (group.tor) { contexts.push(i18n("admin.account_security.correlations.context_tor")); }
    if (group.hosting) { contexts.push(i18n("admin.account_security.correlations.context_hosting")); }
    if (group.mobile) { contexts.push(i18n("admin.account_security.correlations.context_mobile")); }
    if (group.local_blacklist) { contexts.push(i18n("admin.account_security.correlations.context_blacklist")); }
    if (group.usage_type) { contexts.push(group.usage_type); }

    const accounts = (group.accounts || [])
      .map((account) => ({
        ...this.decorateUser(account),
        sources_display: (account.sources || [])
          .map((source) => this.sourceLabel(source))
          .join(", "),
      }))
      .sort((a, b) => (a.username || "").localeCompare(b.username || ""));
    const pairs = (group.pairs || [])
      .map((item) => this.decorateCompactItem(item))
      .filter(Boolean);
    const totalAccounts = Number(group.total_accounts || accounts.length || 0);

    return {
      ...group,
      accounts,
      pairs,
      network_context: networkContext,
      context_display:
        contexts.join(" · ") ||
        i18n("admin.account_security.correlations.context_standard"),
      account_count_label: i18n(
        "admin.account_security.correlations.group_account_count",
        { count: totalAccounts }
      ),
      coverage_label: group.accounts_truncated
        ? i18n("admin.account_security.correlations.group_partial_accounts", {
            visible: accounts.length,
            total: totalAccounts,
          })
        : i18n("admin.account_security.correlations.group_all_accounts", {
            count: totalAccounts,
          }),
      pair_count_label: i18n(
        "admin.account_security.correlations.group_pair_count",
        { count: Number(group.pair_count || 0) }
      ),
    };
  }

  decorateGroupAnchor(anchor) {
    const networkContext = this.decorateNetworkContext(anchor.network_context);
    const contexts = [];
    if (!anchor.public) {
      contexts.push(i18n("admin.account_security.correlations.context_nonpublic"));
    }
    if (anchor.trusted) {
      contexts.push(i18n("admin.account_security.correlations.context_trusted"));
    }
    if (anchor.tor) {
      contexts.push(i18n("admin.account_security.correlations.context_tor"));
    }
    if (anchor.hosting) {
      contexts.push(i18n("admin.account_security.correlations.context_hosting"));
    }
    if (anchor.mobile) {
      contexts.push(i18n("admin.account_security.correlations.context_mobile"));
    }

    return {
      ...anchor,
      network_context: networkContext,
      context_display:
        contexts.join(" · ") ||
        i18n("admin.account_security.correlations.context_standard"),
      account_count_label: i18n(
        "admin.account_security.correlations.group_account_count",
        { count: Number(anchor.account_count || 0) }
      ),
    };
  }

  decorateAccountGroup(group, items) {
    const accounts = (group.accounts || []).map((user) => ({
      ...this.decorateUser(user),
      direct_relation_count: Number(user.direct_relation_count || 0),
    }));
    const visiblePairs = (group.pairs || [])
      .map((item) => this.decorateCompactItem(item))
      .filter(Boolean);
    const statusCounts = group.status_counts || {};
    const evidenceCounts = group.evidence_counts || {};
    const allPairsVisible = group.pairs_truncated !== true;
    const contextOnlyGroup =
      allPairsVisible &&
      visiblePairs.length > 0 &&
      visiblePairs.every((item) => item.context_only === true);
    const evidenceSummary = [];

    if (Number(evidenceCounts.public_ip_pairs || 0) > 0) {
      evidenceSummary.push(
        i18n("admin.account_security.correlations.account_group_public_ip_pairs", {
          count: Number(evidenceCounts.public_ip_pairs || 0),
        })
      );
    }
    if (Number(evidenceCounts.registration_ip_pairs || 0) > 0) {
      evidenceSummary.push(
        i18n(
          "admin.account_security.correlations.account_group_registration_pairs",
          { count: Number(evidenceCounts.registration_ip_pairs || 0) }
        )
      );
    }
    if (Number(evidenceCounts.authentication_ip_pairs || 0) > 0) {
      evidenceSummary.push(
        i18n("admin.account_security.correlations.account_group_auth_pairs", {
          count: Number(evidenceCounts.authentication_ip_pairs || 0),
        })
      );
    }
    if (Number(evidenceCounts.browser_continuity_pairs || 0) > 0) {
      evidenceSummary.push(
        i18n("admin.account_security.correlations.account_group_browser_pairs", {
          count: Number(evidenceCounts.browser_continuity_pairs || 0),
        })
      );
    }
    if (Number(evidenceCounts.temporal_24h_pairs || 0) > 0) {
      evidenceSummary.push(
        i18n("admin.account_security.correlations.account_group_temporal_pairs", {
          count: Number(evidenceCounts.temporal_24h_pairs || 0),
        })
      );
    }
    if (Number(evidenceCounts.auth_proximity_pairs || 0) > 0) {
      evidenceSummary.push(
        i18n("admin.account_security.correlations.account_group_auth_proximity_pairs", {
          count: Number(evidenceCounts.auth_proximity_pairs || 0),
        })
      );
    }
    if (Number(evidenceCounts.auth_same_client_proximity_pairs || 0) > 0) {
      evidenceSummary.push(
        i18n("admin.account_security.correlations.account_group_auth_same_client_pairs", {
          count: Number(evidenceCounts.auth_same_client_proximity_pairs || 0),
        })
      );
    }
    if (Number(evidenceCounts.public_transition_pairs || 0) > 0) {
      evidenceSummary.push(
        i18n("admin.account_security.correlations.account_group_transition_pairs", {
          count: Number(evidenceCounts.public_transition_pairs || 0),
        })
      );
    }
    if (Number(evidenceCounts.browser_continuity_repeated_pairs || 0) > 0) {
      evidenceSummary.push(
        i18n("admin.account_security.correlations.account_group_repeated_browser_pairs", {
          count: Number(evidenceCounts.browser_continuity_repeated_pairs || 0),
        })
      );
    }
    if (Number(evidenceCounts.repeated_session_signature_pairs || 0) > 0) {
      evidenceSummary.push(
        i18n("admin.account_security.correlations.account_group_repeated_session_pairs", {
          count: Number(evidenceCounts.repeated_session_signature_pairs || 0),
        })
      );
    }

    const reviewSummary = [
      "open",
      "monitor",
      "expected_shared_network",
      "confirmed_duplicate",
      "dismissed",
    ]
      .filter((status) => Number(statusCounts[status] || 0) > 0)
      .map((status) => ({
        status,
        label: i18n(`admin.account_security.correlations.statuses.${status}`),
        count: Number(statusCounts[status] || 0),
      }));

    return {
      ...group,
      accounts,
      anchors: (group.anchors || []).map((anchor) =>
        this.decorateGroupAnchor(anchor)
      ),
      visible_pairs: visiblePairs,
      visible_pair_count: visiblePairs.length,
      all_pairs_visible: allPairsVisible,
      strongest_confidence_label: contextOnlyGroup
        ? i18n("admin.account_security.correlations.context_only_short")
        : i18n(
            `admin.account_security.correlations.confidences.${group.strongest_confidence}`
          ),
      account_count_label: i18n(
        "admin.account_security.correlations.group_account_count",
        { count: Number(group.account_count || 0) }
      ),
      relationship_label: i18n(
        "admin.account_security.correlations.account_group_relationships",
        {
          count: Number(group.relation_count || 0),
          possible: Number(group.possible_relation_count || 0),
        }
      ),
      visible_pair_label: i18n(
        "admin.account_security.correlations.account_group_pairs_visible",
        {
          visible: visiblePairs.length,
          total: Number(group.pair_record_count || group.relation_count || 0),
        }
      ),
      score_range_label: contextOnlyGroup
        ? i18n("admin.account_security.correlations.context_only_short")
        : Number(group.min_score || 0) === Number(group.max_score || 0)
          ? `${Number(group.max_score || 0)}`
          : `${Number(group.min_score || 0)}–${Number(group.max_score || 0)}`,
      evidence_summary: evidenceSummary,
      review_summary: reviewSummary,
    };
  }

  decorateData(data) {
    if (!data) {
      return data;
    }

    const items = (data.items || []).map((item) => this.decorateItem(item));
    const accountGroups = (data.account_groups || []).map((group) =>
      this.decorateAccountGroup(group, items)
    );
    const sharedIpGroups = (data.shared_ip_groups || []).map((group) =>
      this.decorateSharedIpGroup(group)
    );
    return {
      ...data,
      scan: this.decorateScan(data.scan),
      schedule: this.decorateSchedule(data.schedule),
      items,
      account_groups: accountGroups,
      shared_ip_groups: sharedIpGroups,
    };
  }

  decorateCalibration(data) {
    if (!data) {
      return data;
    }

    const draft = data.draft_profile || data.live_profile || {};
    const fields = (data.descriptors || []).map((descriptor) => ({
      ...descriptor,
      value: draft[descriptor.key] ?? descriptor.default,
      label: i18n(`admin.account_security.correlations.calibration.fields.${descriptor.key}`),
    }));
    const groupOrder = ["confidence", "ip", "timing", "transition", "browser", "client"];
    const groups = groupOrder.map((group) => ({
      key: group,
      label: i18n(`admin.account_security.correlations.calibration.groups.${group}`),
      fields: fields.filter((field) => field.group === group),
    }));

    return { ...data, groups };
  }

  calibrationProfile() {
    return Object.fromEntries(
      this.calibrationFields.map((field) => [field.key, field.value])
    );
  }

  applyCalibrationData(data) {
    const decorated = this.decorateCalibration(data);
    const firstLoad = !this.calibrationData;
    this.calibrationData = decorated;
    this.calibrationFields = (decorated?.groups || []).flatMap((group) =>
      group.fields.map((field) => ({ ...field }))
    );
    if (firstLoad && Number.isFinite(Number(decorated?.default_preview_rows))) {
      this.calibrationPreviewLimit = Number(decorated.default_preview_rows);
    }
  }

  decorateCalibrationPreview(preview) {
    if (!preview) {
      return preview;
    }

    const reviewStatusOrder = [
      "confirmed_duplicate",
      "expected_shared_network",
      "dismissed",
      "monitor",
      "open",
    ];
    const reviewMatrix = preview.review_matrix || {};
    const reviewRows = reviewStatusOrder
      .filter((status) => reviewMatrix[status])
      .map((status) => {
        const counts = reviewMatrix[status] || {};
        return {
          status,
          label: i18n(`admin.account_security.correlations.statuses.${status}`),
          weak: Number(counts.weak || 0),
          moderate: Number(counts.moderate || 0),
          strong: Number(counts.strong || 0),
          very_strong: Number(counts.very_strong || 0),
          total:
            Number(counts.weak || 0) +
            Number(counts.moderate || 0) +
            Number(counts.strong || 0) +
            Number(counts.very_strong || 0),
        };
      })
      .filter((row) => row.total > 0);

    return {
      ...preview,
      review_rows: reviewRows,
      largest_changes: (preview.largest_changes || []).map((row) => ({
        ...row,
        delta_display:
          Number(row.delta || 0) > 0
            ? `+${Number(row.delta || 0)}`
            : `${Number(row.delta || 0)}`,
        current_confidence_label: i18n(
          `admin.account_security.correlations.confidences.${row.current_confidence || "weak"}`
        ),
        preview_confidence_label: i18n(
          `admin.account_security.correlations.confidences.${row.preview_confidence || "weak"}`
        ),
        preview_breakdown: (row.preview_breakdown || []).map((entry) =>
          this.decorateBreakdown(entry)
        ),
      })),
    };
  }

  get calibrationGroups() {
    const groups = this.calibrationData?.groups || [];
    return groups.map((group) => ({
      ...group,
      fields: this.calibrationFields.filter((field) => field.group === group.key),
    }));
  }

  @action
  async toggleCalibration() {
    this.calibrationOpen = !this.calibrationOpen;
    if (!this.calibrationOpen || this.calibrationData || this.calibrationLoading) {
      return;
    }

    this.calibrationLoading = true;
    try {
      const data = await ajax(
        "/admin/plugins/account-security/scoring-calibration.json"
      );
      this.applyCalibrationData(data);
    } catch (error) {
      popupAjaxError(error);
    } finally {
      this.calibrationLoading = false;
    }
  }

  @action
  setCalibrationPreviewLimit(event) {
    const value = Number.parseInt(event.target.value, 10);
    if (!Number.isFinite(value)) {
      return;
    }
    const maximum = Number(this.calibrationData?.max_preview_rows || 5000);
    this.calibrationPreviewLimit = Math.max(1, Math.min(value, maximum));
  }

  @action
  setCalibrationField(key, event) {
    const raw = event.target.value;
    const field = this.calibrationFields.find((item) => item.key === key);
    if (!field) {
      return;
    }
    const value = field.kind === "integer" ? Number.parseInt(raw, 10) : Number.parseFloat(raw);
    if (!Number.isFinite(value)) {
      return;
    }
    this.calibrationFields = this.calibrationFields.map((item) =>
      item.key === key ? { ...item, value } : item
    );
  }

  @action
  async previewCalibration() {
    this.calibrationSaving = true;
    try {
      const preview = await ajax(
        "/admin/plugins/account-security/scoring-calibration/preview.json",
        {
          type: "POST",
          data: {
            profile: this.calibrationProfile(),
            limit: this.calibrationPreviewLimit,
          },
        }
      );
      this.calibrationPreview = this.decorateCalibrationPreview(preview);
    } catch (error) {
      popupAjaxError(error);
    } finally {
      this.calibrationSaving = false;
    }
  }

  @action
  async saveCalibrationDraft() {
    this.calibrationSaving = true;
    try {
      const data = await ajax(
        "/admin/plugins/account-security/scoring-calibration.json",
        { type: "PUT", data: { profile: this.calibrationProfile() } }
      );
      this.applyCalibrationData(data);
    } catch (error) {
      popupAjaxError(error);
    } finally {
      this.calibrationSaving = false;
    }
  }

  @action
  async resetCalibrationDraft() {
    if (!window.confirm(i18n("admin.account_security.correlations.calibration.reset_confirm"))) {
      return;
    }
    this.calibrationSaving = true;
    try {
      const data = await ajax(
        "/admin/plugins/account-security/scoring-calibration.json",
        { type: "DELETE" }
      );
      this.applyCalibrationData(data);
      this.calibrationPreview = undefined;
    } catch (error) {
      popupAjaxError(error);
    } finally {
      this.calibrationSaving = false;
    }
  }

  async fetchCorrelations({ quiet = false } = {}) {
    const requestSerial = ++this._correlationRequestSerial;
    const requestedView = this.activeView;
    const requestedFocusedPairId = this.focusedPairId;
    const requestedPage = this.page;
    const requestedGroupPage = this.groupPage;
    const requestedSharedIpPage = this.sharedIpPage;

    if (!quiet) {
      this.isLoading = true;
    }

    const filters = {
      status: this.status,
      confidence: this.confidence,
      search: this.search,
    };

    try {
      const pairRequest = ajax("/admin/plugins/account-security/correlations.json", {
        data: {
          ...filters,
          page: requestedPage,
          pair_id: requestedFocusedPairId || undefined,
          include_group_context: false,
        },
      });

      let data;
      if (requestedFocusedPairId) {
        data = await pairRequest;
        data = {
          ...data,
          account_groups: [],
          shared_ip_groups: [],
          account_groups_page: requestedGroupPage,
          account_groups_per_page: 20,
          account_groups_total: 0,
          shared_ip_page: requestedSharedIpPage,
          shared_ip_per_page: 20,
          shared_ip_total: 0,
        };
      } else if (requestedView === "groups") {
        const [pairData, groupData] = await Promise.all([
          pairRequest,
          ajax("/admin/plugins/account-security/correlations/groups.json", {
            data: { ...filters, page: requestedGroupPage },
          }),
        ]);
        data = {
          ...pairData,
          account_groups: groupData.account_groups || [],
          account_groups_truncated: groupData.account_groups_truncated === true,
          account_groups_page: groupData.page || 1,
          account_groups_per_page: groupData.per_page || 20,
          account_groups_total: groupData.total || 0,
          shared_ip_groups: [],
          shared_ip_page: requestedSharedIpPage,
          shared_ip_per_page: 20,
          shared_ip_total: 0,
        };
      } else if (requestedView === "shared_ips") {
        const [pairData, sharedIpData] = await Promise.all([
          pairRequest,
          ajax("/admin/plugins/account-security/correlations/shared-ips.json", {
            data: { ...filters, page: requestedSharedIpPage },
          }),
        ]);
        data = {
          ...pairData,
          account_groups: [],
          account_groups_page: requestedGroupPage,
          account_groups_per_page: 20,
          account_groups_total: 0,
          shared_ip_groups: sharedIpData.shared_ip_groups || [],
          shared_ip_page: sharedIpData.page || 1,
          shared_ip_per_page: sharedIpData.per_page || 20,
          shared_ip_total: sharedIpData.total || 0,
          shared_ip_source_complete: sharedIpData.source_complete !== false,
          shared_ip_filter_truncated: sharedIpData.filter_truncated === true,
          shared_ip_pair_preview_truncated:
            sharedIpData.pair_preview_truncated === true,
        };
      } else {
        const pairData = await pairRequest;
        data = {
          ...pairData,
          account_groups: [],
          shared_ip_groups: [],
          account_groups_page: requestedGroupPage,
          account_groups_per_page: 20,
          account_groups_total: 0,
          shared_ip_page: requestedSharedIpPage,
          shared_ip_per_page: 20,
          shared_ip_total: 0,
        };
      }

      // A slow response from a previously selected tab must never overwrite
      // the current view. Besides preventing stale data, this also prevents
      // transient warnings from being rendered against a response that belongs
      // to another tab.
      if (
        requestSerial !== this._correlationRequestSerial ||
        requestedView !== this.activeView ||
        requestedFocusedPairId !== this.focusedPairId
      ) {
        return false;
      }

      this.data = this.decorateData(data);
      this.loadedView = requestedFocusedPairId ? "pairs" : requestedView;
      this.initializeView(this.data);
      this.syncScanPolling();
      if (requestedFocusedPairId) {
        this.openFocusedPairAfterRender(requestedFocusedPairId);
      }
      return true;
    } catch (error) {
      if (requestSerial === this._correlationRequestSerial) {
        popupAjaxError(error);
      }
      return false;
    } finally {
      if (!quiet && requestSerial === this._correlationRequestSerial) {
        this.isLoading = false;
      }
    }
  }

  openFocusedPairAfterRender(pairId) {
    schedule("afterRender", () => {
      const element = document.getElementById(`correlation-${pairId}`);
      if (!element) { return; }
      element.open = true;
      element.scrollIntoView({ behavior: "smooth", block: "start" });
    });
  }

  @action
  async loadCorrelations() {
    return this.fetchCorrelations();
  }

  scanStateBusy(scan = this.data?.scan) {
    return scan?.state === "queued" || scan?.state === "running";
  }

  syncScanPolling() {
    if (this.scanStateBusy()) {
      this.startScanPolling();
    } else {
      this.stopScanPolling();
    }
  }

  startScanPolling() {
    if (!this._scanPollingActive) {
      return;
    }

    this.isScanning = true;
    if (this._scanPollTimer) {
      return;
    }

    this._scanPollTimer = later(this, this.pollScanStatus, 2000);
  }

  stopScanPolling() {
    if (this._scanPollTimer) {
      cancel(this._scanPollTimer);
      this._scanPollTimer = null;
    }
    this.isScanning = false;
  }

  deactivateScanPolling() {
    this._scanPollingActive = false;
    this.stopScanPolling();
  }

  async pollScanStatus() {
    this._scanPollTimer = null;

    try {
      const response = await ajax(
        "/admin/plugins/account-security/correlations/scan-status.json"
      );
      if (!this._scanPollingActive) {
        return;
      }

      const scan = this.decorateScan(response?.scan);
      this.data = this.data ? { ...this.data, scan } : { scan };

      if (this.scanStateBusy(scan)) {
        this.startScanPolling();
        return;
      }

      this.stopScanPolling();
      await this.fetchCorrelations({ quiet: true });
    } catch (error) {
      this.stopScanPolling();
      popupAjaxError(error);
    }
  }

  @action setStatus(event) { this.status = event.target.value; }
  @action setConfidence(event) { this.confidence = event.target.value; }
  @action setSearch(event) { this.search = event.target.value; }
  @action
  applyFilters() {
    this.page = 1;
    this.groupPage = 1;
    this.sharedIpPage = 1;
    this.clearFocusedPair();
    this.loadCorrelations();
  }

  get scanBusy() {
    return this.isScanning || this.scanStateBusy();
  }

  get currentPage() {
    if (this.isGroupsView) { return this.data?.account_groups_page || 1; }
    if (this.isSharedIpsView) { return this.data?.shared_ip_page || 1; }
    return this.data?.page || 1;
  }

  get currentPerPage() {
    if (this.isGroupsView) { return this.data?.account_groups_per_page || 20; }
    if (this.isSharedIpsView) { return this.data?.shared_ip_per_page || 20; }
    return this.data?.per_page || 50;
  }

  get currentTotal() {
    if (this.isGroupsView) { return this.data?.account_groups_total || 0; }
    if (this.isSharedIpsView) { return this.data?.shared_ip_total || 0; }
    return this.data?.total || 0;
  }

  get hasPreviousPage() {
    return this.currentPage > 1;
  }

  get hasNextPage() {
    return this.currentPage * this.currentPerPage < this.currentTotal;
  }

  @action
  previousPage() {
    if (!this.hasPreviousPage) { return; }
    this.clearFocusedPair();
    if (this.isGroupsView) {
      this.groupPage = Math.max(1, this.groupPage - 1);
    } else if (this.isSharedIpsView) {
      this.sharedIpPage = Math.max(1, this.sharedIpPage - 1);
    } else {
      this.page = Math.max(1, this.page - 1);
    }
    this.loadCorrelations();
  }

  @action
  nextPage() {
    if (!this.hasNextPage) { return; }
    this.clearFocusedPair();
    if (this.isGroupsView) {
      this.groupPage += 1;
    } else if (this.isSharedIpsView) {
      this.sharedIpPage += 1;
    } else {
      this.page += 1;
    }
    this.loadCorrelations();
  }

  @action
  async saveReview(item, status, note, primaryUserId) {
    if (
      status === "confirmed_duplicate" &&
      item.status !== "confirmed_duplicate" &&
      !window.confirm(i18n("admin.account_security.correlations.confirm_duplicate"))
    ) {
      return false;
    }

    try {
      await ajax(`/admin/plugins/account-security/correlations/${item.id}.json`, {
        type: "PUT",
        data: {
          status,
          review_note: note || "",
          primary_user_id: primaryUserId || "",
          confirmed: status === "confirmed_duplicate",
        },
      });
      await this.loadCorrelations();
      return true;
    } catch (error) {
      popupAjaxError(error);
      return false;
    }
  }

  @action
  async addDuplicateUserNote(item) {
    try {
      await ajax(
        `/admin/plugins/account-security/correlations/${item.id}/duplicate-user-note.json`,
        { type: "POST", data: { confirmed: true } }
      );
      await this.loadCorrelations();
      return true;
    } catch (error) {
      popupAjaxError(error);
      return false;
    }
  }

  @action
  async focusPair(pairId) {
    const id = Number(pairId);
    if (!Number.isInteger(id) || id <= 0) { return; }
    this.activeView = "pairs";
    this.viewInitialized = true;

    if ((this.data?.items || []).some((item) => Number(item.id) === id)) {
      this.openFocusedPairAfterRender(id);
      return;
    }

    this.focusedPairId = id;
    await this.fetchCorrelations({ quiet: true });
  }

  @action
  async rebuild() {
    this.isScanning = true;
    try {
      await ajax("/admin/plugins/account-security/correlations/rebuild.json", {
        type: "POST",
      });
      await this.fetchCorrelations({ quiet: true });
    } catch (error) {
      popupAjaxError(error);
      const refreshed = await this.fetchCorrelations({ quiet: true });
      if (!refreshed || !this.scanStateBusy()) {
        this.stopScanPolling();
      }
    }
  }
}
