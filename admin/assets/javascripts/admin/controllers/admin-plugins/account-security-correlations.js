import Controller from "@ember/controller";
import { action } from "@ember/object";
import { tracked } from "@glimmer/tracking";
import { schedule } from "@ember/runloop";
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
  @tracked activeView = "groups";
  @tracked viewInitialized = false;

  resetState() {
    this.data = undefined;
    this.isLoading = false;
    this.isScanning = false;
    this.status = "";
    this.confidence = "";
    this.search = "";
    this.page = 1;
    this.activeView = "groups";
    this.viewInitialized = false;
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
    this.activeView = view;
    this.viewInitialized = true;
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
        Number(evidence.repeated_shared_session_signature_count || 0) > 0,
      auth_pattern_history_incomplete:
        evidence.auth_pattern_history_complete !== true ||
        evidence.core_auth_history_complete !== true ||
        evidence.exact_ip_population_complete !== true,
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

  addGroupAccount(group, user, sources) {
    if (!user?.id) {
      return;
    }

    let account = group.accounts.get(user.id);
    if (!account) {
      account = {
        id: user.id,
        username: user.username,
        profile_url: user.profile_url,
        sources: new Set(),
      };
      group.accounts.set(user.id, account);
    }
    (sources || []).forEach((source) => account.sources.add(source));
  }

  buildSharedIpGroups(items) {
    const groups = new Map();

    (items || []).forEach((item) => {
      (item.shared_ip_details || []).forEach((detail) => {
        const totalAccounts = Number(detail.user_count || 0);
        if (!detail.ip_address || totalAccounts < 3) {
          return;
        }

        let group = groups.get(detail.ip_address);
        if (!group) {
          group = {
            ip_address: detail.ip_address,
            total_accounts: totalAccounts,
            accounts: new Map(),
            pair_ids: new Set(),
            max_score: 0,
            context_display: detail.context_display,
            network_context: detail.network_context,
            public: detail.public === true,
            trusted: detail.trusted === true,
            tor: detail.tor === true,
            hosting: detail.hosting === true,
            mobile: detail.mobile === true,
            local_blacklist: detail.local_blacklist === true,
            usage_type: detail.usage_type || null,
            isp: detail.isp || null,
          };
          groups.set(detail.ip_address, group);
        }

        group.total_accounts = Math.max(group.total_accounts, totalAccounts);
        group.max_score = Math.max(group.max_score, Number(item.score || 0));
        group.pair_ids.add(item.id);
        this.addGroupAccount(group, item.user_a, detail.sources_a);
        this.addGroupAccount(group, item.user_b, detail.sources_b);
      });
    });

    return [...groups.values()]
      .map((group) => {
        const accounts = [...group.accounts.values()]
          .map((account) => ({
            ...account,
            sources_display: [...account.sources]
              .map((source) => this.sourceLabel(source))
              .join(", "),
          }))
          .sort((a, b) => a.username.localeCompare(b.username));
        const registrationAccounts = accounts.filter((account) =>
          account.sources.has("registration")
        ).length;
        const authAccounts = accounts.filter(
          (account) =>
            account.sources.has("auth_session") ||
            account.sources.has("active_session")
        ).length;
        const visibleCount = accounts.length;
        const pairs = items.filter((item) => group.pair_ids.has(item.id));
        const temporalAlignedPairs = pairs.filter((item) =>
          (item.temporal_ip_details || []).some(
            (detail) =>
              detail.ip_address === group.ip_address &&
              Number(detail.closest_gap_seconds) <= 86400
          )
        ).length;

        return {
          ...group,
          accounts,
          pairs,
          visible_account_count: visibleCount,
          pair_count: pairs.length,
          registration_account_count: registrationAccounts,
          auth_account_count: authAccounts,
          temporal_aligned_pair_count: temporalAlignedPairs,
          account_count_label: i18n(
            "admin.account_security.correlations.group_account_count",
            { count: group.total_accounts }
          ),
          coverage_label:
            visibleCount >= group.total_accounts
              ? i18n("admin.account_security.correlations.group_all_accounts", {
                  count: group.total_accounts,
                })
              : i18n("admin.account_security.correlations.group_partial_accounts", {
                  visible: visibleCount,
                  total: group.total_accounts,
                }),
          pair_count_label: i18n(
            "admin.account_security.correlations.group_pair_count",
            { count: pairs.length }
          ),
        };
      })
      .sort(
        (a, b) =>
          b.total_accounts - a.total_accounts ||
          b.max_score - a.max_score ||
          a.ip_address.localeCompare(b.ip_address)
      );
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
    const visiblePairs = (items || []).filter(
      (item) => item.account_group_key === group.key
    );
    const statusCounts = group.status_counts || {};
    const evidenceCounts = group.evidence_counts || {};
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
      all_pairs_visible:
        visiblePairs.length >= Number(group.pair_record_count || group.relation_count || 0),
      strongest_confidence_label: i18n(
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
      score_range_label:
        Number(group.min_score || 0) === Number(group.max_score || 0)
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
    const sharedIpGroups = this.buildSharedIpGroups(items);
    const accountGroupedPairIds = new Set(
      accountGroups.flatMap((group) => group.visible_pairs.map((item) => item.id))
    );

    return {
      ...data,
      scan: this.decorateScan(data.scan),
      schedule: this.decorateSchedule(data.schedule),
      items,
      account_groups: accountGroups,
      shared_ip_groups: sharedIpGroups,
      ungrouped_items: items.filter(
        (item) => !accountGroupedPairIds.has(item.id)
      ),
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
      this.initializeView(this.data);
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
  focusPair(pairId) {
    this.activeView = "pairs";
    this.viewInitialized = true;

    schedule("afterRender", () => {
      const element = document.getElementById(`correlation-${pairId}`);
      if (!element) {
        return;
      }

      element.open = true;
      element.scrollIntoView({ behavior: "smooth", block: "start" });
    });
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
