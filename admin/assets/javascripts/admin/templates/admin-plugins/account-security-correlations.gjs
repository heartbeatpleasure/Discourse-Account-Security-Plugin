import { fn } from "@ember/helper";
import { on } from "@ember/modifier";
import RouteTemplate from "ember-route-template";
import AccountSecurityCorrelationPair from "../../components/account-security-correlation-pair";
import AccountSecurityCorrelationPairRow from "../../components/account-security-correlation-pair-row";
import getURL from "discourse/lib/get-url";
import dIcon from "discourse/ui-kit/helpers/d-icon";
import { i18n } from "discourse-i18n";

const overviewUrl = getURL("/admin/plugins/account-security");
const settingsUrl = getURL(
  "/admin/site_settings/category/all_results?filter=account_security"
);

export default RouteTemplate(
  <template>
    <style>
      .as-correlation {
        --as-surface: var(--secondary);
        --as-surface-alt: var(--primary-very-low);
        --as-border: var(--primary-low);
        --as-muted: var(--primary-medium);
        display: flex;
        min-width: 0;
        flex-direction: column;
        gap: 1rem;
      }
      .as-correlation h1,
      .as-correlation h2,
      .as-correlation h3,
      .as-correlation h4,
      .as-correlation p { margin: 0; }
      .as-correlation__hero,
      .as-correlation__panel {
        min-width: 0;
        padding: 1.2rem 1.35rem;
        border: 1px solid var(--as-border);
        border-radius: 18px;
        background: var(--as-surface);
        box-shadow: 0 1px 2px rgb(0 0 0 / 3%);
      }
      .as-correlation__hero,
      .as-correlation__panel-header {
        display: flex;
        align-items: flex-start;
        justify-content: space-between;
        gap: 1rem;
      }
      .as-correlation__copy {
        display: flex;
        min-width: 0;
        flex: 1 1 auto;
        flex-direction: column;
        gap: .35rem;
      }
      .as-correlation__muted { color: var(--as-muted); }
      .as-correlation__actions,
      .as-correlation__buttons {
        display: flex;
        flex-wrap: wrap;
        align-items: center;
        gap: .5rem;
      }
      .as-correlation__actions {
        flex: 0 0 auto;
        justify-content: flex-end;
        margin-left: auto;
      }
      .as-correlation__actions .btn,
      .as-correlation__buttons .btn { white-space: nowrap; }
      .as-correlation__notice {
        padding: .85rem 1rem;
        border: 1px solid var(--tertiary-low);
        border-left: 3px solid var(--tertiary);
        border-radius: 12px;
        background: var(--tertiary-very-low);
      }
      .as-correlation__warning {
        padding: .85rem 1rem;
        border: 1px solid var(--danger-low-mid);
        border-radius: 12px;
        background: var(--danger-low);
        color: var(--danger);
      }
      .as-correlation__metrics {
        display: grid;
        grid-template-columns: repeat(3, minmax(0, 1fr));
        gap: .75rem;
      }
      .as-correlation__compact-grid,
      .as-correlation__diagnostics,
      .as-correlation__schedule-summary {
        display: grid;
        grid-template-columns: repeat(4, minmax(0, 1fr));
        gap: .75rem;
      }
      .as-correlation__metric,
      .as-correlation__compact-item,
      .as-correlation__diagnostic {
        min-width: 0;
        padding: .8rem .9rem;
        border: 1px solid var(--as-border);
        border-radius: 12px;
        background: var(--as-surface-alt);
      }
      .as-correlation__label {
        color: var(--as-muted);
        font-size: var(--font-down-1);
        font-weight: 700;
      }
      .as-correlation__value {
        margin-top: .2rem;
        overflow-wrap: anywhere;
        font-weight: 700;
      }
      .as-correlation__metric .as-correlation__value {
        font-size: var(--font-up-1);
        font-variant-numeric: tabular-nums;
      }
      .as-correlation__scan-stack {
        display: grid;
        gap: .8rem;
        margin-top: .9rem;
      }
      .as-correlation__subpanel {
        min-width: 0;
        padding: .95rem;
        border: 1px solid var(--as-border);
        border-radius: 14px;
        background: var(--as-surface-alt);
      }
      .as-correlation__subpanel h3 { margin-bottom: .25rem; }
      .as-correlation__diagnostics { margin-top: .75rem; }
      .as-correlation__diagnostic {
        padding: .65rem .75rem;
        background: var(--secondary);
      }
      .as-correlation__diagnostic .as-correlation__value {
        font-variant-numeric: tabular-nums;
      }
      .as-correlation__infrastructure-grid {
        display: grid;
        grid-template-columns: repeat(3, minmax(0, 1fr));
        gap: .7rem;
        margin-top: .75rem;
      }
      .as-correlation__infrastructure-card {
        min-width: 0;
        padding: .75rem .85rem;
        border: 1px solid var(--as-border);
        border-radius: 12px;
        background: var(--secondary);
      }
      .as-correlation__infrastructure-card .as-correlation__ip-address {
        display: block;
        margin-bottom: .3rem;
      }
      .as-correlation__context-lines {
        display: grid;
        gap: .2rem;
        color: var(--as-muted);
        font-size: var(--font-down-1);
      }
      .as-correlation__schedule-summary {
        grid-template-columns: repeat(2, minmax(0, 1fr));
        margin-top: .85rem;
      }
      .as-correlation__field {
        display: grid;
        min-width: 0;
        gap: .3rem;
      }
      .as-correlation__field label { font-weight: 700; }
      .as-correlation__field input,
      .as-correlation__field select {
        width: 100%;
        min-height: 42px;
        box-sizing: border-box;
        margin: 0;
        border: 1px solid var(--as-border);
        border-radius: 10px;
        background: var(--as-surface);
      }
      .as-correlation__filters {
        display: grid;
        grid-template-columns: minmax(150px, .75fr) minmax(150px, .75fr) minmax(220px, 1.4fr) auto;
        align-items: end;
        gap: .75rem;
      }
      .as-correlation__filter-hint {
        margin-top: .65rem !important;
        font-size: var(--font-down-1);
      }
      .as-correlation__view-switcher {
        display: grid;
        gap: .8rem;
      }
      .as-correlation__view-tabs {
        display: flex;
        flex-wrap: wrap;
        gap: .35rem;
        padding: .3rem;
        border: 1px solid var(--as-border);
        border-radius: 12px;
        background: var(--as-surface-alt);
      }
      .as-correlation__view-tab {
        min-height: 2.5rem;
        padding: .55rem .9rem;
        border: 0;
        border-radius: 9px;
        background: transparent;
        color: var(--as-muted);
        font-weight: 700;
        cursor: pointer;
      }
      .as-correlation__view-tab:hover,
      .as-correlation__view-tab:focus-visible {
        background: var(--secondary);
        color: var(--primary);
      }
      .as-correlation__view-tab.is-active {
        background: var(--secondary);
        color: var(--primary);
        box-shadow: 0 1px 3px rgb(0 0 0 / 8%);
      }
      .as-correlation__view-tab.is-active::after {
        content: "";
        display: block;
        height: 2px;
        margin-top: .35rem;
        border-radius: 999px;
        background: var(--tertiary);
      }
      .as-correlation__view-note {
        padding: .75rem .85rem;
        border-radius: 10px;
        background: var(--as-surface-alt);
        color: var(--as-muted);
        font-size: var(--font-down-1);
        line-height: 1.45;
      }
      .as-correlation__group-list,
      .as-correlation__candidate-list {
        display: grid;
        gap: .75rem;
        margin-top: .85rem;
      }
      .as-correlation__group,
      .as-correlation__candidate {
        min-width: 0;
        border: 1px solid var(--as-border);
        border-radius: 14px;
        background: var(--as-surface-alt);
        overflow: hidden;
      }
      .as-correlation .as-correlation__group > .as-correlation__group-summary,
      .as-correlation .as-correlation__candidate > .as-correlation__candidate-summary-line {
        display: flex !important;
        align-items: center;
        justify-content: space-between;
        gap: 1rem;
        padding: .85rem 1rem;
        cursor: pointer;
        list-style: none;
      }
      details.as-correlation__group > summary.as-correlation__group-summary::before,
      details.as-correlation__candidate > summary.as-correlation__candidate-summary-line::before {
        content: "" !important;
        display: none !important;
        width: 0 !important;
        margin: 0 !important;
        padding: 0 !important;
      }
      details.as-correlation__group > summary.as-correlation__group-summary::marker,
      details.as-correlation__candidate > summary.as-correlation__candidate-summary-line::marker {
        content: "" !important;
        font-size: 0 !important;
      }
      details.as-correlation__group > summary.as-correlation__group-summary::-webkit-details-marker,
      details.as-correlation__candidate > summary.as-correlation__candidate-summary-line::-webkit-details-marker {
        display: none !important;
      }
      .as-correlation__group-summary,
      .as-correlation__candidate-summary-line {
        appearance: none;
        -webkit-appearance: none;
      }
      .as-correlation__disclosure-icon {
        display: inline-flex;
        width: 1.9rem;
        height: 1.9rem;
        flex: 0 0 1.9rem;
        align-items: center;
        justify-content: center;
        border: 1px solid var(--as-border);
        border-radius: 999px;
        background: var(--secondary);
        color: var(--as-muted);
        margin-left: auto;
        transition: transform .15s ease, background .15s ease, color .15s ease;
      }
      .as-correlation__disclosure-icon .d-icon {
        width: .8rem;
        height: .8rem;
      }
      details[open] > summary .as-correlation__disclosure-icon {
        transform: rotate(90deg);
        background: var(--tertiary-very-low);
        color: var(--tertiary);
      }
      .as-correlation__summary-main {
        display: flex;
        min-width: 0;
        flex: 1 1 auto;
        flex-direction: column;
        gap: .2rem;
      }
      .as-correlation__summary-title {
        display: flex;
        flex-wrap: wrap;
        align-items: baseline;
        gap: .45rem;
      }
      .as-correlation__summary-title h3 { font-size: var(--font-up-1); }
      .as-correlation__ip-address {
        font-family: var(--d-font-family--monospace);
        font-weight: 700;
        overflow-wrap: anywhere;
      }
      .as-correlation__ip-group-title {
        display: flex;
        flex-wrap: wrap;
        align-items: center;
        gap: .65rem;
        font-size: var(--font-up-1);
      }
      .as-correlation__ip-title-divider {
        width: 1px;
        height: 1.25rem;
        flex: 0 0 1px;
        background: var(--as-border);
      }
      .as-correlation__ip-account-count {
        font-weight: 700;
        white-space: nowrap;
      }
      .as-correlation__group-body,
      .as-correlation__candidate-body {
        padding: 0 1rem 1rem;
        border-top: 1px solid var(--as-border);
      }
      .as-correlation__group-meta {
        display: flex;
        flex-wrap: wrap;
        gap: .5rem 1rem;
        margin-top: .8rem;
        color: var(--as-muted);
        font-size: var(--font-down-1);
      }
      .as-correlation__group-accounts {
        display: grid;
        grid-template-columns: repeat(3, minmax(0, 1fr));
        gap: .6rem;
        margin-top: .75rem;
      }
      .as-correlation__group-account {
        min-width: 0;
        padding: .65rem .75rem;
        border-radius: 10px;
        background: var(--secondary);
      }
      .as-correlation__user-link {
        color: var(--primary);
        font-weight: 700;
        text-decoration: none;
        overflow-wrap: anywhere;
      }
      .as-correlation__user-link:hover {
        color: var(--tertiary);
        text-decoration: underline;
      }
      .as-correlation__group-account strong { overflow-wrap: anywhere; }
      .as-correlation__group-pairs {
        margin-top: .9rem;
        padding-top: .85rem;
        border-top: 1px solid var(--as-border);
      }
      .as-correlation__group-pairs-header {
        display: grid;
        gap: .2rem;
        margin-bottom: .65rem;
      }
      .as-correlation__group-account .as-correlation__muted {
        margin-top: .25rem;
        font-size: var(--font-down-1);
        overflow-wrap: anywhere;
      }
      .as-correlation__account-groups-intro {
        display: grid;
        gap: .25rem;
        margin-bottom: .85rem;
      }
      .as-correlation__account-group-metrics {
        display: grid;
        grid-template-columns: repeat(4, minmax(0, 1fr));
        gap: .6rem;
        margin-top: .8rem;
      }
      .as-correlation__account-group-evidence,
      .as-correlation__account-group-review {
        display: flex;
        flex-wrap: wrap;
        gap: .45rem;
        margin-top: .75rem;
      }
      .as-correlation__account-group-anchor-list {
        display: grid;
        grid-template-columns: repeat(2, minmax(0, 1fr));
        gap: .6rem;
        margin-top: .7rem;
      }
      .as-correlation__account-group-anchor {
        min-width: 0;
        padding: .7rem .8rem;
        border: 1px solid var(--as-border);
        border-radius: 11px;
        background: var(--secondary);
      }
      .as-correlation__account-group-anchor-meta {
        display: flex;
        flex-wrap: wrap;
        gap: .3rem .7rem;
        margin-top: .35rem;
        color: var(--as-muted);
        font-size: var(--font-down-1);
      }
      .as-correlation__compact-pair-list {
        display: grid;
        gap: .45rem;
        margin-top: .65rem;
      }
      .as-correlation__compact-pair {
        position: relative;
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: .75rem;
        min-width: 0;
        padding: .7rem .8rem;
        border: 1px solid var(--as-border);
        border-radius: 12px;
        background: var(--secondary);
      }
      .as-correlation__compact-pair--interactive {
        transition: border-color .15s ease, background .15s ease, box-shadow .15s ease;
      }
      .as-correlation__compact-pair--interactive:hover,
      .as-correlation__compact-pair--interactive:focus-within {
        border-color: var(--primary-low-mid);
        background: var(--d-hover);
        box-shadow: 0 1px 3px rgb(0 0 0 / 5%);
      }
      .as-correlation__compact-pair-main,
      .as-correlation__compact-pair-actions {
        position: relative;
        z-index: 2;
        pointer-events: none;
      }
      .as-correlation__compact-pair .as-correlation__user-link { pointer-events: auto; }
      .as-correlation__compact-pair-actions { padding-right: 2.55rem; }
      .as-correlation__compact-pair-open {
        position: absolute;
        inset: 0;
        z-index: 1;
        display: flex;
        align-items: center;
        justify-content: flex-end;
        width: 100%;
        padding: .7rem .8rem;
        border: 0;
        border-radius: inherit;
        background: transparent;
        color: inherit;
        cursor: pointer;
      }
      .as-correlation__compact-pair-open:focus-visible {
        outline: 2px solid var(--tertiary);
        outline-offset: 2px;
      }
      .as-correlation__compact-pair-open .as-correlation__disclosure-icon {
        margin-left: auto;
      }
      .as-correlation__compact-pair-main {
        display: flex;
        min-width: 0;
        flex-wrap: wrap;
        align-items: center;
        gap: .35rem;
        font-weight: 700;
      }
      .as-correlation__compact-pair-actions {
        display: flex;
        flex: 0 0 auto;
        align-items: center;
        gap: .35rem;
      }
      .as-correlation__badges {
        display: flex;
        flex: 0 0 auto;
        flex-wrap: wrap;
        justify-content: flex-end;
        gap: .4rem;
      }
      .as-correlation__badge {
        display: inline-flex;
        width: max-content;
        padding: .25rem .55rem;
        border: 1px solid var(--as-border);
        border-radius: 999px;
        background: var(--secondary);
        font-size: var(--font-down-1);
        font-weight: 700;
      }
      .as-correlation__score {
        border-color: var(--tertiary-low);
        background: var(--tertiary-very-low);
      }
      .as-correlation__pair-separator { color: var(--as-muted); }
      .as-correlation__accounts-grid {
        display: grid;
        grid-template-columns: repeat(2, minmax(0, 1fr));
        gap: .7rem;
        margin-top: .8rem;
      }
      .as-correlation__account-card {
        min-width: 0;
        padding: .75rem .85rem;
        border-radius: 12px;
        background: var(--secondary);
      }
      .as-correlation__account-card strong { overflow-wrap: anywhere; }
      .as-correlation__account-meta {
        display: grid;
        grid-template-columns: repeat(2, minmax(0, 1fr));
        gap: .45rem .75rem;
        margin-top: .55rem;
      }
      .as-correlation__account-meta .as-correlation__value {
        font-size: var(--font-down-1);
      }
      .as-correlation__account-actions {
        display: flex;
        flex-wrap: wrap;
        gap: .45rem;
        margin-top: .7rem;
      }
      .as-correlation__candidate-meta {
        display: grid;
        grid-template-columns: minmax(0, 1.4fr) minmax(230px, .6fr);
        gap: .8rem;
        margin-top: .8rem;
      }
      .as-correlation__signal-box,
      .as-correlation__time-box {
        min-width: 0;
        padding: .75rem .85rem;
        border-radius: 12px;
        background: var(--secondary);
      }
      .as-correlation__time-box { display: grid; gap: .5rem; }
      .as-correlation__evidence-title {
        margin-top: .9rem;
        padding-top: .9rem;
        border-top: 1px solid var(--as-border);
      }
      .as-correlation__evidence-title p { margin-top: .25rem; }
      .as-correlation__ip-list {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
        gap: .7rem;
        margin-top: .7rem;
      }
      .as-correlation__ip-card {
        min-width: 0;
        padding: .8rem;
        border: 1px solid var(--as-border);
        border-radius: 12px;
        background: var(--secondary);
      }
      .as-correlation__ip-card--contextual { border-style: dashed; }
      .as-correlation__ip-meta {
        display: grid;
        gap: .35rem;
        margin-top: .6rem;
        font-size: var(--font-down-1);
      }
      .as-correlation__temporal-summary {
        display: grid;
        grid-template-columns: repeat(4, minmax(0, 1fr));
        gap: .6rem;
        margin-top: .7rem;
      }
      .as-correlation__temporal-list {
        display: grid;
        grid-template-columns: repeat(2, minmax(0, 1fr));
        gap: .7rem;
        margin-top: .7rem;
      }
      .as-correlation__temporal-card {
        min-width: 0;
        padding: .8rem;
        border: 1px solid var(--as-border);
        border-radius: 12px;
        background: var(--secondary);
      }
      .as-correlation__temporal-card-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: .75rem;
      }
      .as-correlation__temporal-account-grid {
        display: grid;
        grid-template-columns: repeat(2, minmax(0, 1fr));
        gap: .75rem;
        margin-top: .65rem;
      }
      .as-correlation__temporal-account-grid .as-correlation__value {
        font-size: var(--font-down-1);
      }
      .as-correlation__temporal-account-grid .as-correlation__muted {
        margin-top: .2rem;
        font-size: var(--font-down-1);
      }
      .as-correlation__breakdown {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
        gap: .55rem;
        margin-top: .7rem;
      }
      .as-correlation__reason {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: .75rem;
        min-width: 0;
        padding: .65rem .75rem;
        border-radius: 10px;
        background: var(--secondary);
      }
      .as-correlation__points {
        flex: 0 0 auto;
        font-weight: 700;
        font-variant-numeric: tabular-nums;
      }
      .as-correlation__points--positive { color: var(--success); }
      .as-correlation__points--negative { color: var(--danger); }
      .as-correlation__continuity-note {
        margin-top: .7rem;
        padding: .7rem .8rem;
        border-radius: 10px;
        background: var(--secondary);
        color: var(--as-muted);
        font-size: var(--font-down-1);
      }
      .as-correlation__investigation {
        margin-top: 1rem;
        padding-top: .2rem;
        border-top: 1px solid var(--as-border);
      }
      .as-correlation__evidence-title--first {
        margin-top: .7rem;
        padding-top: 0;
        border-top: 0;
      }
      .as-correlation__investigation-summary {
        display: grid;
        grid-template-columns: repeat(4, minmax(0, 1fr));
        gap: .6rem;
        margin-top: .75rem;
      }
      .as-correlation__review-form {
        display: grid;
        grid-template-columns: minmax(0, 1fr);
        gap: .9rem;
        margin-top: .8rem;
        padding: 1rem;
        border: 1px solid var(--as-border);
        border-radius: 14px;
        background: var(--secondary);
      }
      .as-correlation__review-decision,
      .as-correlation__review-form .as-correlation__field {
        min-width: 0;
      }
      .as-correlation__field-label,
      .as-correlation__review-form .as-correlation__field > span:first-child {
        display: block;
        margin-bottom: .4rem;
        font-weight: 700;
      }
      .as-correlation__decision-actions {
        display: flex;
        flex-wrap: wrap;
        gap: .45rem;
      }
      .as-correlation__decision-actions .btn {
        min-height: 2.4rem;
        padding-inline: .85rem;
        white-space: nowrap;
      }
      .as-correlation__decision-button--selected {
        border-color: var(--tertiary);
        background: var(--tertiary);
        color: var(--secondary);
      }
      .as-correlation__decision-button--selected:hover,
      .as-correlation__decision-button--selected:focus {
        color: var(--secondary);
      }
      .as-correlation__decision-button--selected-danger {
        border-color: var(--danger);
        background: var(--danger);
        color: var(--secondary);
        box-shadow: 0 0 0 2px var(--danger-low-mid);
      }
      .as-correlation__review-form select,
      .as-correlation__review-form textarea {
        width: 100%;
        box-sizing: border-box;
        margin: 0;
        border: 1px solid var(--as-border);
        border-radius: 10px;
        background: var(--as-surface);
      }
      .as-correlation__field--keep {
        width: min(28rem, 100%);
      }
      .as-correlation__field--note {
        width: 100%;
      }
      .as-correlation__review-form textarea {
        min-height: 9.5rem;
        padding: .75rem .8rem;
        resize: vertical;
        line-height: 1.45;
      }
      .as-correlation__review-form select {
        min-height: 42px;
      }
      .as-correlation__field-hint {
        display: block;
        margin-top: .4rem;
        max-width: 70rem;
        color: var(--as-muted);
        font-size: var(--font-down-2);
        line-height: 1.45;
      }
      .as-correlation__review-footer {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 1rem;
        padding-top: .8rem;
        border-top: 1px solid var(--as-border);
      }
      .as-correlation__review-footer .btn {
        flex: 0 0 auto;
        min-width: 8.5rem;
        white-space: nowrap;
      }
      .as-correlation__policy-actions {
        margin-top: .9rem;
      }
      .as-correlation__policy-grid {
        display: grid;
        grid-template-columns: repeat(2, minmax(0, 1fr));
        gap: .7rem;
        margin-top: .75rem;
      }
      .as-correlation__policy-card {
        min-width: 0;
        padding: .85rem;
        border: 1px solid var(--as-border);
        border-radius: 12px;
        background: var(--secondary);
      }
      .as-correlation__policy-card--action {
        border-color: var(--tertiary-low);
      }
      .as-correlation__policy-card h5 {
        margin: .55rem 0 .25rem;
        font-size: var(--font-up-1);
        overflow-wrap: anywhere;
      }
      .as-correlation__policy-state {
        display: flex;
        flex-wrap: wrap;
        gap: .35rem 1rem;
        margin-top: .65rem;
        color: var(--as-muted);
        font-size: var(--font-down-1);
      }
      .as-correlation__policy-note {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 1rem;
        margin-top: .75rem;
        padding: .8rem .85rem;
        border: 1px solid var(--as-border);
        border-radius: 12px;
        background: var(--secondary);
      }
      .as-correlation__policy-note > :first-child { min-width: 0; }
      .as-correlation__policy-note .btn,
      .as-correlation__policy-note .as-correlation__badge { flex: 0 0 auto; }
      .as-correlation__history {
        margin-top: .9rem;
      }
      .as-correlation__history > h4 { margin-bottom: .6rem; }
      .as-correlation__history-list {
        display: grid;
        gap: .55rem;
      }
      .as-correlation__history-item {
        min-width: 0;
        padding: .75rem .85rem;
        border: 1px solid var(--as-border);
        border-radius: 11px;
        background: var(--secondary);
      }
      .as-correlation__history-header {
        display: flex;
        align-items: baseline;
        justify-content: space-between;
        gap: .75rem;
      }
      .as-correlation__history-meta {
        display: flex;
        flex-wrap: wrap;
        gap: .35rem 1rem;
        margin-top: .35rem;
        color: var(--as-muted);
        font-size: var(--font-down-1);
      }
      .as-correlation__history-note {
        margin-top: .55rem !important;
        white-space: pre-wrap;
        overflow-wrap: anywhere;
      }
      .as-correlation__pagination {
        display: flex;
        align-items: center;
        justify-content: flex-end;
        gap: .6rem;
        margin-top: .9rem;
      }
      .as-correlation__empty {
        padding: 1rem;
        border-radius: 12px;
        background: var(--as-surface-alt);
        color: var(--as-muted);
      }
      @media (max-width: 1050px) {
        .as-correlation__infrastructure-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      }
      @media (max-width: 1150px) {
        .as-correlation__compact-grid,
        .as-correlation__diagnostics { grid-template-columns: repeat(3, minmax(0, 1fr)); }
      }
      @media (max-width: 1100px) {
        .as-correlation__account-group-metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      }
      .as-correlation__calibration-groups { display: grid; gap: .8rem; margin-top: .9rem; }
      .as-correlation__calibration-group { min-width: 0; padding: .9rem; border: 1px solid var(--as-border); border-radius: 14px; background: var(--as-surface-alt); }
      .as-correlation__calibration-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: .7rem; margin-top: .65rem; }
      .as-correlation__calibration-grid input { width: 100%; min-height: 40px; box-sizing: border-box; margin: 0; }
      .as-correlation__calibration-toolbar { display: flex; flex-wrap: wrap; align-items: flex-end; gap: .65rem; margin-top: .9rem; }
      .as-correlation__calibration-limit { width: min(210px, 100%); }
      .as-correlation__calibration-distributions { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: .75rem; margin-top: .8rem; }
      .as-correlation__calibration-distribution { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: .5rem; margin-top: .55rem; }
      .as-correlation__calibration-review { display: grid; gap: .45rem; margin-top: .65rem; }
      .as-correlation__calibration-review-row { display: grid; grid-template-columns: minmax(150px, 1.5fr) repeat(4, minmax(75px, .7fr)); gap: .45rem; align-items: center; padding: .55rem .65rem; border: 1px solid var(--as-border); border-radius: 10px; background: var(--secondary); }
      .as-correlation__calibration-review-cell { min-width: 0; }
      .as-correlation__calibration-review-count { font-weight: 650; }
      .as-correlation__calibration-change-list { display: grid; gap: .55rem; margin-top: .65rem; }
      .as-correlation__calibration-change { min-width: 0; padding: .7rem .8rem; border: 1px solid var(--as-border); border-radius: 12px; background: var(--secondary); }
      .as-correlation__calibration-change-head { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: .55rem; }
      .as-correlation__calibration-breakdown { display: flex; flex-wrap: wrap; gap: .35rem; margin-top: .45rem; }
      .as-correlation__calibration-breakdown span { padding: .2rem .42rem; border-radius: 999px; background: var(--primary-very-low); color: var(--as-muted); font-size: var(--font-down-1); }
      @media (max-width: 900px) {
        .as-correlation__calibration-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
        .as-correlation__calibration-distributions { grid-template-columns: 1fr; }
        .as-correlation__calibration-review-row { grid-template-columns: minmax(135px, 1.25fr) repeat(4, minmax(60px, .7fr)); }
        .as-correlation__compact-grid,
        .as-correlation__diagnostics { grid-template-columns: repeat(2, minmax(0, 1fr)); }
        .as-correlation__filters { grid-template-columns: 1fr 1fr; }
        .as-correlation__candidate-meta { grid-template-columns: 1fr; }
        .as-correlation__investigation-summary { grid-template-columns: repeat(2, minmax(0, 1fr)); }
        .as-correlation__policy-grid { grid-template-columns: 1fr; }
        .as-correlation__group-accounts { grid-template-columns: repeat(2, minmax(0, 1fr)); }
        .as-correlation__account-group-anchor-list { grid-template-columns: 1fr; }
        .as-correlation__temporal-summary { grid-template-columns: repeat(2, minmax(0, 1fr)); }
        .as-correlation__temporal-list { grid-template-columns: 1fr; }
      }
      @media (max-width: 700px) {
        .as-correlation__hero,
        .as-correlation__panel-header { flex-direction: column; }
        .as-correlation__actions,
        .as-correlation__badges { justify-content: flex-start; margin-left: 0; }
        .as-correlation__metrics,
        .as-correlation__schedule-summary,
        .as-correlation__filters,
        .as-correlation__accounts-grid,
        .as-correlation__investigation-summary,
        .as-correlation__account-group-metrics { grid-template-columns: 1fr; }
        .as-correlation__review-footer { flex-direction: column; align-items: stretch; }
        .as-correlation__review-footer .btn { align-self: flex-start; }
        .as-correlation__group-summary,
        .as-correlation__candidate-summary-line { align-items: flex-start; }
        .as-correlation__compact-pair { align-items: flex-start; flex-direction: column; }
        .as-correlation__group-accounts,
        .as-correlation__infrastructure-grid { grid-template-columns: 1fr; }
        .as-correlation__temporal-summary,
        .as-correlation__temporal-account-grid { grid-template-columns: 1fr; }
      }
      @media (max-width: 520px) {
        .as-correlation__calibration-grid,
        .as-correlation__calibration-distribution { grid-template-columns: 1fr; }
        .as-correlation__calibration-review-row { grid-template-columns: 1fr 1fr; }
        .as-correlation__calibration-review-row > strong { grid-column: 1 / -1; }
        .as-correlation__compact-grid,
        .as-correlation__diagnostics { grid-template-columns: 1fr; }
        .as-correlation__view-tabs { display: grid; grid-template-columns: 1fr; }
        .as-correlation__view-tab { text-align: left; }
      }
    </style>

    <div class="as-correlation">
      <section class="as-correlation__hero">
        <div class="as-correlation__copy">
          <h1>{{i18n "admin.account_security.correlations.title"}}</h1>
          <p class="as-correlation__muted">{{i18n "admin.account_security.correlations.description"}}</p>
        </div>
        <div class="as-correlation__actions">
          <a class="btn" href={{overviewUrl}}>{{i18n "admin.account_security.back_overview"}}</a>
          <button class="btn" type="button" disabled={{@controller.isLoading}} {{on "click" @controller.loadCorrelations}}>{{i18n "admin.account_security.correlations.refresh"}}</button>
        </div>
      </section>

      <div class="as-correlation__notice">{{i18n "admin.account_security.correlations.notice"}}</div>

      {{#if @controller.data}}
        <section class="as-correlation__metrics">
          <div class="as-correlation__metric"><div class="as-correlation__label">{{i18n "admin.account_security.correlations.enabled"}}</div><div class="as-correlation__value">{{@controller.data.enabled}}</div></div>
          <div class="as-correlation__metric"><div class="as-correlation__label">{{i18n "admin.account_security.correlations.open"}}</div><div class="as-correlation__value">{{@controller.data.open_count}}</div></div>
          <div class="as-correlation__metric"><div class="as-correlation__label">{{i18n "admin.account_security.correlations.strong"}}</div><div class="as-correlation__value">{{@controller.data.strong_open_count}}</div></div>
        </section>
      {{/if}}

      <section class="as-correlation__panel">
        <div class="as-correlation__panel-header">
          <div class="as-correlation__copy">
            <h2>{{i18n "admin.account_security.correlations.scan_title"}}</h2>
            <p class="as-correlation__muted">{{i18n "admin.account_security.correlations.scan_description"}}</p>
          </div>
          <button class="btn btn-primary" type="button" disabled={{@controller.scanBusy}} {{on "click" @controller.rebuild}}>{{i18n "admin.account_security.correlations.scan"}}</button>
        </div>

        {{#if @controller.data.scoring_refresh_required}}
          <div class="as-correlation__notice" style="margin-top: .9rem;">{{i18n "admin.account_security.correlations.scoring_refresh_required"}}</div>
        {{/if}}
        {{#if @controller.data.temporal_refresh_required}}
          <div class="as-correlation__notice" style="margin-top: .9rem;">{{i18n "admin.account_security.correlations.temporal_refresh_required"}}</div>
        {{/if}}

        <div class="as-correlation__scan-stack">
          <div class="as-correlation__subpanel">
            <div class="as-correlation__panel-header">
              <div class="as-correlation__copy">
                <h3>{{i18n "admin.account_security.correlations.automatic_scans"}}</h3>
                <p class="as-correlation__muted">{{i18n "admin.account_security.correlations.automatic_scans_settings_only"}}</p>
              </div>
              <a class="btn" href={{settingsUrl}}>{{i18n "admin.account_security.open_settings"}}</a>
            </div>

            {{#if @controller.data.schedule}}
              <div class="as-correlation__schedule-summary">
                <div class="as-correlation__compact-item">
                  <div class="as-correlation__label">{{i18n "admin.account_security.correlations.schedule_next"}}</div>
                  <div class="as-correlation__value">{{@controller.data.schedule.next_run_at_display}}</div>
                </div>
              </div>
            {{/if}}
          </div>

          <div class="as-correlation__subpanel">
            <h3>{{i18n "admin.account_security.correlations.scan_diagnostics"}}</h3>
            <p class="as-correlation__muted">{{i18n "admin.account_security.correlations.scan_diagnostics_description"}}</p>
            {{#if @controller.data.scan}}
              <div class="as-correlation__compact-grid" style="margin-top: .75rem;">
                <div class="as-correlation__compact-item"><div class="as-correlation__label">{{i18n "admin.account_security.correlations.scan_state"}}</div><div class="as-correlation__value">{{@controller.data.scan.state}}</div></div>
                <div class="as-correlation__compact-item"><div class="as-correlation__label">{{i18n "admin.account_security.correlations.scan_pairs"}}</div><div class="as-correlation__value">{{if @controller.data.scan.pairs_processed @controller.data.scan.pairs_processed 0}}</div></div>
                <div class="as-correlation__compact-item"><div class="as-correlation__label">{{i18n "admin.account_security.correlations.scan_new_candidates"}}</div><div class="as-correlation__value">{{if @controller.data.scan.new_candidates @controller.data.scan.new_candidates 0}}</div></div>
                <div class="as-correlation__compact-item"><div class="as-correlation__label">{{i18n "admin.account_security.correlations.scan_existing_updated"}}</div><div class="as-correlation__value">{{if @controller.data.scan.existing_candidates_updated @controller.data.scan.existing_candidates_updated 0}}</div></div>
                <div class="as-correlation__compact-item"><div class="as-correlation__label">{{i18n "admin.account_security.correlations.scan_existing_below_threshold"}}</div><div class="as-correlation__value">{{if @controller.data.scan.existing_candidates_below_threshold @controller.data.scan.existing_candidates_below_threshold 0}}</div></div>
                <div class="as-correlation__compact-item"><div class="as-correlation__label">{{i18n "admin.account_security.correlations.scan_new_below_threshold"}}</div><div class="as-correlation__value">{{if @controller.data.scan.new_candidates_below_threshold @controller.data.scan.new_candidates_below_threshold 0}}</div></div>
                <div class="as-correlation__compact-item"><div class="as-correlation__label">{{i18n "admin.account_security.correlations.scan_failed_pairs"}}</div><div class="as-correlation__value">{{if @controller.data.scan.pairs_failed @controller.data.scan.pairs_failed 0}}</div></div>
                <div class="as-correlation__compact-item"><div class="as-correlation__label">{{i18n "admin.account_security.correlations.scan_skipped_pairs"}}</div><div class="as-correlation__value">{{if @controller.data.scan.pairs_skipped @controller.data.scan.pairs_skipped 0}}</div></div>
                <div class="as-correlation__compact-item"><div class="as-correlation__label">{{i18n "admin.account_security.correlations.scan_source"}}</div><div class="as-correlation__value">{{@controller.data.scan.source_label}}</div></div>
              </div>
              <div class="as-correlation__diagnostics">
                {{#each @controller.data.scan.diagnostic_cards as |card|}}
                  <div class="as-correlation__diagnostic"><div class="as-correlation__label">{{card.label}}</div><div class="as-correlation__value">{{card.value}}</div></div>
                {{/each}}
              </div>
              {{#if @controller.data.scan.started_at}}
                <p class="as-correlation__muted" style="margin-top: .65rem;">{{i18n "admin.account_security.correlations.scan_started"}}: {{@controller.data.scan.started_at_display}}{{#if @controller.data.scan.completed_at}} · {{i18n "admin.account_security.correlations.scan_completed"}}: {{@controller.data.scan.completed_at_display}}{{/if}}</p>
              {{/if}}
              {{#if @controller.data.scan.stale_recovered}}<div class="as-correlation__warning" style="margin-top: .7rem;">{{i18n "admin.account_security.correlations.scan_stale_recovered"}}</div>{{/if}}
              {{#if @controller.data.scan.auth_log_truncated}}<div class="as-correlation__warning" style="margin-top: .7rem;">{{i18n "admin.account_security.correlations.diagnostics_auth_truncated"}}</div>{{/if}}
              {{#if @controller.data.scan.session_observation_truncated}}<div class="as-correlation__warning" style="margin-top: .7rem;">{{i18n "admin.account_security.correlations.diagnostics_session_observation_truncated"}}</div>{{/if}}
              {{#if @controller.data.scan.truncated}}<div class="as-correlation__warning" style="margin-top: .7rem;">{{i18n "admin.account_security.correlations.scan_truncated"}}</div>{{/if}}
              {{#if @controller.data.scan.has_pair_failures}}<div class="as-correlation__warning" style="margin-top: .7rem;">{{i18n "admin.account_security.correlations.scan_pair_failures" count=@controller.data.scan.pairs_failed}}</div>{{/if}}
              {{#if @controller.data.scan.has_pair_skips}}<div class="as-correlation__notice" style="margin-top: .7rem;">{{i18n "admin.account_security.correlations.scan_pair_skips" count=@controller.data.scan.pairs_skipped}}</div>{{/if}}
              {{#if @controller.data.scan.large_shared_groups.length}}
                <div class="as-correlation__subpanel" style="margin-top: .8rem; background: var(--secondary);">
                  <h4>{{i18n "admin.account_security.correlations.high_sharing_title"}}</h4>
                  <p class="as-correlation__muted" style="margin-top: .25rem;">{{i18n "admin.account_security.correlations.high_sharing_description"}}</p>
                  <div class="as-correlation__infrastructure-grid">
                    {{#each @controller.data.scan.large_shared_groups as |group|}}
                      <div class="as-correlation__infrastructure-card">
                        <span class="as-correlation__ip-address">{{group.ip_address}}</span>
                        <div class="as-correlation__value">{{group.account_count_label}}</div>
                        <div class="as-correlation__context-lines" style="margin-top: .35rem;">
                          <span>{{group.context_display}}</span>
                          {{#if group.network_context.network_display}}<span><strong>{{i18n "admin.account_security.correlations.network_asn"}}:</strong> {{group.network_context.network_display}}</span>{{/if}}
                          {{#if group.isp}}<span><strong>{{i18n "admin.account_security.correlations.cached_isp"}}:</strong> {{group.isp}}</span>{{/if}}
                          {{#if group.usage_type}}<span><strong>{{i18n "admin.account_security.intelligence.usage_type"}}:</strong> {{group.usage_type}}</span>{{/if}}
                          {{#if group.network_context.location_display}}<span><strong>{{i18n "admin.account_security.correlations.approximate_location"}}:</strong> {{group.network_context.location_display}}</span>{{/if}}
                        </div>
                      </div>
                    {{/each}}
                  </div>
                </div>
              {{/if}}
            {{else}}
              <div class="as-correlation__empty" style="margin-top: .75rem;">{{i18n "admin.account_security.no_data"}}</div>
            {{/if}}
          </div>
        </div>
      </section>

      <section class="as-correlation__panel">
        <div class="as-correlation__panel-header">
          <div class="as-correlation__copy">
            <h2>{{i18n "admin.account_security.correlations.calibration.title"}}</h2>
            <p class="as-correlation__muted">{{i18n "admin.account_security.correlations.calibration.description"}}</p>
          </div>
          <button class="btn" type="button" {{on "click" @controller.toggleCalibration}}>
            {{if @controller.calibrationOpen (i18n "admin.account_security.correlations.calibration.close") (i18n "admin.account_security.correlations.calibration.open")}}
          </button>
        </div>
        <div class="as-correlation__notice" style="margin-top: .8rem;">
          {{i18n "admin.account_security.correlations.calibration.preview_only_notice"}}
        </div>

        {{#if @controller.calibrationOpen}}
          {{#if @controller.calibrationLoading}}
            <div class="as-correlation__empty" style="margin-top: .8rem;">{{i18n "admin.account_security.correlations.calibration.loading"}}</div>
          {{else}}
            {{#if @controller.calibrationData}}
              <p class="as-correlation__muted" style="margin-top: .8rem;">
                {{i18n "admin.account_security.correlations.calibration.live_version" version=@controller.calibrationData.scoring_version revision=@controller.calibrationData.scoring_revision}}
              </p>
              <div class="as-correlation__calibration-groups">
                {{#each @controller.calibrationGroups as |group|}}
                  <div class="as-correlation__calibration-group">
                    <h3>{{group.label}}</h3>
                    <div class="as-correlation__calibration-grid">
                      {{#each group.fields as |field|}}
                        <div class="as-correlation__field">
                          <label>{{field.label}}</label>
                          <input
                            type="number"
                            min={{field.min}}
                            max={{field.max}}
                            step={{field.step}}
                            value={{field.value}}
                            disabled={{@controller.calibrationSaving}}
                            {{on "input" (fn @controller.setCalibrationField field.key)}}
                          />
                        </div>
                      {{/each}}
                    </div>
                  </div>
                {{/each}}
              </div>

              <div class="as-correlation__calibration-toolbar">
                <div class="as-correlation__field as-correlation__calibration-limit">
                  <label>{{i18n "admin.account_security.correlations.calibration.preview_rows"}}</label>
                  <input
                    type="number"
                    min="1"
                    max={{@controller.calibrationData.max_preview_rows}}
                    step="100"
                    value={{@controller.calibrationPreviewLimit}}
                    disabled={{@controller.calibrationSaving}}
                    {{on "input" @controller.setCalibrationPreviewLimit}}
                  />
                </div>
                <button class="btn btn-primary" type="button" disabled={{@controller.calibrationSaving}} {{on "click" @controller.previewCalibration}}>{{i18n "admin.account_security.correlations.calibration.preview"}}</button>
                <button class="btn" type="button" disabled={{@controller.calibrationSaving}} {{on "click" @controller.saveCalibrationDraft}}>{{i18n "admin.account_security.correlations.calibration.save_draft"}}</button>
                <button class="btn" type="button" disabled={{@controller.calibrationSaving}} {{on "click" @controller.resetCalibrationDraft}}>{{i18n "admin.account_security.correlations.calibration.reset"}}</button>
              </div>
              <p class="as-correlation__muted" style="margin-top: .55rem;">{{i18n "admin.account_security.correlations.calibration.draft_note"}}</p>

              {{#if @controller.calibrationPreview}}
                <div class="as-correlation__subpanel" style="margin-top: .9rem;">
                  <h3>{{i18n "admin.account_security.correlations.calibration.preview_results"}}</h3>
                  <div class="as-correlation__compact-grid" style="margin-top: .65rem;">
                    <div class="as-correlation__compact-item"><div class="as-correlation__label">{{i18n "admin.account_security.correlations.calibration.processed"}}</div><div class="as-correlation__value">{{@controller.calibrationPreview.processed}} / {{@controller.calibrationPreview.total}}</div></div>
                    <div class="as-correlation__compact-item"><div class="as-correlation__label">{{i18n "admin.account_security.correlations.calibration.changed"}}</div><div class="as-correlation__value">{{@controller.calibrationPreview.changed_count}}</div></div>
                    <div class="as-correlation__compact-item"><div class="as-correlation__label">{{i18n "admin.account_security.correlations.calibration.confidence_changed"}}</div><div class="as-correlation__value">{{@controller.calibrationPreview.confidence_changed_count}}</div></div>
                    <div class="as-correlation__compact-item"><div class="as-correlation__label">{{i18n "admin.account_security.correlations.calibration.context_only"}}</div><div class="as-correlation__value">{{@controller.calibrationPreview.context_only_count}}</div></div>
                  </div>
                  {{#if @controller.calibrationPreview.truncated}}
                    <div class="as-correlation__notice" style="margin-top: .65rem;">{{i18n "admin.account_security.correlations.calibration.preview_truncated" limit=@controller.calibrationPreview.limit total=@controller.calibrationPreview.total}}</div>
                  {{/if}}

                  <div class="as-correlation__calibration-distributions">
                    <div class="as-correlation__subpanel" style="background: var(--secondary);">
                      <h4>{{i18n "admin.account_security.correlations.calibration.current_distribution"}}</h4>
                      <div class="as-correlation__calibration-distribution">
                        <div class="as-correlation__diagnostic"><div class="as-correlation__label">{{i18n "admin.account_security.correlations.confidences.weak"}}</div><div class="as-correlation__value">{{@controller.calibrationPreview.current_distribution.weak}}</div></div>
                        <div class="as-correlation__diagnostic"><div class="as-correlation__label">{{i18n "admin.account_security.correlations.confidences.moderate"}}</div><div class="as-correlation__value">{{@controller.calibrationPreview.current_distribution.moderate}}</div></div>
                        <div class="as-correlation__diagnostic"><div class="as-correlation__label">{{i18n "admin.account_security.correlations.confidences.strong"}}</div><div class="as-correlation__value">{{@controller.calibrationPreview.current_distribution.strong}}</div></div>
                        <div class="as-correlation__diagnostic"><div class="as-correlation__label">{{i18n "admin.account_security.correlations.confidences.very_strong"}}</div><div class="as-correlation__value">{{@controller.calibrationPreview.current_distribution.very_strong}}</div></div>
                      </div>
                    </div>
                    <div class="as-correlation__subpanel" style="background: var(--secondary);">
                      <h4>{{i18n "admin.account_security.correlations.calibration.preview_distribution"}}</h4>
                      <div class="as-correlation__calibration-distribution">
                        <div class="as-correlation__diagnostic"><div class="as-correlation__label">{{i18n "admin.account_security.correlations.confidences.weak"}}</div><div class="as-correlation__value">{{@controller.calibrationPreview.preview_distribution.weak}}</div></div>
                        <div class="as-correlation__diagnostic"><div class="as-correlation__label">{{i18n "admin.account_security.correlations.confidences.moderate"}}</div><div class="as-correlation__value">{{@controller.calibrationPreview.preview_distribution.moderate}}</div></div>
                        <div class="as-correlation__diagnostic"><div class="as-correlation__label">{{i18n "admin.account_security.correlations.confidences.strong"}}</div><div class="as-correlation__value">{{@controller.calibrationPreview.preview_distribution.strong}}</div></div>
                        <div class="as-correlation__diagnostic"><div class="as-correlation__label">{{i18n "admin.account_security.correlations.confidences.very_strong"}}</div><div class="as-correlation__value">{{@controller.calibrationPreview.preview_distribution.very_strong}}</div></div>
                      </div>
                    </div>
                  </div>

                  <div style="margin-top: .85rem;">
                    <h4>{{i18n "admin.account_security.correlations.calibration.review_matrix_title"}}</h4>
                    <p class="as-correlation__muted">{{i18n "admin.account_security.correlations.calibration.review_matrix_note"}}</p>
                    {{#if @controller.calibrationPreview.review_rows.length}}
                      <div class="as-correlation__calibration-review">
                        {{#each @controller.calibrationPreview.review_rows as |row|}}
                          <div class="as-correlation__calibration-review-row">
                            <strong>{{row.label}} ({{row.total}})</strong>
                            <div class="as-correlation__calibration-review-cell"><div class="as-correlation__label">{{i18n "admin.account_security.correlations.confidences.weak"}}</div><div class="as-correlation__calibration-review-count">{{row.weak}}</div></div>
                            <div class="as-correlation__calibration-review-cell"><div class="as-correlation__label">{{i18n "admin.account_security.correlations.confidences.moderate"}}</div><div class="as-correlation__calibration-review-count">{{row.moderate}}</div></div>
                            <div class="as-correlation__calibration-review-cell"><div class="as-correlation__label">{{i18n "admin.account_security.correlations.confidences.strong"}}</div><div class="as-correlation__calibration-review-count">{{row.strong}}</div></div>
                            <div class="as-correlation__calibration-review-cell"><div class="as-correlation__label">{{i18n "admin.account_security.correlations.confidences.very_strong"}}</div><div class="as-correlation__calibration-review-count">{{row.very_strong}}</div></div>
                          </div>
                        {{/each}}
                      </div>
                    {{else}}
                      <div class="as-correlation__empty" style="margin-top: .55rem;">{{i18n "admin.account_security.correlations.calibration.review_matrix_empty"}}</div>
                    {{/if}}
                  </div>

                  <div style="margin-top: .85rem;">
                    <h4>{{i18n "admin.account_security.correlations.calibration.largest_changes"}}</h4>
                    {{#if @controller.calibrationPreview.largest_changes.length}}
                      <div class="as-correlation__calibration-change-list">
                        {{#each @controller.calibrationPreview.largest_changes as |row|}}
                          <div class="as-correlation__calibration-change">
                            <div class="as-correlation__calibration-change-head">
                              <strong>{{row.user_a.username}} ↔ {{row.user_b.username}}</strong>
                              <span>{{row.current_score}} / {{row.current_confidence_label}} → {{row.preview_score}} / {{row.preview_confidence_label}} ({{row.delta_display}})</span>
                            </div>
                            {{#if row.preview_breakdown.length}}
                              <div class="as-correlation__calibration-breakdown">
                                {{#each row.preview_breakdown as |entry|}}
                                  <span>{{entry.label}} {{entry.points_display}}</span>
                                {{/each}}
                              </div>
                            {{/if}}
                          </div>
                        {{/each}}
                      </div>
                    {{else}}
                      <div class="as-correlation__empty" style="margin-top: .6rem;">{{i18n "admin.account_security.correlations.calibration.no_changes"}}</div>
                    {{/if}}
                  </div>
                </div>
              {{/if}}
            {{/if}}
          {{/if}}
        {{/if}}
      </section>

      <section class="as-correlation__panel">
        <div class="as-correlation__filters">
          <div class="as-correlation__field">
            <label>{{i18n "admin.account_security.correlations.filter_status"}}</label>
            <select {{on "change" @controller.setStatus}}>
              <option value="">{{i18n "admin.account_security.all"}}</option>
              <option value="open">{{i18n "admin.account_security.correlations.statuses.open"}}</option>
              <option value="monitor">{{i18n "admin.account_security.correlations.statuses.monitor"}}</option>
              <option value="expected_shared_network">{{i18n "admin.account_security.correlations.statuses.expected_shared_network"}}</option>
              <option value="confirmed_duplicate">{{i18n "admin.account_security.correlations.statuses.confirmed_duplicate"}}</option>
              <option value="dismissed">{{i18n "admin.account_security.correlations.statuses.dismissed"}}</option>
            </select>
          </div>
          <div class="as-correlation__field">
            <label>{{i18n "admin.account_security.correlations.filter_confidence"}}</label>
            <select {{on "change" @controller.setConfidence}}>
              <option value="">{{i18n "admin.account_security.all"}}</option>
              <option value="weak">{{i18n "admin.account_security.correlations.confidences.weak"}}</option>
              <option value="moderate">{{i18n "admin.account_security.correlations.confidences.moderate"}}</option>
              <option value="strong">{{i18n "admin.account_security.correlations.confidences.strong"}}</option>
              <option value="very_strong">{{i18n "admin.account_security.correlations.confidences.very_strong"}}</option>
            </select>
          </div>
          <div class="as-correlation__field">
            <label>{{i18n "admin.account_security.correlations.search"}}</label>
            <input type="search" placeholder={{i18n "admin.account_security.correlations.search_placeholder"}} value={{@controller.search}} {{on "input" @controller.setSearch}} />
          </div>
          <button class="btn" type="button" {{on "click" @controller.applyFilters}}>{{i18n "admin.account_security.correlations.apply"}}</button>
        </div>
        <p class="as-correlation__muted as-correlation__filter-hint">{{i18n "admin.account_security.correlations.filters_apply_views"}}</p>
      </section>

      {{#if @controller.data}}
        <section class="as-correlation__panel as-correlation__view-switcher">
          <div class="as-correlation__copy">
            <h2>{{i18n "admin.account_security.correlations.views_title"}}</h2>
            <p class="as-correlation__muted">{{i18n "admin.account_security.correlations.views_description"}}</p>
          </div>
          <div class="as-correlation__view-tabs" role="tablist" aria-label={{i18n "admin.account_security.correlations.views_title"}}>
            <button
              type="button"
              role="tab"
              id="account-security-correlation-tab-groups"
              aria-controls="account-security-correlation-view-panel"
              aria-selected={{if @controller.isGroupsView "true" "false"}}
              tabindex={{if @controller.isGroupsView "0" "-1"}}
              class="as-correlation__view-tab {{if @controller.isGroupsView "is-active" ""}}"
              {{on "click" (fn @controller.selectView "groups")}}
              {{on "keydown" (fn @controller.navigateViews 0)}}
            >{{i18n "admin.account_security.correlations.tab_account_groups"}}</button>
            <button
              type="button"
              role="tab"
              id="account-security-correlation-tab-shared_ips"
              aria-controls="account-security-correlation-view-panel"
              aria-selected={{if @controller.isSharedIpsView "true" "false"}}
              tabindex={{if @controller.isSharedIpsView "0" "-1"}}
              class="as-correlation__view-tab {{if @controller.isSharedIpsView "is-active" ""}}"
              {{on "click" (fn @controller.selectView "shared_ips")}}
              {{on "keydown" (fn @controller.navigateViews 1)}}
            >{{i18n "admin.account_security.correlations.tab_shared_ips"}}</button>
            <button
              type="button"
              role="tab"
              id="account-security-correlation-tab-pairs"
              aria-controls="account-security-correlation-view-panel"
              aria-selected={{if @controller.isPairsView "true" "false"}}
              tabindex={{if @controller.isPairsView "0" "-1"}}
              class="as-correlation__view-tab {{if @controller.isPairsView "is-active" ""}}"
              {{on "click" (fn @controller.selectView "pairs")}}
              {{on "keydown" (fn @controller.navigateViews 2)}}
            >{{i18n "admin.account_security.correlations.tab_pair_comparisons"}}</button>
          </div>
        </section>

        <div
          role="tabpanel"
          id="account-security-correlation-view-panel"
          aria-labelledby={{@controller.activeTabId}}
        >
          {{#if @controller.isGroupsView}}
            <section class="as-correlation__panel">
              <div class="as-correlation__account-groups-intro">
                <h2>{{i18n "admin.account_security.correlations.account_groups_title"}}</h2>
                <p class="as-correlation__muted">{{i18n "admin.account_security.correlations.account_groups_description"}}</p>
              </div>
              <div class="as-correlation__view-note">{{i18n "admin.account_security.correlations.account_groups_score_note"}}</div>
              {{#if @controller.data.account_groups_truncated}}
                <div class="as-correlation__notice" style="margin-top: .85rem;">{{i18n "admin.account_security.correlations.account_groups_truncated"}}</div>
              {{/if}}
              {{#if @controller.data.account_groups.length}}
                <div class="as-correlation__group-list">
                  {{#each @controller.data.account_groups as |group|}}
                    <details class="as-correlation__group as-correlation__account-group">
                      <summary class="as-correlation__group-summary">
                        <div class="as-correlation__summary-main">
                          <div class="as-correlation__summary-title">
                            <strong>{{group.account_count_label}}</strong>
                            <span class="as-correlation__muted">{{i18n "admin.account_security.correlations.account_group_label"}}</span>
                          </div>
                          <span class="as-correlation__muted">{{group.relationship_label}}</span>
                        </div>
                        <div class="as-correlation__badges">
                          <span class="as-correlation__badge">{{i18n "admin.account_security.correlations.strongest_pair"}}: {{group.strongest_confidence_label}}</span>
                          <span class="as-correlation__badge as-correlation__score">{{i18n "admin.account_security.correlations.score_range"}} {{group.score_range_label}}</span>
                        </div>
                        <span class="as-correlation__disclosure-icon" aria-hidden="true">{{dIcon "chevron-right"}}</span>
                      </summary>
                      <div class="as-correlation__group-body">
                        <p class="as-correlation__muted" style="margin-top: .8rem;">{{i18n "admin.account_security.correlations.account_group_explanation"}}</p>

                        <div class="as-correlation__account-group-metrics">
                          <div class="as-correlation__compact-item"><div class="as-correlation__label">{{i18n "admin.account_security.correlations.direct_relationships"}}</div><div class="as-correlation__value">{{group.relation_count}} / {{group.possible_relation_count}}</div></div>
                          <div class="as-correlation__compact-item"><div class="as-correlation__label">{{i18n "admin.account_security.correlations.relationship_coverage"}}</div><div class="as-correlation__value">{{group.coverage_percent}}%</div></div>
                          <div class="as-correlation__compact-item"><div class="as-correlation__label">{{i18n "admin.account_security.correlations.score_range"}}</div><div class="as-correlation__value">{{group.score_range_label}}</div></div>
                          <div class="as-correlation__compact-item"><div class="as-correlation__label">{{i18n "admin.account_security.correlations.strongest_pair"}}</div><div class="as-correlation__value">{{group.strongest_confidence_label}}</div></div>
                        </div>

                        <div class="as-correlation__evidence-title">
                          <h3>{{i18n "admin.account_security.correlations.account_group_accounts"}}</h3>
                          <p class="as-correlation__muted">{{i18n "admin.account_security.correlations.account_group_accounts_description"}}</p>
                        </div>
                        <div class="as-correlation__group-accounts">
                          {{#each group.accounts as |account|}}
                            <div class="as-correlation__group-account">
                              <a class="trigger-user-card as-correlation__user-link" data-user-card={{account.username}} href={{account.profile_url}}>{{account.username}}</a>
                              <div class="as-correlation__muted">{{i18n "admin.account_security.correlations.direct_relationship_count" count=account.direct_relation_count}}</div>
                            </div>
                          {{/each}}
                        </div>

                        {{#if group.evidence_summary.length}}
                          <div class="as-correlation__account-group-evidence">
                            {{#each group.evidence_summary as |summary|}}<span class="as-correlation__badge">{{summary}}</span>{{/each}}
                          </div>
                        {{/if}}

                        {{#if group.anchors.length}}
                          <div class="as-correlation__evidence-title">
                            <h3>{{i18n "admin.account_security.correlations.account_group_anchors"}}</h3>
                            <p class="as-correlation__muted">{{i18n "admin.account_security.correlations.account_group_anchors_description"}}</p>
                          </div>
                          <div class="as-correlation__account-group-anchor-list">
                            {{#each group.anchors as |anchor|}}
                              <div class="as-correlation__account-group-anchor">
                                <div class="as-correlation__ip-address">{{anchor.ip_address}}</div>
                                <div class="as-correlation__account-group-anchor-meta">
                                  <span>{{anchor.account_count_label}}</span>
                                  <span>{{anchor.context_display}}</span>
                                  {{#if anchor.network_context.network_display}}<span>{{anchor.network_context.network_display}}</span>{{/if}}
                                  {{#if anchor.network_context.location_display}}<span>{{anchor.network_context.location_display}}</span>{{/if}}
                                </div>
                              </div>
                            {{/each}}
                          </div>
                        {{/if}}

                        {{#if group.review_summary.length}}
                          <div class="as-correlation__evidence-title">
                            <h3>{{i18n "admin.account_security.correlations.account_group_review_progress"}}</h3>
                          </div>
                          <div class="as-correlation__account-group-review">
                            {{#each group.review_summary as |review|}}<span class="as-correlation__badge">{{review.label}}: {{review.count}}</span>{{/each}}
                          </div>
                        {{/if}}

                        {{#if group.visible_pairs.length}}
                          <div class="as-correlation__group-pairs">
                            <div class="as-correlation__group-pairs-header">
                              <h3>{{i18n "admin.account_security.correlations.account_group_pair_comparisons"}}</h3>
                              <p class="as-correlation__muted">{{if group.all_pairs_visible (i18n "admin.account_security.correlations.account_group_all_pairs_visible") group.visible_pair_label}}</p>
                            </div>
                            <div class="as-correlation__view-note">{{i18n "admin.account_security.correlations.account_group_pair_score_note"}}</div>
                            <div class="as-correlation__compact-pair-list">
                              {{#each group.visible_pairs as |item|}}
                                <AccountSecurityCorrelationPairRow @item={{item}} @controller={{@controller}} />
                              {{/each}}
                            </div>
                          </div>
                        {{/if}}
                      </div>
                    </details>
                  {{/each}}
                </div>
              {{else}}
                <div class="as-correlation__empty" style="margin-top: .85rem;">{{i18n "admin.account_security.correlations.no_account_groups"}}</div>
              {{/if}}
            </section>
          {{else}}
            {{#if @controller.isSharedIpsView}}
              <section class="as-correlation__panel">
                <div class="as-correlation__copy">
                  <h2>{{i18n "admin.account_security.correlations.shared_ip_groups_title"}}</h2>
                  <p class="as-correlation__muted">{{i18n "admin.account_security.correlations.shared_ip_groups_description"}}</p>
                </div>
                <div class="as-correlation__view-note" style="margin-top: .8rem;">{{i18n "admin.account_security.correlations.shared_ip_score_note"}}</div>
                {{#if @controller.sharedIpsReady}}
                {{#unless @controller.data.shared_ip_source_complete}}
                  <div class="as-correlation__warning" style="margin-top: .7rem;">{{i18n "admin.account_security.correlations.shared_ip_source_incomplete"}}</div>
                {{/unless}}
                {{#if @controller.data.shared_ip_filter_truncated}}
                  <div class="as-correlation__warning" style="margin-top: .7rem;">{{i18n "admin.account_security.correlations.shared_ip_filter_truncated"}}</div>
                {{/if}}
                {{#if @controller.data.shared_ip_groups.length}}
                  <div class="as-correlation__group-list">
                    {{#each @controller.data.shared_ip_groups as |group|}}
                      <details class="as-correlation__group">
                        <summary class="as-correlation__group-summary">
                          <div class="as-correlation__summary-main">
                            <div class="as-correlation__ip-group-title">
                              <span class="as-correlation__ip-address">{{group.ip_address}}</span>
                              <span class="as-correlation__ip-title-divider" aria-hidden="true"></span>
                              <strong class="as-correlation__ip-account-count">{{group.account_count_label}}</strong>
                            </div>
                            <span class="as-correlation__muted">{{group.coverage_label}} · {{group.pair_count_label}}</span>
                          </div>
                          <div class="as-correlation__badges">
                            {{#unless group.public}}<span class="as-correlation__badge">{{i18n "admin.account_security.correlations.context_nonpublic"}}</span>{{/unless}}
                            {{#if group.tor}}<span class="as-correlation__badge">{{i18n "admin.account_security.correlations.context_tor"}}</span>{{/if}}
                            {{#if group.hosting}}<span class="as-correlation__badge">{{i18n "admin.account_security.correlations.context_hosting"}}</span>{{/if}}
                            {{#if group.mobile}}<span class="as-correlation__badge">{{i18n "admin.account_security.correlations.context_mobile"}}</span>{{/if}}
                            {{#if group.local_blacklist}}<span class="as-correlation__badge">{{i18n "admin.account_security.correlations.context_blacklist"}}</span>{{/if}}
                            {{#if group.trusted}}<span class="as-correlation__badge">{{i18n "admin.account_security.correlations.context_trusted"}}</span>{{/if}}
                          </div>
                          <span class="as-correlation__disclosure-icon" aria-hidden="true">{{dIcon "chevron-right"}}</span>
                        </summary>
                        <div class="as-correlation__group-body">
                          <div class="as-correlation__group-meta">
                            <span>{{i18n "admin.account_security.correlations.group_registration_accounts" count=group.registration_account_count}}</span>
                            <span>{{i18n "admin.account_security.correlations.group_auth_accounts" count=group.auth_account_count}}</span>
                            {{#if group.temporal_aligned_pair_count}}<span>{{i18n "admin.account_security.correlations.group_temporal_pairs" count=group.temporal_aligned_pair_count}}</span>{{/if}}
                            <span>{{i18n "admin.account_security.correlations.ip_context"}}: {{group.context_display}}</span>
                            {{#if group.network_context.network_display}}<span>{{i18n "admin.account_security.correlations.network_asn"}}: {{group.network_context.network_display}}</span>{{/if}}
                            {{#if group.isp}}<span>{{i18n "admin.account_security.correlations.cached_isp"}}: {{group.isp}}</span>{{/if}}
                            {{#if group.usage_type}}<span>{{i18n "admin.account_security.intelligence.usage_type"}}: {{group.usage_type}}</span>{{/if}}
                            {{#if group.network_context.location_display}}<span>{{i18n "admin.account_security.correlations.approximate_location"}}: {{group.network_context.location_display}}</span>{{/if}}
                          </div>
                          <div class="as-correlation__group-accounts">
                            {{#each group.accounts as |account|}}
                              <div class="as-correlation__group-account">
                                <a class="trigger-user-card as-correlation__user-link" data-user-card={{account.username}} href={{account.profile_url}}>{{account.username}}</a>
                                <div class="as-correlation__muted">{{account.sources_display}}</div>
                              </div>
                            {{/each}}
                          </div>
                          {{#if group.accounts_truncated}}
                            <p class="as-correlation__muted">{{i18n "admin.account_security.correlations.account_preview_truncated"}}</p>
                          {{/if}}
                          {{#if group.pairs.length}}
                            <div class="as-correlation__group-pairs">
                              <div class="as-correlation__group-pairs-header">
                                <h3>{{i18n "admin.account_security.correlations.group_pair_comparisons"}}</h3>
                                <p class="as-correlation__muted">{{i18n "admin.account_security.correlations.group_pair_comparisons_compact_description"}}</p>
                              </div>
                              <div class="as-correlation__compact-pair-list">
                                {{#each group.pairs as |item|}}
                                  <AccountSecurityCorrelationPairRow @item={{item}} @controller={{@controller}} />
                                {{/each}}
                              </div>
                              {{#if group.pairs_truncated}}
                                <p class="as-correlation__muted" style="margin-top: .55rem;">{{i18n "admin.account_security.correlations.pair_preview_truncated"}}</p>
                              {{/if}}
                            </div>
                          {{/if}}
                        </div>
                      </details>
                    {{/each}}
                  </div>
                {{else}}
                  <div class="as-correlation__empty" style="margin-top: .85rem;">{{i18n "admin.account_security.correlations.no_shared_ip_groups"}}</div>
                {{/if}}
                {{else}}
                  <div class="as-correlation__empty" style="margin-top: .85rem;">{{i18n "admin.account_security.loading"}}</div>
                {{/if}}
              </section>
            {{else}}
              <section class="as-correlation__panel">
                <div class="as-correlation__copy">
                  <h2>{{i18n "admin.account_security.correlations.pair_comparisons_title"}}</h2>
                  <p class="as-correlation__muted">{{i18n "admin.account_security.correlations.pair_comparisons_description"}}</p>
                </div>
                <div class="as-correlation__view-note" style="margin-top: .8rem;">{{i18n "admin.account_security.correlations.pair_score_definition"}}</div>
                {{#if @controller.data.items.length}}
                  <div class="as-correlation__candidate-list">
                    {{#each @controller.data.items as |item|}}
                      <AccountSecurityCorrelationPair @item={{item}} @controller={{@controller}} />
                    {{/each}}
                  </div>
                {{else}}
                  <div class="as-correlation__empty" style="margin-top: .85rem;">{{i18n "admin.account_security.no_data"}}</div>
                {{/if}}
              </section>
            {{/if}}
          {{/if}}
        </div>

        <section class="as-correlation__panel">
          <div class="as-correlation__pagination">
            <button class="btn" type="button" disabled={{unless @controller.hasPreviousPage true false}} {{on "click" @controller.previousPage}}>{{i18n "admin.account_security.correlations.previous"}}</button>
            <span class="as-correlation__muted">{{i18n "admin.account_security.correlations.page"}} {{@controller.currentPage}}</span>
            <button class="btn" type="button" disabled={{unless @controller.hasNextPage true false}} {{on "click" @controller.nextPage}}>{{i18n "admin.account_security.correlations.next"}}</button>
          </div>
        </section>
      {{else}}
        <section class="as-correlation__panel">
          <div class="as-correlation__empty">{{if @controller.isLoading (i18n "admin.account_security.loading") (i18n "admin.account_security.no_data")}}</div>
        </section>
      {{/if}}
    </div>
  </template>
);
