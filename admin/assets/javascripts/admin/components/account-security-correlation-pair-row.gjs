import Component from "@glimmer/component";
import { fn } from "@ember/helper";
import { on } from "@ember/modifier";
import dIcon from "discourse/ui-kit/helpers/d-icon";
import { i18n } from "discourse-i18n";

export default class AccountSecurityCorrelationPairRow extends Component {
  get ariaLabel() {
    return i18n("admin.account_security.correlations.compact_pair_open_label", {
      first: this.args.item.user_a?.username || "—",
      second: this.args.item.user_b?.username || "—",
    });
  }

  <template>
    <div class="as-correlation__compact-pair as-correlation__compact-pair--interactive">
      <div class="as-correlation__compact-pair-main">
        {{#if @item.user_a}}
          <a
            class="trigger-user-card as-correlation__user-link"
            data-user-card={{@item.user_a.username}}
            href={{@item.user_a.profile_url}}
          >{{@item.user_a.username}}</a>
        {{else}}
          <span>—</span>
        {{/if}}
        <span class="as-correlation__pair-separator">↔</span>
        {{#if @item.user_b}}
          <a
            class="trigger-user-card as-correlation__user-link"
            data-user-card={{@item.user_b.username}}
            href={{@item.user_b.profile_url}}
          >{{@item.user_b.username}}</a>
        {{else}}
          <span>—</span>
        {{/if}}
      </div>
      <div class="as-correlation__compact-pair-actions">
        <span class="as-correlation__badge as-correlation__score">{{i18n "admin.account_security.correlations.score"}} {{@item.score}}</span>
        <span class="as-correlation__badge">{{@item.confidence_label}}</span>
        <span class="as-correlation__badge">{{@item.status_label}}</span>
      </div>
      <button
        class="as-correlation__compact-pair-open"
        type="button"
        aria-label={{this.ariaLabel}}
        {{on "click" (fn @controller.focusPair @item.id)}}
      >
        <span class="as-correlation__disclosure-icon" aria-hidden="true">{{dIcon "chevron-right"}}</span>
      </button>
    </div>
  </template>
}
