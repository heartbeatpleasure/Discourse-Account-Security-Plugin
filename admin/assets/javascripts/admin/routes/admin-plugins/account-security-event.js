import DiscourseRoute from "discourse/routes/discourse";
import { ajax } from "discourse/lib/ajax";
import { i18n } from "discourse-i18n";

export default class AdminPluginsAccountSecurityEventRoute extends DiscourseRoute {
  titleToken() {
    return i18n("admin.account_security.event_detail.title");
  }

  model(params) {
    return ajax(`/admin/plugins/account-security/events/${params.event_id}.json`);
  }

  setupController(controller, model) {
    super.setupController(...arguments);
    controller.resetState?.(model);
  }
}
