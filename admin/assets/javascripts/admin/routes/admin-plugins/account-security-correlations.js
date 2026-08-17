import DiscourseRoute from "discourse/routes/discourse";
import { i18n } from "discourse-i18n";

export default class AdminPluginsAccountSecurityCorrelationsRoute extends DiscourseRoute {
  titleToken() {
    return i18n("admin.account_security.correlations.title");
  }

  setupController(controller) {
    super.setupController(...arguments);
    controller.resetState?.();
    controller.loadCorrelations?.();
  }
}
