import DiscourseRoute from "discourse/routes/discourse";
import { i18n } from "discourse-i18n";
export default class AdminPluginsAccountSecurityHealthRoute extends DiscourseRoute {
  titleToken() { return i18n("admin.account_security.health.title"); }
  setupController(controller) { super.setupController(...arguments); controller.resetState?.(); controller.loadHealth?.(); }
}
