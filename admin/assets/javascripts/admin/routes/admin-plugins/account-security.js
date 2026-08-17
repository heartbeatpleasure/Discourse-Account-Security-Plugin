import DiscourseRoute from "discourse/routes/discourse";
import { ajax } from "discourse/lib/ajax";
import { i18n } from "discourse-i18n";
export default class AdminPluginsAccountSecurityRoute extends DiscourseRoute {
  titleToken() { return i18n("admin.account_security.title"); }
  model() { return ajax("/admin/plugins/account-security/overview.json"); }
}
