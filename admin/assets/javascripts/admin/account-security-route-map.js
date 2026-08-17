import "./api-initializers/account-security-settings-button-fix";
export default {
  resource: "admin.adminPlugins",
  path: "/plugins",
  map() {
    this.route("accountSecurity", { path: "/account-security" });
  },
};
