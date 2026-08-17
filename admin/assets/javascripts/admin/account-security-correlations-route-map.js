export default {
  resource: "admin.adminPlugins",
  path: "/plugins",
  map() {
    this.route("accountSecurityCorrelations", { path: "/account-security-correlations" });
  },
};
