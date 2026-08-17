export default { resource: "admin.adminPlugins", path: "/plugins", map() { this.route("accountSecurityHealth", { path: "/account-security-health" }); } };
