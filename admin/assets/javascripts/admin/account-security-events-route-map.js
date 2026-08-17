export default { resource: "admin.adminPlugins", path: "/plugins", map() { this.route("accountSecurityEvents", { path: "/account-security-events" }); } };
