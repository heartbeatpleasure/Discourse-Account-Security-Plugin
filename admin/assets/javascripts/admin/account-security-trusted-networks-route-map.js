export default { resource: "admin.adminPlugins", path: "/plugins", map() { this.route("accountSecurityTrustedNetworks", { path: "/account-security-trusted-networks" }); } };
