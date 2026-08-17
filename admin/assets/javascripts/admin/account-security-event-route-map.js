export default {
  resource: "admin.adminPlugins",
  path: "/plugins",
  map() {
    this.route("accountSecurityEvent", {
      path: "/account-security-events/:event_id",
    });
  },
};
